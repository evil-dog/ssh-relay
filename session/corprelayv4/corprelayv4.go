// Package corprelayv4 implements the corp-relay-v4@google.com protocol, see
// https://chromium.googlesource.com/apps/libapps/+/HEAD/nassh/docs/relay-protocol.md#corp-relay-v4.
package corprelayv4

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/hazaelsan/ssh-relay/session"
	"github.com/hazaelsan/ssh-relay/session/corprelayv4/command"
)

// newWriter defines a function to get a WebSocket writer, used for ease of testing.
type newWriter func(int) (io.WriteCloser, error)

// noopWriteCloser discards all writes, used during reconnect-wait buffering mode.
type noopWriteCloser struct{}

func (noopWriteCloser) Write(b []byte) (int, error) { return len(b), nil }
func (noopWriteCloser) Close() error                { return nil }

// reconnectReq carries a new WebSocket and client ack for a /v4/reconnect call.
type reconnectReq struct {
	ws   *websocket.Conn
	ack  uint64
	done chan error
}

var (
	// ErrInvalidSession is returned when a session is in an invalid state.
	ErrInvalidSession = errors.New("invalid session")
)

// New creates a *Session from a given SSH connection.
func New(ssh io.ReadWriteCloser, role session.Role) *Session {
	s := &Session{
		ssh:  ssh,
		role: role,
		done: make(chan struct{}),
	}
	if s.role == session.Server {
		s.sid = uuid.New()
	}
	return s
}

// A Session is a V4 SSH-over-Websocket Relay session.
type Session struct {
	sid    uuid.UUID
	ssh    io.ReadWriteCloser
	ws     *websocket.Conn
	rCount uint64 // bytes received from client (ws→ssh), used for ACKs we send
	wCount uint64 // bytes client has acknowledged (ssh→ws), updated by readAck
	mu     sync.RWMutex
	wFunc  newWriter
	role   session.Role
	done   chan struct{}

	// Reconnect support (zero value = disabled).
	sendBuf        []byte          // unACKed data sent to client, for retransmission
	sendBufCap     int             // max send buffer capacity (0 = no reconnect)
	serverWritePos uint64          // total bytes written to client
	buffering      bool            // true when in reconnect-wait mode
	reconnectCh    chan *reconnectReq
	reconnectWait  time.Duration
}

func (s *Session) String() string {
	return s.sid.String()
}

// SID returns the Session ID.
func (s *Session) SID() uuid.UUID {
	return s.sid
}

// Version returns the protocol version in use for the session.
func (s *Session) Version() session.ProtocolVersion {
	return session.CorpRelayV4
}

// SetReconnectConfig enables reconnect support with the given send buffer size and wait timeout.
// Must be called before Run().
func (s *Session) SetReconnectConfig(bufSize int, wait time.Duration) {
	s.sendBufCap = bufSize
	s.reconnectWait = wait
	if bufSize > 0 && wait > 0 {
		s.sendBuf = make([]byte, 0, bufSize)
		s.reconnectCh = make(chan *reconnectReq, 1)
	}
}

// Close closes the SSH connection, causing the Session to be invalid.
func (s *Session) Close() error {
	err := s.ssh.Close()
	s.done <- struct{}{}
	return err
}

// Done notifies when a session has terminated.
func (s *Session) Done() <-chan struct{} {
	return s.done
}

// Reconnect resumes the session on a new WebSocket after an unclean disconnect.
// ack is the client's read position (bytes received from server).
// Blocks until the new WebSocket disconnects or the session terminates.
func (s *Session) Reconnect(ws *websocket.Conn, ack uint64) error {
	if s.reconnectCh == nil {
		return ErrInvalidSession
	}
	req := &reconnectReq{
		ws:   ws,
		ack:  ack,
		done: make(chan error, 1),
	}
	select {
	case s.reconnectCh <- req:
	case <-s.done:
		return ErrInvalidSession
	}
	return <-req.done
}

// Run starts a new session between the WebSocket and SSH connections.
func (s *Session) Run(ws *websocket.Conn) error {
	defer s.Close()
	s.mu.Lock()
	s.ws = ws
	s.wFunc = ws.NextWriter
	s.mu.Unlock()
	if s.role == session.Server {
		if err := s.establishConn(0); err != nil {
			return err
		}
	}
	sshErrc := make(chan error, 1)
	go s.runSSH(sshErrc)
	return s.mainLoop(sshErrc)
}

// mainLoop coordinates WebSocket and SSH goroutines, handling reconnect-wait states.
func (s *Session) mainLoop(sshErrc <-chan error) error {
	var currentReq *reconnectReq
	for {
		wsErrc := make(chan error, 1)
		go s.runWS(wsErrc)

		select {
		case err := <-sshErrc:
			if currentReq != nil {
				currentReq.done <- err
			}
			return err

		case wsErr := <-wsErrc:
			if !isUncleanClose(wsErr) || s.reconnectCh == nil {
				if currentReq != nil {
					currentReq.done <- wsErr
				}
				return wsErr
			}
			// Unclean disconnect — enter reconnect-wait.
			s.enterBufferingMode()
			if currentReq != nil {
				currentReq.done <- nil
				currentReq = nil
			}

			timer := time.NewTimer(s.reconnectWait)
			var newReq *reconnectReq
			select {
			case err := <-sshErrc:
				timer.Stop()
				return err
			case req := <-s.reconnectCh:
				timer.Stop()
				newReq = req
			case <-timer.C:
				return fmt.Errorf("%v: reconnect timeout after %v", s, s.reconnectWait)
			}

			if err := s.doReconnect(newReq); err != nil {
				newReq.done <- err
				return err
			}
			currentReq = newReq
			// Loop back to start runWS on the new WebSocket.
		}
	}
}

// enterBufferingMode switches wFunc to a no-op writer so runSSH buffers data
// into sendBuf instead of writing to the (now broken) WebSocket.
func (s *Session) enterBufferingMode() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buffering = true
	s.wFunc = func(int) (io.WriteCloser, error) {
		return noopWriteCloser{}, nil
	}
}

// doReconnect processes a reconnect request: updates clientAck, sends RECONNECT_SUCCESS,
// retransmits buffered data, then switches back to normal write mode.
func (s *Session) doReconnect(req *reconnectReq) error {
	// Update clientAck and trim sendBuf.
	s.mu.Lock()
	if req.ack > s.wCount {
		trim := int(req.ack - s.wCount)
		if trim <= len(s.sendBuf) {
			s.sendBuf = s.sendBuf[trim:]
		}
		s.wCount = req.ack
	}
	rCount := s.rCount
	s.mu.Unlock()

	// Send RECONNECT_SUCCESS with server's read position.
	if err := s.writeToWS(req.ws, command.NewReconnectSuccess(rCount)); err != nil {
		return fmt.Errorf("RECONNECT_SUCCESS error: %w", err)
	}

	// Retransmit all buffered data (catching up any new data that arrived during the wait).
	if err := s.retransmitAll(req.ws); err != nil {
		return fmt.Errorf("retransmit error: %w", err)
	}

	// Switch to normal write mode on the new WebSocket.
	s.mu.Lock()
	s.buffering = false
	s.ws = req.ws
	s.wFunc = req.ws.NextWriter
	s.mu.Unlock()

	return nil
}

// writeToWS acquires the write lock and writes a Command directly to ws.
// Used for control frames (RECONNECT_SUCCESS) that bypass the wFunc mechanism.
func (s *Session) writeToWS(ws *websocket.Conn, cmd command.Command) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, err := ws.NextWriter(websocket.BinaryMessage)
	if err != nil {
		return err
	}
	defer w.Close()
	return cmd.Write(w)
}

// writeDataToWS writes a DATA command for the given bytes directly to ws.
// Used during retransmit — does NOT update sendBuf or serverWritePos.
func (s *Session) writeDataToWS(ws *websocket.Conn, data []byte) error {
	d, err := command.NewData(data)
	if err != nil {
		return err
	}
	return s.writeToWS(ws, d)
}

// retransmitAll sends all data in sendBuf to ws, looping until no new data
// has accumulated from runSSH during the retransmit itself.
func (s *Session) retransmitAll(ws *websocket.Conn) error {
	var offset int
	for {
		s.mu.RLock()
		total := len(s.sendBuf)
		s.mu.RUnlock()
		if offset >= total {
			break
		}

		s.mu.RLock()
		chunk := make([]byte, total-offset)
		copy(chunk, s.sendBuf[offset:total])
		s.mu.RUnlock()

		for len(chunk) > 0 {
			size := len(chunk)
			if size > command.MaxArrayLen {
				size = command.MaxArrayLen
			}
			if err := s.writeDataToWS(ws, chunk[:size]); err != nil {
				return err
			}
			chunk = chunk[size:]
		}
		offset = total
	}
	return nil
}

// isUncleanClose reports whether err represents an unexpected WebSocket closure.
// Normal close (code 1000) and going away (code 1001) are considered clean.
func isUncleanClose(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) {
		return false
	}
	var ce *websocket.CloseError
	if errors.As(err, &ce) {
		return ce.Code != websocket.CloseNormalClosure && ce.Code != websocket.CloseGoingAway
	}
	return true
}

// wsWriter is a wrapper to a websocket writer.
// Returns a writer and a cancel function to release the lock.
// Needed because gorilla doesn't support concurrent writes.
func (s *Session) wsWriter(t int) (io.WriteCloser, func(), error) {
	s.mu.Lock()
	w, err := s.wFunc(t)
	if err != nil {
		defer s.mu.Unlock()
		return nil, nil, err
	}
	done := func() {
		w.Close()
		s.mu.Unlock()
	}
	return w, done, nil
}

// recvCmd parses an in-band command from a WebSocket stream.
func (s *Session) recvCmd(b []byte) error {
	c, err := command.Unmarshal(b)
	if err != nil {
		return fmt.Errorf("command.Unmarshal(%v) error: %w", b, err)
	}
	switch c.Tag() {
	case command.TagConnectSuccess:
		b := c.(command.ConnectSuccess).SID()
		// CONNECT_SUCCESS can only be sent to a client as the first command.
		if s.role != session.Client || !bytes.Equal(s.sid[:], uuid.Nil[:]) {
			break
		}
		s.sid, err = uuid.Parse(b)
		if err != nil {
			return fmt.Errorf("uuid.Parse(%v) error: %w", b, err)
		}
		return nil
	case command.TagReconnectSuccess:
		return errors.New("not implemented")
	case command.TagData:
		if err := s.readData(c.(command.Data)); err != nil {
			return err
		}
		return s.sendAck()
	case command.TagAck:
		return s.readAck(c.(command.Ack))
	}
	return fmt.Errorf("%w: %v", command.ErrBadCommand, c.Tag())
}

// establishConn sends the initial CONNECT_SUCCESS command to establish a connection.
func (s *Session) establishConn(ack uint64) error {
	if ack > 0 {
		return errors.New("non-zero ack in establishConn: reconnect handled by doReconnect")
	}
	return s.sendConnect()
}

// sendConnect sends a CONNECT_SUCCESS command.
func (s *Session) sendConnect() error {
	sid, err := s.sid.MarshalText()
	if err != nil {
		return err
	}
	w, cancel, err := s.wsWriter(websocket.BinaryMessage)
	if err != nil {
		return fmt.Errorf("wFunc() error: %w", err)
	}
	defer cancel()
	cs, err := command.NewConnectSuccess(sid)
	if err != nil {
		return err
	}
	return cs.Write(w)
}

// readData processes an incoming DATA command.
func (s *Session) readData(d command.Data) error {
	data := d.Data()
	s.rCount += uint64(len(data))
	glog.V(5).Infof("%v: ws->ssh read %v bytes", s, len(data))
	if _, err := s.ssh.Write(data); err != nil {
		return err
	}
	return nil
}

// sendAck sends an ACK command in response to received data from one or more DATA commands.
func (s *Session) sendAck() error {
	w, cancel, err := s.wsWriter(websocket.BinaryMessage)
	if err != nil {
		return fmt.Errorf("wFunc() error: %w", err)
	}
	defer cancel()
	a := command.NewAck(s.rCount)
	return a.Write(w)
}

// readAck processes an incoming ACK command and trims the send buffer accordingly.
func (s *Session) readAck(a command.Ack) error {
	ack := a.Ack()
	s.mu.Lock()
	defer s.mu.Unlock()
	diff := int(ack - s.wCount)
	if diff == 0 {
		return nil
	}
	if diff < 0 {
		return fmt.Errorf("reverse ack %v -> %v", s.wCount, ack)
	}
	if s.sendBufCap > 0 && diff <= len(s.sendBuf) {
		s.sendBuf = s.sendBuf[diff:]
	}
	s.wCount = ack
	return nil
}

// runSSH handles reads from SSH and forwards them to the WebSocket.
func (s *Session) runSSH(errc chan<- error) {
	for {
		err := func() error {
			r := bufio.NewReader(s.ssh)
			b := make([]byte, command.MaxArrayLen)
			n, err := r.Read(b)
			data := b[0:n]
			glog.V(5).Infof("%v: ssh->ws read %v bytes", s, n)
			if err != nil {
				return err
			}
			w, cancel, err := s.wsWriter(websocket.BinaryMessage)
			if err != nil {
				return fmt.Errorf("wFunc() error: %w", err)
			}
			defer cancel()
			return s.copySSH(w, data)
		}()
		if err != nil {
			errc <- err
			return
		}
	}
}

// copySSH copies SSH data to the WebSocket writer and updates the send buffer.
// Must be called while s.mu is held (via wsWriter).
func (s *Session) copySSH(w io.Writer, b []byte) error {
	if s.sendBufCap > 0 {
		if s.buffering && len(s.sendBuf)+len(b) > s.sendBufCap {
			return fmt.Errorf("%v: reconnect buffer overflow (%d unACKed bytes)", s, len(s.sendBuf))
		}
		s.sendBuf = append(s.sendBuf, b...)
		s.serverWritePos += uint64(len(b))
	}
	d, err := command.NewData(b)
	if err != nil {
		return err
	}
	return d.Write(w)
}

// runWS handles reads from the WebSocket.
func (s *Session) runWS(errc chan<- error) {
	for {
		t, r, err := s.ws.NextReader()
		if err != nil {
			errc <- fmt.Errorf("NextReader() error: %w", err)
			return
		}

		err = func() error {
			switch t {
			case websocket.BinaryMessage:
				return s.parseBinary(r)
			default:
				return fmt.Errorf("unsupported message type: %v", t)
			}
		}()
		if err != nil {
			errc <- err
			return
		}
	}
}

// parseBinary handles a ws->ssh message.
func (s *Session) parseBinary(r io.Reader) error {
	b := new(bytes.Buffer)
	if _, err := b.ReadFrom(r); err != nil {
		return err
	}
	return s.recvCmd(b.Bytes())
}
