// Package corprelayv4 implements a corp-relay-v4@google.com SSH-over-WebSocket Relay client session.
package corprelayv4

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"

	"github.com/golang/glog"
	"github.com/gorilla/websocket"
	hsession "github.com/hazaelsan/ssh-relay/helper/session"
	"github.com/hazaelsan/ssh-relay/session"
	"github.com/hazaelsan/ssh-relay/session/corprelayv4"
	"github.com/hazaelsan/ssh-relay/tls"

	"github.com/hazaelsan/ssh-relay/proto/v1/tlspb"
)

// reconnectBufSize is the per-session send buffer for client-side reconnect support.
// Matches the server's default (128 KiB).
const reconnectBufSize = 131072

// New creates a *Session.
// Communication to ssh(1) is done via stdin/stdout.
func New(opts hsession.Options) *Session {
	ssh := hsession.NewWrapper(os.Stdin, os.Stdout)
	return &Session{
		opts: opts,
		s:    corprelayv4.New(ssh, session.Client),
	}
}

// A Session is a corp-relay-v4@google.com SSH-over-WebSocket Relay client session.
type Session struct {
	opts hsession.Options
	s    *corprelayv4.Session
	ws   *websocket.Conn
}

// Run copies I/O to an SSH host through a WebSocket Relay via /v4/connect.
// On unclean disconnects, it automatically reconnects via /v4/reconnect.
func (s *Session) Run() error {
	u := s.connectURL()
	if err := s.dial(u); err != nil {
		return fmt.Errorf("dial(%v) error: %w", u, err)
	}
	s.s.SetClientReconnectConfig(reconnectBufSize, s.reconnectDial)
	return s.s.Run(s.ws)
}

// Done notifies when the Session has terminated.
func (s *Session) Done() <-chan struct{} {
	return s.s.Done()
}

// connectHeader builds an http.Header for /v4/connect and /v4/reconnect requests.
func (s *Session) connectHeader() http.Header {
	h := http.Header{}
	h.Add("Origin", s.opts.Origin)
	for _, c := range s.opts.Cookies {
		h.Add("Cookie", c.String())
	}
	return h
}

// connectURL builds the URL for /v4/connect requests.
func (s *Session) connectURL() string {
	u := url.URL{
		Scheme: s.wsScheme(),
		Host:   s.opts.Relay,
		Path:   "/v4/connect",
	}
	q := u.Query()
	q.Set("host", s.opts.Host)
	q.Set("port", s.opts.Port)
	u.RawQuery = q.Encode()
	return u.String()
}

// reconnectURL builds the URL for /v4/reconnect requests.
// sid is the session ID from CONNECT_SUCCESS; ack is the client's read count.
func (s *Session) reconnectURL(sid string, ack uint64) string {
	u := url.URL{
		Scheme: s.wsScheme(),
		Host:   s.opts.Relay,
		Path:   "/v4/reconnect",
	}
	q := u.Query()
	q.Set("sid", sid)
	q.Set("ack", strconv.FormatUint(ack, 10))
	u.RawQuery = q.Encode()
	return u.String()
}

// wsScheme returns "wss" or "ws" based on the transport TLS config.
func (s *Session) wsScheme() string {
	if s.opts.Transport.GetTlsConfig().GetTlsMode() == tlspb.TlsConfig_TLS_MODE_DISABLED {
		return "ws"
	}
	return "wss"
}

// dial initiates the WebSocket connection to u.
func (s *Session) dial(u string) error {
	glog.V(2).Infof("Copying I/O via %v", u)
	tlsCfg, err := tls.Config(s.opts.Transport.GetTlsConfig())
	if err != nil {
		return fmt.Errorf("tls.Config() error: %w", err)
	}
	d := &websocket.Dialer{TLSClientConfig: tlsCfg}
	s.ws, _, err = d.Dial(u, s.connectHeader())
	if err != nil {
		return fmt.Errorf("Dial(%v) error: %w", u, err)
	}
	return nil
}

// reconnectDial dials /v4/reconnect and returns the new WebSocket.
// It is passed to SetClientReconnectConfig and called by the session on unclean disconnect.
func (s *Session) reconnectDial(sid string, ack uint64) (*websocket.Conn, error) {
	u := s.reconnectURL(sid, ack)
	glog.V(2).Infof("Reconnecting via %v", u)
	tlsCfg, err := tls.Config(s.opts.Transport.GetTlsConfig())
	if err != nil {
		return nil, fmt.Errorf("tls.Config() error: %w", err)
	}
	d := &websocket.Dialer{TLSClientConfig: tlsCfg}
	ws, _, err := d.Dial(u, s.connectHeader())
	if err != nil {
		return nil, fmt.Errorf("Dial(%v) error: %w", u, err)
	}
	return ws, nil
}
