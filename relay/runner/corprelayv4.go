package runner

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"

	"github.com/golang/glog"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/hazaelsan/ssh-relay/relay/request"
	"github.com/hazaelsan/ssh-relay/session"
	v4session "github.com/hazaelsan/ssh-relay/session/corprelayv4"
)

// connectHandleV4 handles /v4/connect requests.
func (r *Runner) connectHandleV4(w http.ResponseWriter, req *http.Request) {
	var s session.Session
	var ws *websocket.Conn
	var addr string
	code, err := func() (code int, err error) {
		host := req.URL.Query().Get("host")
		port := req.URL.Query().Get("port")
		dstUsername := req.URL.Query().Get("dstUsername")
		origin, err := request.Origin(req, r.cfg.OriginCookieName)
		if err != nil {
			return http.StatusBadRequest, fmt.Errorf("request.Origin(%v) error: %w", r.cfg.OriginCookieName, err)
		}
		addr = net.JoinHostPort(host, port)
		ssh, err := net.Dial("tcp", addr)
		if err != nil {
			return http.StatusBadGateway, fmt.Errorf("net.Dial(%v) error: %w", addr, err)
		}
		s, err = r.mgr.New(ssh, session.CorpRelayV4)
		if err != nil {
			return http.StatusServiceUnavailable, fmt.Errorf("mgr.New(%v) error: %w", addr, err)
		}
		glog.V(4).Infof("%v: Connected to %v (dstUsername: %v)", s, addr, dstUsername)

		upgrader := websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return r.Header.Get("Origin") == origin
			},
			Subprotocols: []string{"ssh"},
		}
		ws, err = upgrader.Upgrade(w, req, nil)
		if err != nil {
			return http.StatusBadGateway, fmt.Errorf("upgrader.Upgrade(%v) error: %w", origin, err)
		}
		return 0, nil
	}()
	if err != nil {
		http.Error(w, errors.Unwrap(err).Error(), code)
		if glog.V(5) {
			glog.Error(err)
		}
		return
	}
	defer ws.Close()
	if err := s.Run(ws); err != nil {
		if errors.Is(err, io.EOF) {
			glog.V(1).Infof("%v: Connection to %v closed", s, addr)
			if err := r.mgr.Delete(s.SID()); err != nil {
				glog.Errorf("mgr.Delete(%v) error: %v", s, err)
			}
			return
		}
		glog.Error(err)
	}
}

// reconnectHandleV4 handles /v4/reconnect requests.
// It looks up the existing session by SID and resumes it on a new WebSocket.
func (r *Runner) reconnectHandleV4(w http.ResponseWriter, req *http.Request) {
	sidStr := req.URL.Query().Get("sid")
	ackStr := req.URL.Query().Get("ack")

	ack, err := strconv.ParseUint(ackStr, 10, 64)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid ack: %v", err), http.StatusBadRequest)
		return
	}
	sid, err := uuid.Parse(sidStr)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid sid: %v", err), http.StatusBadRequest)
		return
	}

	sess, err := r.mgr.Get(sid)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	sv4, ok := sess.(*v4session.Session)
	if !ok {
		http.Error(w, "session type mismatch", http.StatusBadRequest)
		return
	}

	origin, err := request.Origin(req, r.cfg.OriginCookieName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return r.Header.Get("Origin") == origin
		},
		Subprotocols: []string{"ssh"},
	}
	ws, err := upgrader.Upgrade(w, req, nil)
	if err != nil {
		glog.Errorf("reconnect upgrader.Upgrade(%v) error: %v", origin, err)
		return
	}
	defer ws.Close()
	if err := sv4.Reconnect(ws, ack); err != nil {
		glog.Errorf("%v: Reconnect error: %v", sid, err)
	}
}
