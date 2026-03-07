package runner

import (
	"fmt"
	"time"

	"github.com/hazaelsan/ssh-relay/duration"
	"github.com/hazaelsan/ssh-relay/http"
	"github.com/hazaelsan/ssh-relay/relay/session/manager"

	"github.com/hazaelsan/ssh-relay/proto/v1/protocolversionpb"
	"github.com/hazaelsan/ssh-relay/relay/proto/v1/configpb"
)

func protocolEnabled(cfg *configpb.Config, pv protocolversionpb.ProtocolVersion) bool {
	for _, v := range cfg.GetProtocolVersions() {
		if v == pv {
			return true
		}
	}
	return false
}

// New instantiates a Runner with a *configpb.Config.
func New(cfg *configpb.Config) (*Runner, error) {
	s, err := http.NewServer(cfg.ServerOptions)
	if err != nil {
		return nil, fmt.Errorf("http.NewServer() error = %w", err)
	}
	var maxAge time.Duration
	if err := duration.FromProto(&maxAge, cfg.MaxSessionAge); err != nil {
		return nil, fmt.Errorf("duration.FromProto(%v) error = %w", cfg.MaxSessionAge, err)
	}
	var reconnectWait time.Duration
	if err := duration.FromProto(&reconnectWait, cfg.ReconnectWaitTimeout); err != nil {
		return nil, fmt.Errorf("duration.FromProto(%v) error = %w", cfg.ReconnectWaitTimeout, err)
	}
	epRouter, err := newEndpointRouter(cfg)
	if err != nil {
		return nil, fmt.Errorf("newEndpointRouter() error = %w", err)
	}
	r := &Runner{
		cfg:      cfg,
		mgr:      manager.New(int(cfg.MaxSessions), maxAge, int(cfg.ReconnectBufferSize), reconnectWait),
		server:   s,
		epRouter: epRouter,
	}

	// /endpoint is registered unconditionally — it's the discovery layer.
	s.HandleFunc("/endpoint", r.endpointHandle)

	if protocolEnabled(cfg, protocolversionpb.ProtocolVersion_CORP_RELAY) {
		s.HandleFunc("/connect", r.connectHandle)
		s.HandleFunc("/proxy", r.proxyHandle)
	}
	if protocolEnabled(cfg, protocolversionpb.ProtocolVersion_CORP_RELAY_V4) {
		s.HandleFunc("/v4/connect", r.connectHandleV4)
		s.HandleFunc("/v4/reconnect", r.reconnectHandleV4)
	}

	return r, nil
}

// Runner is the main SSH-over-WebSocket Relay connection handler.
type Runner struct {
	cfg      *configpb.Config
	mgr      *manager.Manager
	server   *http.Server
	epRouter *endpointRouter
}

// Run executes the runner, listens for incoming client connections.
func (r *Runner) Run() error {
	return r.server.Run()
}
