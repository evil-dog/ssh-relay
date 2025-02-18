// example implements a simple gRPC server for authorizing /cookie requests.
//
// This implementation is a Proof of Concept -- it doesn't provide any
// additional security compared to a regular `ssh(1)` session.
package main

import (
  ctls "crypto/tls"
	"context"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"github.com/hazaelsan/ssh-relay/tls"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	configpb "github.com/hazaelsan/ssh-relay/cookie-server/backend/example/proto/v1/config_go_proto"
	servicepb "github.com/hazaelsan/ssh-relay/cookie-server/proto/v1/service_go_proto"
)

var (
	cfgFile = flag.String("config", "", "path to a textproto config file")
)

func loadConfig(s string) (*configpb.Config, error) {
	buf, err := ioutil.ReadFile(s)
	if err != nil {
		return nil, err
	}
	cfg := new(configpb.Config)
	if err := proto.UnmarshalText(string(buf), cfg); err != nil {
		return nil, err
	}
	if cfg.GrpcOptions == nil {
		return nil, errors.New("grpc_options must be set")
	}
	if cfg.GetSshRelayAddr() == "" {
		return nil, errors.New("ssh_relay_addr must be set")
	}
	return cfg, nil
}

func main() {
	flag.Parse()
	if *cfgFile == "" {
		glog.Exit("--config must be set")
	}
	cfg, err := loadConfig(*cfgFile)
	if err != nil {
		glog.Exit(err)
	}
	s := &Server{cfg: cfg}
	glog.Exit(s.Run())
}

// A Server is a non-authenticating server for Cookie Server gRPC requests.
type Server struct {
	cfg *configpb.Config
}

// Run starts the Server.
func (s *Server) Run() error {
  var tlsCfg *ctls.Config
  var err error

  if (s.cfg.GrpcOptions.TlsConfig != nil) {
  	tlsCfg, err = tls.CertConfig(s.cfg.GetGrpcOptions().GetTlsConfig())
	  if err != nil {
		  return fmt.Errorf("tls.CertConfig() error: %w", err)
	  }
  }
	addr := net.JoinHostPort(s.cfg.GetGrpcOptions().GetAddr(), s.cfg.GetGrpcOptions().GetPort())
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("net.Listen(%v) error: %w", addr, err)
	}

  var srv *grpc.Server
  if (s.cfg.GrpcOptions.TlsConfig != nil) {
  	srv = grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsCfg)))
  } else {
  	srv = grpc.NewServer()
  }

	servicepb.RegisterCookieServerServer(srv, s)
	glog.V(4).Infof("gRPC server listening on %v", addr)
	return srv.Serve(l)
}

// Authorize responds to a /cookie authorization request, it always succeeds.
func (s *Server) Authorize(ctx context.Context, req *servicepb.AuthorizeRequest) (*servicepb.AuthorizeResponse, error) {
	return &servicepb.AuthorizeResponse{
		Redirect: &servicepb.AuthorizeResponse_Endpoint{s.cfg.GetSshRelayAddr()},
		Method:   req.GetRequest().GetMethod(),
	}, nil
}
