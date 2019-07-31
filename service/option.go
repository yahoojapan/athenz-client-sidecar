package service

import (
	"net/http"

	"github.com/yahoojapan/athenz-client-sidecar/config"
)

// Option represents the functional option implementation for server.
type Option func(*server)

// WithServerConfig set the service configuration to server.
func WithServerConfig(cfg config.Server) Option {
	return func(s *server) {
		s.cfg = cfg
	}
}

// WithServerHandler set the handler to server.
func WithServerHandler(h http.Handler) Option {
	return func(s *server) {
		s.srvHandler = h
	}
}
