package service

import (
	"net/http"

	"github.com/yahoojapan/athenz-client-sidecar/config"
)

type Option func(*server)

func WithServerConfig(cfg config.Server) Option {
	return func(s *server) {
		s.cfg = cfg
	}
}

func WithServerHandler(h http.Handler) Option {
	return func(s *server) {
		s.srvHandler = h
	}
}
