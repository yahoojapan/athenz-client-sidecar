/*
Copyright (C)  2018 Yahoo Japan Corporation Athenz team.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
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
