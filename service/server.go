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
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/kpango/glg"
	"github.com/yahoojapan/athenz-client-sidecar/config"
)

// Server represents a client sidecar server behavior
type Server interface {
	ListenAndServe(context.Context) chan []error
}

type server struct {
	// client sidecar server
	srv        *http.Server
	srvHandler http.Handler
	srvRunning bool

	// Health Check server
	hcsrv     *http.Server
	hcrunning bool

	cfg config.Server

	// ShutdownDelay
	sdd time.Duration

	// ShutdownTimeout
	sdt time.Duration

	// mutext lock variable
	mu sync.RWMutex
}

const (
	// ContentType represents a HTTP header name "Content-Type"
	ContentType = "Content-Type"

	// TextPlain represents a HTTP content type "text/plain"
	TextPlain = "text/plain"

	// CharsetUTF8 represents a UTF-8 charset for HTTP response "charset=UTF-8"
	CharsetUTF8 = "charset=UTF-8"
)

var (
	// ErrContextClosed represents a error that the context is closed
	ErrContextClosed = errors.New("context Closed")
)

// NewServer returns a Server interface, which includes client sidecar server and health check server structs.
// The client sidecar server is a http.Server instance, which the port number is read from "config.Server.Port"
// , and set the handler as this function argument "handler".
//
// The health check server is a http.Server instance, which the port number is read from "config.Server.HealthCheck.Port"
// , and the handler is as follow - Handle HTTP GET request and always return HTTP Status OK (200) response.
func NewServer(opts ...Option) Server {
	var err error

	s := &server{}
	for _, o := range opts {
		o(s)
	}

	s.srv = &http.Server{
		Addr:    fmt.Sprintf(":%d", s.cfg.Port),
		Handler: s.srvHandler,
	}
	s.srv.SetKeepAlivesEnabled(true)

	if s.healthzSrvEnable() {
		s.hcsrv = &http.Server{
			Addr:    fmt.Sprintf(":%d", s.cfg.HealthCheck.Port),
			Handler: createHealthCheckServiceMux(s.cfg.HealthCheck.Endpoint),
		}
		s.hcsrv.SetKeepAlivesEnabled(true)
	}

	s.sdt, err = time.ParseDuration(s.cfg.ShutdownTimeout)
	if err != nil {
		glg.Warn(err)
	}

	s.sdd, err = time.ParseDuration(s.cfg.ShutdownDelay)
	if err != nil {
		glg.Warn(err)
	}

	return s
}

// ListenAndServe returns a error channel, which includes error returned from client sidecar server.
// This function start both health check and client sidecar server, and the server will close whenever the context receive a Done signal.
// Whenever the server closed, the client sidecar server will shutdown after a defined duration (cfg.ShutdownDelay), while the health check server will shutdown immediately
func (s *server) ListenAndServe(ctx context.Context) chan []error {
	var (
		echan = make(chan []error, 1)
		sech  = make(chan error, 1)
		hech  chan error

		wg = new(sync.WaitGroup)
	)

	// start both client sidecar server and health check server
	wg.Add(1)
	go func() {
		s.mu.Lock()
		s.srvRunning = true
		s.mu.Unlock()
		wg.Done()

		glg.Info("client sidecar api server starting")
		sech <- s.listenAndServeAPI()
		close(sech)

		s.mu.Lock()
		s.srvRunning = false
		s.mu.Unlock()
	}()

	if s.healthzSrvEnable() {
		wg.Add(1)
		hech = make(chan error, 1)
		go func() {
			s.mu.Lock()
			s.hcrunning = true
			s.mu.Unlock()
			wg.Done()

			glg.Info("client sidecar health check server starting")
			hech <- s.hcsrv.ListenAndServe()
			close(hech)

			s.mu.Lock()
			s.hcrunning = false
			s.mu.Unlock()
		}()
	}

	go func() {
		// wait for all server running
		wg.Wait()

		appendErr := func(errs []error, err error) []error {
			if err != nil {
				return append(errs, err)
			}
			return errs
		}

		errs := make([]error, 0, 3)
		for {
			select {
			case <-ctx.Done(): // when context receive done signal, close running servers and return any error
				s.mu.RLock()
				if s.hcrunning {
					glg.Info("client sidecar health check server will shutdown")
					errs = appendErr(errs, s.hcShutdown(context.Background()))
				}
				if s.srvRunning {
					glg.Info("client sidecar api server will shutdown")
					errs = appendErr(errs, s.apiShutdown(context.Background()))
				}
				s.mu.RUnlock()

				echan <- appendErr(errs, ctx.Err())
				return

			case err := <-sech: // when client sidecar server returns, close running health check server and return any error
				if err != nil {
					errs = appendErr(errs, err)
				}

				s.mu.RLock()
				if s.hcrunning {
					glg.Info("client sidecar health check server will shutdown")
					errs = appendErr(errs, s.hcShutdown(ctx))
				}
				s.mu.RUnlock()
				echan <- errs
				return

			case err := <-hech: // when health check server returns, close running client sidecar server and return any error
				if err != nil {
					errs = append(errs, err)
				}

				s.mu.RLock()
				if s.srvRunning {
					glg.Info("client sidecar api server will shutdown")
					errs = appendErr(errs, s.apiShutdown(ctx))
				}
				s.mu.RUnlock()
				echan <- errs
				return
			}
		}
	}()

	return echan
}

func (s *server) hcShutdown(ctx context.Context) error {
	hctx, hcancel := context.WithTimeout(ctx, s.sdt)
	defer hcancel()
	return s.hcsrv.Shutdown(hctx)
}

// apiShutdown returns any error when shutdown the client sidecar server.
// Before shutdown the client sidecar server, it will sleep config.ShutdownDelay to prevent any issue from K8s
func (s *server) apiShutdown(ctx context.Context) error {
	time.Sleep(s.sdd)
	sctx, scancel := context.WithTimeout(ctx, s.sdt)
	defer scancel()
	return s.srv.Shutdown(sctx)
}

// createHealthCheckServiceMux return a *http.ServeMux object
// The function will register the health check server handler for given pattern, and return
func createHealthCheckServiceMux(pattern string) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc(pattern, handleHealthCheckRequest)
	return mux
}

// handleHealthCheckRequest is a handler function for and health check request, which always a HTTP Status OK (200) result
func handleHealthCheckRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.WriteHeader(http.StatusOK)
		w.Header().Set(ContentType, fmt.Sprintf("%s;%s", TextPlain, CharsetUTF8))
		_, err := fmt.Fprint(w, http.StatusText(http.StatusOK))
		if err != nil {
			glg.Fatal(err)
		}
	}
}

// listenAndServeAPI return any error occurred when start a HTTPS server, including any error when loading TLS certificate
func (s *server) listenAndServeAPI() error {
	if !s.cfg.TLS.Enable {
		return s.srv.ListenAndServe()
	}

	cfg, err := NewTLSConfig(s.cfg.TLS)
	if err == nil && cfg != nil {
		s.srv.TLSConfig = cfg
	}
	if err != nil {
		glg.Error(err)
	}
	return s.srv.ListenAndServeTLS("", "")
}

func (s *server) healthzSrvEnable() bool {
	return s.cfg.HealthCheck.Port > 0
}
