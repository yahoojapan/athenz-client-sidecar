package service

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"ghe.corp.yahoo.co.jp/athenz/athenz-tenant-sidecar/config"
	"github.com/kpango/glg"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
)

type Server interface {
	ListenAndServe(context.Context) chan error
	Shutdown(context.Context) error
}

type server struct {
	srv   *http.Server
	hcsrv *http.Server
	cfg   config.Server
}

const (
	ContentType = "Content-Type"
	TextPlain   = "text/plain"
	CharsetUTF8 = "charset=UTF-8"
)

var (
	ErrContextClosed = errors.New("context Closed")
)

func NewServer(cfg config.Server, h http.Handler) Server {
	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Port),
		Handler: h,
	}
	srv.SetKeepAlivesEnabled(true)
	mux := http.NewServeMux()
	mux.HandleFunc(cfg.HealthzPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			w.Header().Set(ContentType, fmt.Sprintf("%s;%s", TextPlain, CharsetUTF8))
			_, err := fmt.Fprint(w, http.StatusText(http.StatusOK))
			if err != nil {
				glg.Fatal(err)
			}
		}
	})
	hcsrv := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.HealthzPort),
		Handler: mux,
	}
	hcsrv.SetKeepAlivesEnabled(true)
	return &server{
		srv:   srv,
		hcsrv: hcsrv,
		cfg:   cfg,
	}
}

func (s *server) ListenAndServe(ctx context.Context) chan error {
	echan := make(chan error, 1)
	go func() {
		defer func() {
			err := s.hcsrv.Close()
			if err != nil {
				glg.Fatal(err)
			}
			err = s.srv.Close()
			if err != nil {
				glg.Fatal(err)
			}
		}()

		eg := new(errgroup.Group)
		eg.Go(func() error {
			cfg, err := NewTLSConfig(s.cfg.TLS)
			if err == nil && cfg != nil {
				s.srv.TLSConfig = cfg
			} else {
				return s.srv.ListenAndServe()
			}
			return s.srv.ListenAndServeTLS("", "")
		})

		eg.Go(func() error {
			return s.hcsrv.ListenAndServe()
		})

		eg.Go(func() error {
			<-ctx.Done()
			return ctx.Err()
		})

		echan <- eg.Wait()
	}()
	return echan
}

func (s *server) Shutdown(ctx context.Context) error {
	dur, err := time.ParseDuration(s.cfg.ShutdownDuration)
	if err != nil {
		dur = time.Second * 5
	}

	eg := new(errgroup.Group)

	eg.Go(func() error {
		sctx, scancel := context.WithTimeout(ctx, dur)
		defer scancel()
		return s.srv.Shutdown(sctx)
	})

	eg.Go(func() error {
		hctx, hcancel := context.WithTimeout(ctx, dur)
		defer hcancel()
		return s.hcsrv.Shutdown(hctx)
	})

	return eg.Wait()
}
