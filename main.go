package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/kpango/glg"
	"github.com/pkg/errors"
	"github.com/yahoojapan/athenz-client-sidecar/config"
	"github.com/yahoojapan/athenz-client-sidecar/usecase"
)

type params struct {
	configFilePath string
	showVersion    bool
}

func parseParams() (*params, error) {
	p := new(params)
	f := flag.NewFlagSet(filepath.Base(os.Args[0]), flag.ContinueOnError)
	f.StringVar(&p.configFilePath,
		"f",
		"/etc/athenz/client/config.yaml",
		"client config yaml file path")
	f.BoolVar(&p.showVersion,
		"version",
		false,
		"show athenz clientd version")

	err := f.Parse(os.Args[1:])
	if err != nil {
		return nil, errors.Wrap(err, "Parse Failed")
	}

	return p, nil
}

func run(cfg config.Config) []error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	daemon, err := usecase.New(cfg)
	if err != nil {
		return []error{err}
	}

	ech := daemon.Start(ctx)

	sigCh := make(chan os.Signal, 1)

	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	for {
		select {
		case <-sigCh:
			cancel()
			glg.Warn("athenz client server shutdown...")
		case errs := <-ech:
			return errs
		}
	}
}

func main() {
	defer func() {
		if err := recover(); err != nil {
			if _, ok := err.(runtime.Error); ok {
				panic(err)
			}
			glg.Error(err)
		}
	}()

	p, err := parseParams()
	if err != nil {
		glg.Fatal(err)
		return
	}

	if p.showVersion {
		glg.Infof("athenz clientd version -> %s", config.GetVersion())
		return
	}

	cfg, err := config.New(p.configFilePath)
	if err != nil {
		glg.Fatal(err)
		return
	}

	if cfg.Version != config.GetVersion() {
		glg.Fatal(errors.New("invalid athenz client proxy configuration version"))
		return
	}

	errs := run(*cfg)
	if errs != nil && len(errs) > 0 {
		glg.Fatal(errs)
		return
	}
}
