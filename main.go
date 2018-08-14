package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"ghe.corp.yahoo.co.jp/athenz/hcc-k8s/config"
	"ghe.corp.yahoo.co.jp/athenz/hcc-k8s/usecase"
	"github.com/kpango/glg"
	"github.com/pkg/errors"
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
		"/etc/hcc/config.yaml",
		"hcc config yaml file path")
	f.BoolVar(&p.showVersion,
		"version",
		false,
		"show hcc version")

	err := f.Parse(os.Args[1:])
	if err != nil {
		return nil, errors.Wrap(err, "Parse Failed")
	}

	return p, nil
}

func run(cfg config.Config) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	daemon, err := usecase.New(cfg)
	if err != nil {
		return err
	}

	ech := daemon.Start(ctx)

	sigCh := make(chan os.Signal, 1)

	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	for {
		select {
		case <-sigCh:
			close(sigCh)
			glg.Warn("hcc server shutdown...")
			return daemon.Stop(ctx)
		case err = <-ech:
			close(ech)
			return err
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

	// Docker環境においては色出力の意味がないため無効にする
	defer glg.Get().Stop()

	p, err := parseParams()
	if err != nil {
		glg.Fatal(err)
		return
	}

	if p.showVersion {
		glg.Infof("hcc version -> %s", config.GetVersion())
		return
	}

	cfg, err := config.New(p.configFilePath)
	if err != nil {
		glg.Fatal(err)
		return
	}

	if cfg.Version != config.GetVersion() {
		glg.Fatal(errors.New("invalid hccaphic proxy configuration version"))
		return
	}

	err = run(*cfg)
	if err != nil {
		glg.Fatal(err)
		return
	}
}
