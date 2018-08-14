package usecase

import (
	"context"

	"ghe.corp.yahoo.co.jp/athenz/hcc-k8s/config"
	"ghe.corp.yahoo.co.jp/athenz/hcc-k8s/handler"
	"ghe.corp.yahoo.co.jp/athenz/hcc-k8s/router"
	"ghe.corp.yahoo.co.jp/athenz/hcc-k8s/service"
)

type DemogDaemon interface {
	Start(ctx context.Context) chan error
	Stop(ctx context.Context) error
}

type hcc struct {
	cfg    config.Config
	token  service.TokenVerifier
	udb    service.UDB
	server service.Server
}

func New(cfg config.Config) (DemogDaemon, error) {
	token, err := service.NewTokenService(cfg.Token)
	if err != nil {
		return nil, err
	}
	token.SetHostname(cfg.YCA.Hostname)
	token.SetIPAddr(cfg.YCA.IP)

	yca, err := service.NewYCA(cfg.YCA, token.GetTokenProvider())
	if err != nil {
		return nil, err
	}

	u := service.NewUDBClient(cfg.UDB, yca)
	e := service.NewEncrypter()
	return &hcc{
		cfg:    cfg,
		token:  token,
		udb:    u,
		server: service.NewServer(cfg.Server, router.New(cfg.Server, handler.New(u, e, cfg.Cookie))),
	}, nil
}

func (g *hcc) Start(ctx context.Context) chan error {
	g.token.StartTokenUpdater(ctx)
	return g.server.ListenAndServe(ctx)
}

func (g *hcc) Stop(ctx context.Context) error {
	return g.server.Shutdown(ctx)
}
