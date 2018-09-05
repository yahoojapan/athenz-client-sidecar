package usecase

import (
	"context"

	"ghe.corp.yahoo.co.jp/athenz/athenz-tenant-sidecar/config"
	"ghe.corp.yahoo.co.jp/athenz/athenz-tenant-sidecar/handler"
	"ghe.corp.yahoo.co.jp/athenz/athenz-tenant-sidecar/router"
	"ghe.corp.yahoo.co.jp/athenz/athenz-tenant-sidecar/service"
)

type Tenant interface {
	Start(ctx context.Context) chan error
	Stop(ctx context.Context) error
}

type tenantd struct {
	cfg    config.Config
	token  service.TokenVerifier
	udb    service.UDB
	hcc    service.HCC
	server service.Server
}

func New(cfg config.Config) (Tenant, error) {
	token, err := service.NewTokenService(cfg.Token)
	if err != nil {
		return nil, err
	}
	token.SetHostname(cfg.HCC.Hostname)
	token.SetIPAddr(cfg.HCC.IP)

	hcc, err := service.NewHCC(cfg.HCC, token.GetTokenProvider())
	if err != nil {
		return nil, err
	}

	u := service.NewUDBClient(cfg.UDB, hcc.GetCertProvider())
	return &tenantd{
		cfg:   cfg,
		token: token,
		udb:   u,
		hcc:   hcc,
		server: service.NewServer(cfg.Server,
			router.New(cfg.Server,
				handler.New(cfg.Proxy, u, token.GetTokenProvider(), hcc.GetCertProvider()))),
	}, nil
}

func (t *tenantd) Start(ctx context.Context) chan error {
	t.token.StartTokenUpdater(ctx)
	t.hcc.StartCertUpdater(ctx)
	return t.server.ListenAndServe(ctx)
}

func (t *tenantd) Stop(ctx context.Context) error {
	return t.server.Shutdown(ctx)
}
