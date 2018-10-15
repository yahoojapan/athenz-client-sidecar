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
	hc     service.HC
	server service.Server
	role   service.RoleService
}

func New(cfg config.Config) (Tenant, error) {
	token, err := service.NewTokenService(cfg.Token)
	if err != nil {
		return nil, err
	}
	err = token.SetHostname(config.GetValue(cfg.HC.Hostname))
	if err != nil {
		return nil, err
	}
	err = token.SetIPAddr(config.GetValue(cfg.HC.IP))
	if err != nil {
		return nil, err
	}

	role := service.NewRoleService(cfg.Role, token.GetTokenProvider())

	hc, err := service.NewHC(cfg.HC, token.GetTokenProvider())
	if err != nil {
		return nil, err
	}

	u := service.NewUDBClient(cfg.UDB, hc.GetCertProvider())
	return &tenantd{
		cfg:   cfg,
		token: token,
		udb:   u,
		hc:    hc,
		role:  role,
		server: service.NewServer(cfg.Server,
			router.New(cfg.Server,
				handler.New(cfg.Proxy, u, token.GetTokenProvider(), role.GetRoleProvider(), hc.GetCertProvider()))),
	}, nil
}

func (t *tenantd) Start(ctx context.Context) chan error {
	t.token.StartTokenUpdater(ctx)
	t.role.StartRoleUpdater(ctx)
	t.hc.StartCertUpdater(ctx)
	return t.server.ListenAndServe(ctx)
}

func (t *tenantd) Stop(ctx context.Context) error {
	return t.server.Shutdown(ctx)
}
