package usecase

import (
	"context"

	"ghe.corp.yahoo.co.jp/athenz/athenz-tenant-sidecar/config"
	"ghe.corp.yahoo.co.jp/athenz/athenz-tenant-sidecar/handler"
	"ghe.corp.yahoo.co.jp/athenz/athenz-tenant-sidecar/router"
	"ghe.corp.yahoo.co.jp/athenz/athenz-tenant-sidecar/service"
)

// Tenant represent a tenant sidecar behavour
type Tenant interface {
	Start(ctx context.Context) chan []error
}

type tenantd struct {
	cfg    config.Config
	token  service.TokenService
	udb    service.UDB
	hc     service.HC
	server service.Server
	role   service.RoleService
}

// New returns a tenant sidecar daemon, or any error occurred.
// Tenant sidecar daemon contains token service, role token service, host certificate service, user database client and tenant sidecar service.
func New(cfg config.Config) (Tenant, error) {
	// create token service
	token, err := service.NewTokenService(cfg.Token, cfg.HC)
	if err != nil {
		return nil, err
	}

	// create role service
	role := service.NewRoleService(cfg.Role, token.GetTokenProvider())

	// create host certificate service
	hc, err := service.NewHC(cfg.HC, token.GetTokenProvider())
	if err != nil {
		return nil, err
	}

	// create UDB client
	u := service.NewUDBClient(cfg.UDB, hc.GetCertProvider())

	serveMux := router.New(cfg.Server, handler.New(cfg.Proxy, u, token.GetTokenProvider(), role.GetRoleProvider(), hc.GetCertProvider()))

	return &tenantd{
		cfg:    cfg,
		token:  token,
		udb:    u,
		hc:     hc,
		role:   role,
		server: service.NewServer(cfg.Server, serveMux),
	}, nil
}

// Start returns a error slice channel. This error channel contains the error returned by tenant sidecar daemon.
func (t *tenantd) Start(ctx context.Context) chan []error {
	t.token.StartTokenUpdater(ctx)
	t.role.StartRoleUpdater(ctx)
	t.hc.StartCertUpdater(ctx)
	return t.server.ListenAndServe(ctx)
}
