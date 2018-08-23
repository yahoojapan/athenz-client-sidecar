package usecase

import (
	"context"

	"ghe.corp.yahoo.co.jp/athenz/hcc-k8s/config"
	"ghe.corp.yahoo.co.jp/athenz/hcc-k8s/handler"
	"ghe.corp.yahoo.co.jp/athenz/hcc-k8s/router"
	"ghe.corp.yahoo.co.jp/athenz/hcc-k8s/service"
)

type HCC interface {
	Start(ctx context.Context) chan error
	Stop(ctx context.Context) error
}

type hccd struct {
	cfg    config.Config
	token  service.TokenVerifier
	udb    service.UDB
	hcc    service.HCC
	server service.Server
}

func New(cfg config.Config) (HCC, error) {
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
	return &hccd{
		cfg:   cfg,
		token: token,
		udb:   u,
		hcc:   hcc,
		server: service.NewServer(cfg.Server,
			router.New(cfg.Server,
				handler.New(u, token.GetTokenProvider(), hcc.GetCertProvider()))),
	}, nil
}

func (h *hccd) Start(ctx context.Context) chan error {
	h.token.StartTokenUpdater(ctx)
	h.hcc.StartCertUpdater(ctx)
	return h.server.ListenAndServe(ctx)
}

func (h *hccd) Stop(ctx context.Context) error {
	return h.server.Shutdown(ctx)
}
