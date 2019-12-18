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
package usecase

import (
	"context"
	"fmt"
	"io/ioutil"
	"time"

	ntokend "github.com/kpango/ntokend"
	"github.com/yahoojapan/athenz-client-sidecar/config"
	"github.com/yahoojapan/athenz-client-sidecar/handler"
	"github.com/yahoojapan/athenz-client-sidecar/infra"
	"github.com/yahoojapan/athenz-client-sidecar/router"
	"github.com/yahoojapan/athenz-client-sidecar/service"
)

// Tenant represent a client sidecar behavior
type Tenant interface {
	Start(ctx context.Context) chan []error
}

type clientd struct {
	cfg     config.Config
	token   ntokend.TokenService
	server  service.Server
	role    service.RoleService
	svccert service.SvcCertService
}

// New returns a client sidecar daemon, or any error occurred.
// Client sidecar daemon contains token service, role token service, host certificate service, user database client and client sidecar service.
func New(cfg config.Config) (Tenant, error) {
	// create token service
	token, err := createNtokend(cfg.Token)
	if err != nil {
		return nil, err
	}

	// create role service
	role := service.NewRoleService(cfg.Role, token.GetTokenProvider())

	// create handler
	h := handler.New(
		cfg.Proxy,
		infra.NewBuffer(cfg.Proxy.BufferSize),
		token.GetTokenProvider(),
		role.GetRoleProvider(),
	)

	// create svccert service
	var svccert service.SvcCertService

	// Assign the svccert service. If a user does not set enable, sidecar does not handle the request to get the certificate.
	// And it is disabled by default.
	if cfg.ServiceCert.Enable {
		svccert, err := service.NewSvcCertService(cfg, token.GetTokenProvider())
		if err != nil {
			return nil, err
		}
		h.EnableSvcCert(svccert.GetSvcCertProvider())
	}

	serveMux := router.New(cfg, h)
	srv := service.NewServer(
		service.WithServerConfig(cfg.Server),
		service.WithServerHandler(serveMux),
	)

	return &clientd{
		cfg:     cfg,
		token:   token,
		role:    role,
		svccert: svccert,
		server:  srv,
	}, nil
}

// Start returns a error slice channel. This error channel contains the error returned by client sidecar daemon.
func (t *clientd) Start(ctx context.Context) chan []error {
	t.token.StartTokenUpdater(ctx)
	t.role.StartRoleUpdater(ctx)

	if t.svccert != nil {
		t.svccert.StartSvcCertUpdater(ctx)
	}

	return t.server.ListenAndServe(ctx)
}

// createNtokend returns a TokenService object or any error
func createNtokend(cfg config.Token) (ntokend.TokenService, error) {
	dur, err := time.ParseDuration(cfg.RefreshDuration)
	if err != nil {
		return nil, fmt.Errorf("invalid token refresh duration %s, %v", cfg.RefreshDuration, err)
	}

	exp, err := time.ParseDuration(cfg.Expiration)
	if err != nil {
		return nil, fmt.Errorf("invalid token expiration %s, %v", cfg.Expiration, err)
	}

	keyData, err := ioutil.ReadFile(config.GetActualValue(cfg.PrivateKeyPath))
	if err != nil && keyData == nil {
		if cfg.NTokenPath == "" {
			return nil, fmt.Errorf("invalid token certificate %v", err)
		}
	}

	domain := config.GetActualValue(cfg.AthenzDomain)
	service := config.GetActualValue(cfg.ServiceName)

	ntok, err := ntokend.New(ntokend.RefreshDuration(dur), ntokend.TokenExpiration(exp), ntokend.KeyVersion(cfg.KeyVersion), ntokend.KeyData(keyData), ntokend.TokenFilePath(cfg.NTokenPath),
		ntokend.AthenzDomain(domain), ntokend.ServiceName(service))

	if err != nil {
		return nil, err
	}

	return ntok, nil
}
