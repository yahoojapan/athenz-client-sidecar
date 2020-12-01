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

	"github.com/kpango/glg"
	"github.com/kpango/ntokend"
	"github.com/pkg/errors"
	"github.com/yahoojapan/athenz-client-sidecar/v2/config"
	"github.com/yahoojapan/athenz-client-sidecar/v2/handler"
	"github.com/yahoojapan/athenz-client-sidecar/v2/infra"
	"github.com/yahoojapan/athenz-client-sidecar/v2/router"
	"github.com/yahoojapan/athenz-client-sidecar/v2/service"
)

// Tenant represents a client sidecar behavior
type Tenant interface {
	Start(ctx context.Context) chan []error
}

type clientd struct {
	cfg     config.Config
	token   ntokend.TokenService
	server  service.Server
	access  service.AccessService
	role    service.RoleService
	svccert service.SvcCertService
}

// New returns a client sidecar daemon, or any error occurred.
// Client sidecar daemon contains token service, role token service, host certificate service, user database client and client sidecar service.
func New(cfg config.Config) (t Tenant, err error) {

	// create token service
	var token ntokend.TokenService
	var tokenProvider ntokend.TokenProvider
	if requireNtokend(cfg) {
		token, err = createNtokend(cfg.NToken)
		if err != nil {
			return nil, errors.Wrap(err, "ntokend error")
		}
		tokenProvider = token.GetTokenProvider()
		glg.Info("ntokend is enabled. we’re going to use ntoken to interact with Athenz server.")
	} else {
		glg.Info("ntokend is disabled.")
	}

	// create access service
	var access service.AccessService
	var accessProvider service.AccessProvider
	if cfg.AccessToken.Enable {
		access, err = service.NewAccessService(cfg.AccessToken, tokenProvider)
		if err != nil {
			return nil, errors.Wrap(err, "access token service error")
		}
		accessProvider = access.GetAccessProvider()
	}

	// create role service
	var role service.RoleService
	var roleProvider service.RoleProvider
	if cfg.RoleToken.Enable {
		role, err = service.NewRoleService(cfg.RoleToken, tokenProvider)
		if err != nil {
			return nil, errors.Wrap(err, "role token service error")
		}
		roleProvider = role.GetRoleProvider()
	}

	// create svccert service
	var svccert service.SvcCertService
	var svccertProvider service.SvcCertProvider
	if cfg.ServiceCert.Enable {
		svccert, err = service.NewSvcCertService(cfg, tokenProvider)
		if err != nil {
			return nil, errors.Wrap(err, "service certificate service error")
		}
		svccertProvider = svccert.GetSvcCertProvider()
	}

	// create handler
	h := handler.New(
		cfg.Proxy,
		infra.NewBuffer(cfg.Proxy.BufferSize),
		tokenProvider,
		accessProvider,
		roleProvider,
		svccertProvider,
	)

	serveMux := router.New(cfg, h)
	srv := service.NewServer(
		service.WithServerConfig(cfg.Server),
		service.WithServerHandler(serveMux),
	)

	return &clientd{
		cfg:     cfg,
		token:   token,
		access:  access,
		role:    role,
		svccert: svccert,
		server:  srv,
	}, nil
}

// Start returns a error slice channel. This error channel contains the error returned by client sidecar daemon.
func (t *clientd) Start(ctx context.Context) chan []error {
	if t.token != nil {
		t.token.StartTokenUpdater(ctx)
	}

	// t.svccert only is null when the configuration of ServiceCert is disabled
	if t.svccert != nil {
		t.svccert.StartSvcCertUpdater(ctx)
	}

	// t.access only is null when the configuration of Access is disabled
	if t.access != nil {
		go func() {
			for err := range t.access.StartAccessUpdater(ctx) {
				glg.Error(err)
			}
		}()
	}

	if t.role != nil {
		go func() {
			for err := range t.role.StartRoleUpdater(ctx) {
				glg.Error(err)
			}
		}()
	}
	return t.server.ListenAndServe(ctx)
}

// createNtokend returns a TokenService object or any error
func createNtokend(cfg config.NToken) (ntokend.TokenService, error) {

	if !cfg.Enable {
		return nil, errors.New("Disabled")
	}

	dur, err := time.ParseDuration(cfg.RefreshPeriod)
	if err != nil {
		return nil, fmt.Errorf("invalid token refresh period %s, %v", cfg.RefreshPeriod, err)
	}

	exp, err := time.ParseDuration(cfg.Expiry)
	if err != nil {
		return nil, fmt.Errorf("invalid token expiry %s, %v", cfg.Expiry, err)
	}

	keyData, err := ioutil.ReadFile(config.GetActualValue(cfg.PrivateKeyPath))
	if err != nil && keyData == nil {
		if cfg.ExistingTokenPath == "" {
			return nil, fmt.Errorf("invalid token private key %v", err)
		}
	}

	domain := config.GetActualValue(cfg.AthenzDomain)
	service := config.GetActualValue(cfg.ServiceName)

	ntd, err := ntokend.New(
		ntokend.RefreshDuration(dur),
		ntokend.TokenExpiration(exp),
		ntokend.KeyVersion(cfg.KeyVersion),
		ntokend.KeyData(keyData),
		ntokend.TokenFilePath(cfg.ExistingTokenPath),
		ntokend.AthenzDomain(domain),
		ntokend.ServiceName(service),
	)

	if err != nil {
		return nil, err
	}

	return ntd, nil
}

func requireNtokend(cfg config.Config) bool {
	if cfg.NToken.Enable {
		glg.Info("Requires ntokend as ntoken endpoint is enabled")
		return true
	}
	if cfg.AccessToken.Enable && cfg.AccessToken.CertPath == "" {
		glg.Info("Requires ntokend as access token endpoint is enabled, and client certificate is not set")
		return true
	}
	if cfg.RoleToken.Enable && cfg.RoleToken.CertPath == "" {
		glg.Info("Requires ntokend as role token endpoint is enabled, and client certificate is not set")
		return true
	}
	if cfg.ServiceCert.Enable {
		glg.Info("Requires ntokend as service certificate endpoint is enabled")
		return true
	}
	if cfg.Proxy.Enable {
		glg.Info("Requires ntokend as proxy endpoint is enabled")
		return true
	}

	return false
}
