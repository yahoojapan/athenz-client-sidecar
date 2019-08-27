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
package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/kpango/gache"
	"github.com/kpango/glg"
	"github.com/yahoojapan/athenz-client-sidecar/config"
	"golang.org/x/sync/singleflight"
)

var (
	// defaultRefreshDuration represent the default svccert expiry time.
	defaultRefreshDuration = time.Hour * 24
)

type SvcCertService interface {
	StartSvcCertUpdate(context.Context) SvcCertService
	GetSvcCertProvider() SvcCertProvider
}

// svcCertService represent the implementation of athenz RoleService
type svcCertService struct {
	cfg                   config.Token
	athenzURL             string
	dnsDomain             string
	athenzPrincipleHeader string
	intermediateCert      bool
	svcCert               *atomic.Value
	group                 singleflight.Group
	refreshDuration       time.Duration
	httpClient            *http.Client
}

// SvcCert represent the basic information of the svccert.
type SvcCert struct {
	Cert       []byte `json:"cert"`
	ExpiryTime int64  `json:"expiryTime"`
}

// SvcCertProvider represent a function pointer to get the svccert.
type SvcCertProvider func(ctx context.Context, domain string, role string, proxyForPrincipal string, minExpiry time.Duration, maxExpiry time.Duration) (*SvcCert, error)

// NewSvcCertService returns a SvcCertService to update and get the svccert from athenz.
func NewSvcCertService(cfg config.Config) SvcCertService {
	dur, err := time.ParseDuration(cfg.ServiceCert.RefreshDuration)
	if err != nil {
		dur = defaultRefreshDuration
	}

	var cp *x509.CertPool
	var httpClient *http.Client
	if len(cfg.ServiceCert.AthenzRootCA) != 0 {
		certPath := config.GetActualValue(cfg.ServiceCert.AthenzRootCA)
		_, err := os.Stat(certPath)
		if !os.IsNotExist(err) {
			cp, err = NewX509CertPool(certPath)
			if err != nil {
				cp = nil
			}
		}
	}
	if cp != nil {
		httpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: cp,
				},
			},
		}
	} else {
		httpClient = http.DefaultClient
	}

	return &svcCertService{
		athenzURL:          cfg.ServiceCert.AthenzURL,
		dnsDomain:          cfg.ServiceCert.DNSDomain,
		intermediateCert:   cfg.ServiceCert.IntermediateCert,
		domainSvcCertCache: gache.New(),
		refreshDuration:    dur,
		httpClient:         httpClient,
	}
}

func (s *svcCertService) StartSvcCertUpdate(ctx context.Context) SvcCertService {
	go func() {
		var err error
		err = s.update()
		fch := make(chan struct{})
		if err != nil {
			glg.Error(err)
			fch <- struct{}{}
		}

		ticker := time.NewTicker(s.refreshDuration)
		for {
			select {
			case <-ctx.Done():
				ticker.Stop()
				return
			case <-fch:
				err = s.update()
				if err != nil {
					glg.Error(err)
					time.Sleep(time.Second)
					fch <- struct{}{}
				}
			case <-ticker.C:
				err = s.update()
				if err != nil {
					glg.Error(err)
					fch <- struct{}{}
				}
			}
		}
	}()
	return s
}

func (s *svcCertService) GetSvcCertProvider() SvcCertProvider {
	return nil
}

func (s *svcCertService) update() error {
	cert, err := s.loadSvcCert()
	if err != nil {
		return err
	}
	s.setCert(cert)
	return nil
}

func (s *svcCertService) setCert(svcCert []byte) {
	s.svcCert.Store(svcCert)
}

func (s *svcCertService) loadSvcCert() ([]byte, error) {
	return nil, nil
}
