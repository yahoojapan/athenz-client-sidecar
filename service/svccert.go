package service

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

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/kpango/fastime"
	"github.com/kpango/glg"
	"github.com/kpango/ntokend"
	"github.com/yahoo/athenz/clients/go/zts"
	"github.com/yahoojapan/athenz-client-sidecar/config"
	"golang.org/x/sync/singleflight"
)

var (
	// defaultSvcCertRefreshDuration represents the default time to refresh the goroutine.
	defaultSvcCertRefreshDuration = time.Hour * 24

	// defaultSvcCertExpireMargin represents the default vaule of ExpireMargin.
	defaultSvcCertExpireMargin = time.Hour * 24 * 10

	// defaultSvcCertExpiration represents the default vaule of Expiration
	defaultSvcCertExpiration int32

	// domainReg is used to parse the athenz domain which is contained in config
	domainReg = regexp.MustCompile(`^([a-zA-Z0-9_][a-zA-Z0-9_-]*\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*$`)

	// ErrCertNotFound represents an error when failed to fetch the svccert from SvcCertProvider.
	ErrCertNotFound = errors.New("Failed to fetch service cert")

	// ErrInvalidCert represents an error when failed to parse the svccert from SvcCertProvider.
	ErrInvalidCert = errors.New("Failed to parse service cert")

	// ErrLoadPrivateKey represents an error when failed to load privatekey.
	ErrLoadPrivateKey = errors.New("PrivateKey does not exist")

	// ErrFailedToInitialize represents an error when failed to initialize a service.
	ErrFailedToInitialize = errors.New("Failed to initialize a service")

	// ErrInvalidParameter represents an error when the invalid parameter is contained in config
	ErrInvalidParameter = errors.New("Invalid parameter")
)

type signer struct {
	key       crypto.Signer
	algorithm x509.SignatureAlgorithm
}

type requestTemplate struct {
	req          *zts.InstanceRefreshRequest
	compoundName zts.CompoundName
	simpleName   zts.SimpleName
}

// SvcCertService represents a interface to automatically refresh the certificate.
type SvcCertService interface {
	StartSvcCertUpdater(context.Context) SvcCertService
	GetSvcCertProvider() SvcCertProvider
	RefreshSvcCert() ([]byte, error)
}

type certCache struct {
	cert []byte
	exp  time.Time
}

// svcCertService represents the implementation of athenz RoleService
type svcCertService struct {
	cfg             config.ServiceCert
	token           ntokend.TokenProvider
	certCache       *atomic.Value
	group           singleflight.Group
	refreshDuration time.Duration
	expireMargin    time.Duration
	client          *zts.ZTSClient
	refreshRequest  *requestTemplate
}

// SvcCertProvider represents a function pointer to get the svccert.
type SvcCertProvider func() ([]byte, error)

// NewSvcCertService returns a SvcCertService to update and get the svccert from athenz.
func NewSvcCertService(cfg config.Config, token ntokend.TokenProvider) (SvcCertService, error) {
	dur, err := time.ParseDuration(cfg.ServiceCert.RefreshDuration)
	if err != nil {
		glg.Warnf("Failed to parse configuration value of refresh_duration, err: %s. Using default value: %d", err.Error(), defaultSvcCertRefreshDuration)
		dur = defaultSvcCertRefreshDuration
	}

	beforeDur, err := time.ParseDuration(cfg.ServiceCert.ExpireMargin)
	if err != nil {
		glg.Warnf("Failed to parse configuration value of expire_margin, err: %s. Using default value: %d", err.Error(), defaultSvcCertExpireMargin)
		beforeDur = defaultSvcCertExpireMargin
	}

	// NOTE: The limitation for this expiration is not defined,
	// but it returns error if user sets the exceeded value by int64 (expect less than "1<<63 - 1").
	// The maximum 'cfg.ServiceCert.Expiration' is approximately 290 years.
	expireDur, err := time.ParseDuration(cfg.ServiceCert.Expiration)
	var expireInt int32
	if err != nil {
		glg.Warnf("Failed to parse configuration value of expiration, err: %s. Using default value: %d", err.Error(), defaultSvcCertExpiration)
		expireInt = defaultSvcCertExpiration
	} else {
		expireInt = int32(expireDur.Minutes())
	}

	reqTemp, client, err := setup(cfg, expireInt)
	if err != nil {
		return nil, err
	}

	cache := &atomic.Value{}
	cache.Store(
		certCache{
			cert: nil,
			exp:  fastime.Now(),
		},
	)

	return &svcCertService{
		cfg:             cfg.ServiceCert,
		certCache:       cache,
		token:           token,
		refreshDuration: dur,
		expireMargin:    beforeDur,
		client:          client,
		refreshRequest:  reqTemp,
	}, nil
}

func isValidDomain(domain string) bool {
	return domainReg.MatchString(domain)
}

func setup(cfg config.Config, expiration int32) (*requestTemplate, *zts.ZTSClient, error) {
	// load private key
	keyBytes, err := ioutil.ReadFile(cfg.Token.PrivateKeyPath)
	if err != nil {
		return nil, nil, ErrLoadPrivateKey
	}

	// get our private key signer for csr
	pkSigner, err := newSigner(keyBytes)
	if err != nil {
		return nil, nil, ErrFailedToInitialize
	}

	// generate a csr for this service
	// note: RFC 6125 states that if the SAN (Subject Alternative Name) exists,
	// it is used, not the CA. So, we will always put the Athenz name in the CN
	// (it is *not* a DNS domain name), and put the host name into the SAN.

	if !isValidDomain(cfg.Token.AthenzDomain) {
		return nil, nil, ErrInvalidParameter
	}

	hyphenDomain := strings.Replace(cfg.Token.AthenzDomain, ".", "-", -1)
	host := fmt.Sprintf("%s.%s.%s", cfg.Token.ServiceName, hyphenDomain, cfg.ServiceCert.DNSSuffix)
	commonName := fmt.Sprintf("%s.%s", cfg.Token.AthenzDomain, cfg.Token.ServiceName)

	subj := pkix.Name{
		CommonName:         commonName,
		OrganizationalUnit: []string{cfg.ServiceCert.Subject.OrganizationalUnit},
		Organization:       []string{cfg.ServiceCert.Subject.Organization},
		Province:           []string{cfg.ServiceCert.Subject.Province},
		Country:            []string{cfg.ServiceCert.Subject.Country},
	}

	uri := ""
	if cfg.ServiceCert.Spiffe {
		uri = fmt.Sprintf("spiffe://%s/sa/%s", cfg.Token.AthenzDomain, cfg.Token.ServiceName)
	}

	csrData, err := generateCSR(pkSigner, subj, host, uri)
	if err != nil {
		return nil, nil, ErrFailedToInitialize
	}

	// if we're given a certificate then we'll use that otherwise
	// we're going to generate a ntoken for our request unless
	// we're using copper argos which only uses tls and the attestation
	// data contains the authentication details

	client, err := ztsClient(cfg.ServiceCert)
	if err != nil {
		return nil, nil, ErrFailedToInitialize
	}

	// if we're given provider then we're going to use our
	// copper argos model to request the certificate
	req := &zts.InstanceRefreshRequest{
		Csr:        csrData,
		ExpiryTime: &expiration,
	}

	return &requestTemplate{
		req:          req,
		compoundName: zts.CompoundName(cfg.Token.AthenzDomain),
		simpleName:   zts.SimpleName(cfg.Token.ServiceName),
	}, client, nil
}

func newSigner(privateKeyPEM []byte) (*signer, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("Unable to load private key")
	}

	switch block.Type {
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return &signer{key: key, algorithm: x509.ECDSAWithSHA256}, nil
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return &signer{key: key, algorithm: x509.SHA256WithRSA}, nil
	default:
		return nil, fmt.Errorf("Unsupported private key type: %s", block.Type)
	}
}

func generateCSR(keySigner *signer, subj pkix.Name, host, uri string) (string, error) {
	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: keySigner.algorithm,
	}
	if host != "" {
		template.DNSNames = []string{host}
	}
	if uri != "" {
		uriptr, err := url.Parse(uri)
		if err == nil {
			template.URIs = []*url.URL{uriptr}
		}
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, keySigner.key)
	if err != nil {
		return "", fmt.Errorf("Cannot create CSR: %v", err)
	}
	block := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	}

	var buf bytes.Buffer
	err = pem.Encode(&buf, block)
	if err != nil {
		return "", fmt.Errorf("Cannot encode CSR to PEM: %v", err)
	}
	return buf.String(), nil
}

func ztsClient(cfg config.ServiceCert) (*zts.ZTSClient, error) {
	_, err := url.Parse(cfg.AthenzURL)
	if err != nil {
		return nil, ErrInvalidParameter
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ResponseHeaderTimeout: 30 * time.Second,
	}

	if cfg.AthenzRootCA != "" {
		config := &tls.Config{}
		certPool := x509.NewCertPool()
		caCert, err := ioutil.ReadFile(cfg.AthenzRootCA)
		if err != nil {
			return nil, err
		}
		certPool.AppendCertsFromPEM(caCert)
		config.RootCAs = certPool
		transport.TLSClientConfig = config
	}

	client := zts.NewClient(cfg.AthenzURL, transport)

	return &client, nil
}

func (s *svcCertService) StartSvcCertUpdater(ctx context.Context) SvcCertService {
	go func() {
		var err error
		fch := make(chan struct{}, 1)

		ticker := time.NewTicker(s.refreshDuration)
		for {
			select {
			case <-ctx.Done():
				ticker.Stop()
				return
			case <-fch:
				_, err = s.RefreshSvcCert()
				if err != nil {
					glg.Error(err)
					time.Sleep(time.Minute * 10)
					fch <- struct{}{}
				}
			case <-ticker.C:
				_, err = s.RefreshSvcCert()
				if err != nil {
					glg.Error(err)
					fch <- struct{}{}
				}
			}
		}
	}()
	return s
}

// GetSvcCertProvider returns a function pointer to get the svccert.
func (s *svcCertService) GetSvcCertProvider() SvcCertProvider {
	return s.getSvcCert
}

// getSvcCert return a token string or error
// This function is thread-safe. This function will return the svccert stored in the atomic variable,
// or return the error when the svccert is not initialized or cannot be generated
func (s *svcCertService) getSvcCert() ([]byte, error) {
	cache := s.certCache.Load().(certCache)

	if cache.cert == nil || cache.exp.Before(fastime.Now()) {
		cert, err := s.RefreshSvcCert()
		if err != nil {
			//  NOTE: When RefreshSvcCert is failed, return the cached certificate if it is not expired
			if cache.cert != nil && cache.exp.Add(s.expireMargin).After(fastime.Now()) {
				glg.Warn("Cached certificate is not expired. Return from cache. Error: " + err.Error())
				return cache.cert, nil
			}
			glg.Error(err)
			return nil, err
		}
		return cert, nil
	}
	return cache.cert, nil
}

func (s *svcCertService) RefreshSvcCert() ([]byte, error) {
	svccert, err, _ := s.group.Do("", func() (interface{}, error) {
		ntoken, err := s.token()
		if err != nil {
			return nil, err
		}

		s.client.AddCredentials(s.cfg.PrincipalAuthHeaderName, ntoken)

		// request a tls certificate for this service
		identity, err := s.client.PostInstanceRefreshRequest(
			s.refreshRequest.compoundName,
			s.refreshRequest.simpleName,
			s.refreshRequest.req,
		)
		if err != nil {
			return nil, err
		}

		block, _ := pem.Decode([]byte(identity.Certificate))
		if block == nil {
			return nil, ErrInvalidCert
		}

		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, ErrInvalidCert
		}

		var cert []byte
		if s.cfg.IntermediateCert {
			cert = []byte(identity.Certificate + identity.CaCertBundle)
		} else {
			cert = []byte(identity.Certificate)
		}

		// update cert cache and expiration
		cache := certCache{
			cert: cert,
			exp:  certificate.NotAfter.Add(-s.expireMargin),
		}
		s.certCache.Store(cache)

		return cert, nil
	})

	if err != nil {
		return nil, err
	}

	return svccert.([]byte), nil
}
