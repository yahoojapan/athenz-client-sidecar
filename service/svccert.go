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
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/kpango/glg"
	ntokend "github.com/kpango/ntokend"
	"github.com/yahoo/athenz/clients/go/zts"
	"github.com/yahoojapan/athenz-client-sidecar/config"
	"golang.org/x/sync/singleflight"
)

var (
	// defaultRefreshDuration represents the default time to refresh the goroutine.
	defaultSvcCertRefreshDuration = time.Hour * 24

	// defaultexpiration represents the default expiration time for certificate
	// defaultSvcCertExpiration = time.Hour * 24 * 20

	// ErrCertNotFound represents an error when failed to fetch the svccert from SvcCertProvider.
	ErrCertNotFound = errors.New("Failed to fetch service cert")

	// ErrCertNotFound represents an error when failed to parse the svccert from SvcCertProvider.
	ErrInvalidCert = errors.New("Failed to parse service cert")
)

type signer struct {
	key       crypto.Signer
	algorithm x509.SignatureAlgorithm
}

// SvcCertService represents a interface to automatically refresh the certificate.
type SvcCertService interface {
	StartSvcCertUpdater(context.Context) SvcCertService
	GetSvcCertProvider() SvcCertProvider
}

// svcCertService represents the implementation of athenz RoleService
type svcCertService struct {
	cfg             config.ServiceCert
	tokenCfg        config.Token
	token           ntokend.TokenProvider
	svcCert         *atomic.Value
	group           singleflight.Group
	refreshDuration time.Duration
	expiration      time.Time
	httpClient      *http.Client
}

// SvcCertProvider represents a function pointer to get the svccert.
type SvcCertProvider func() ([]byte, error)

// NewSvcCertService returns a SvcCertService to update and get the svccert from athenz.
func NewSvcCertService(cfg config.Config, token ntokend.TokenProvider) SvcCertService {
	dur, err := time.ParseDuration(cfg.ServiceCert.RefreshDuration)
	if err != nil {
		dur = defaultSvcCertRefreshDuration
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
		cfg:             cfg.ServiceCert,
		tokenCfg:        cfg.Token,
		svcCert:         &atomic.Value{},
		token:           token,
		refreshDuration: dur,
		httpClient:      httpClient,
	}
}

func (s *svcCertService) StartSvcCertUpdater(ctx context.Context) SvcCertService {
	go func() {
		var err error
		_, err = s.update()
		fch := make(chan struct{})
		if err != nil {
			fch <- struct{}{}
		}

		ticker := time.NewTicker(s.refreshDuration)
		for {
			select {
			case <-ctx.Done():
				ticker.Stop()
				return
			case <-fch:
				_, err = s.update()
				if err != nil {
					glg.Error(err)
					time.Sleep(time.Second)
					fch <- struct{}{}
				}
			case <-ticker.C:
				_, err = s.update()
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
	cert := s.svcCert.Load()

	if cert == nil || s.expiration.Before(time.Now()) {
		return s.update()
	}
	return cert.([]byte), nil
}

func (s *svcCertService) update() ([]byte, error) {
	cert, err := s.loadSvcCert()
	if err != nil {
		return nil, ErrCertNotFound
	}

	s.setCert(cert)

	block, _ := pem.Decode(cert)

	var certificate []*x509.Certificate
	if s.cfg.IntermediateCert {
		certificate, err = x509.ParseCertificates(block.Bytes)
	} else {
		certificate[0], err = x509.ParseCertificate(block.Bytes)
	}
	if err != nil {
		return nil, ErrInvalidCert
	}

	s.expiration = certificate[0].NotAfter
	return cert, nil
}

func (s *svcCertService) setCert(svcCert []byte) {
	s.svcCert.Store(svcCert)
}

func (s *svcCertService) loadSvcCert() ([]byte, error) {
	// load private key
	keyBytes, err := ioutil.ReadFile(s.tokenCfg.PrivateKeyPath)
	if err != nil {
		return nil, err
	}
	// get our private key signer for csr
	pkSigner, err := newSigner(keyBytes)
	if err != nil {
		return nil, err
	}

	// generate a csr for this service
	// note: RFC 6125 states that if the SAN (Subject Alternative Name) exists,
	// it is used, not the CA. So, we will always put the Athenz name in the CN
	// (it is *not* a DNS domain name), and put the host name into the SAN.

	hyphenDomain := strings.Replace(s.tokenCfg.AthenzDomain, ".", "-", -1)
	host := fmt.Sprintf("%s.%s.%s", s.tokenCfg.ServiceName, hyphenDomain, s.cfg.DNSDomain)
	commonName := fmt.Sprintf("%s.%s", s.tokenCfg.AthenzDomain, s.tokenCfg.ServiceName)

	subj := pkix.Name{
		CommonName:         commonName,
		OrganizationalUnit: []string{s.cfg.Subject.OrganizationalUnit},
		Organization:       []string{s.cfg.Subject.Organization},
		Country:            []string{s.cfg.Subject.Country},
	}

	csrData, err := generateCSR(pkSigner, subj, host, "", "")
	if err != nil {
		return nil, err
	}

	// if we're given a certificate then we'll use that otherwise
	// we're going to generate a ntoken for our request unless
	// we're using copper argos which only uses tls and the attestation
	// data contains the authentication details

	client, err := s.ntokenClient(
		s.cfg.AthenzURL,
		s.tokenCfg.AthenzDomain,
		s.tokenCfg.ServiceName,
		s.tokenCfg.KeyVersion,
		s.cfg.AthenzRootCA,
		s.cfg.PrincipalAuthHeaderName,
		keyBytes,
	)
	if err != nil {
		return nil, err
	}

	// if we're given provider then we're going to use our
	// copper argos model to request the certificate
	expiryTime32 := int32(1)
	req := &zts.InstanceRefreshRequest{
		Csr:        csrData,
		KeyId:      s.tokenCfg.KeyVersion,
		ExpiryTime: &expiryTime32,
	}

	// request a tls certificate for this service
	identity, err := client.PostInstanceRefreshRequest(
		zts.CompoundName(s.tokenCfg.AthenzDomain),
		zts.SimpleName(s.tokenCfg.ServiceName),
		req,
	)
	if err != nil {
		return nil, err
	}

	certificate := identity.Certificate
	caCertificates := identity.CaCertBundle

	if s.cfg.IntermediateCert {
		return []byte(certificate + caCertificates), nil
	}

	return []byte(certificate), nil
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

func generateCSR(keySigner *signer, subj pkix.Name, host, ip, uri string) (string, error) {
	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: keySigner.algorithm,
	}
	if host != "" {
		template.DNSNames = []string{host}
	}
	if ip != "" {
		template.IPAddresses = []net.IP{net.ParseIP(ip)}
	}
	if uri != "" {
		uriptr, err := url.Parse(uri)
		if err == nil {
			if len(template.URIs) > 0 {
				template.URIs = append(template.URIs, uriptr)
			} else {
				template.URIs = []*url.URL{uriptr}
			}
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

func (s *svcCertService) ntokenClient(ztsURL, domain, service, keyID, caCertFile, hdr string, keyBytes []byte) (*zts.ZTSClient, error) {
	ntoken, err := s.token()
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	if caCertFile != "" {
		config := &tls.Config{}
		certPool := x509.NewCertPool()
		caCert, err := ioutil.ReadFile(caCertFile)
		if err != nil {
			return nil, err
		}
		certPool.AppendCertsFromPEM(caCert)
		config.RootCAs = certPool
		transport.TLSClientConfig = config
	}
	// use the ntoken to talk to Athenz
	client := zts.NewClient(ztsURL, transport)
	client.AddCredentials(hdr, ntoken)
	return &client, nil
}
