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
	"github.com/yahoo/athenz/clients/go/zts"
	"github.com/yahoo/athenz/libs/go/zmssvctoken"
	"github.com/yahoojapan/athenz-client-sidecar/config"
	"golang.org/x/sync/singleflight"
)

var (
	// defaultRefreshDuration represent the default svccert expiry time.
	defaultRefreshDuration = time.Hour * 24

	// ErrCertNotFound represent an error when failed to fetch the svccert from SvcCertProvider.
	ErrCertNotFound = errors.New("Failed to fetch service cert")
)

type signer struct {
	key       crypto.Signer
	algorithm x509.SignatureAlgorithm
}

type SvcCertService interface {
	StartSvcCertUpdater(context.Context) SvcCertService
	GetSvcCertProvider() SvcCertProvider
}

// svcCertService represent the implementation of athenz RoleService
type svcCertService struct {
	cfg                   config.Token
	athenzURL             string
	athenzRootCA          string
	dnsDomain             string
	athenzPrincipleHeader string
	intermediateCert      bool
	svcCert               *atomic.Value
	group                 singleflight.Group
	refreshDuration       time.Duration
	httpClient            *http.Client
}

// SvcCertProvider represent a function pointer to get the svccert.
type SvcCertProvider func() ([]byte, error)

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
		cfg:                   cfg.Token,
		svcCert:               &atomic.Value{},
		athenzURL:             cfg.ServiceCert.AthenzURL,
		dnsDomain:             cfg.ServiceCert.DNSDomain,
		athenzRootCA:          cfg.ServiceCert.AthenzRootCA,
		intermediateCert:      cfg.ServiceCert.IntermediateCert,
		athenzPrincipleHeader: cfg.ServiceCert.PrincipalAuthHeaderName,
		refreshDuration:       dur,
		httpClient:            httpClient,
	}
}

func (s *svcCertService) StartSvcCertUpdater(ctx context.Context) SvcCertService {
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

// GetSvcCertProvider returns a function pointer to get the svccert.
func (s *svcCertService) GetSvcCertProvider() SvcCertProvider {
	return s.getSvcCert
}

// getSvcCert return a token string or error
// This function is thread-safe. This function will return the svccert stored in the atomic variable,
// or return the error when the svccert is not initialized or cannot be generated
func (s *svcCertService) getSvcCert() ([]byte, error) {
	cert := s.svcCert.Load()
	if cert == nil {
		return nil, ErrCertNotFound
	}
	return cert.([]byte), nil
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
	// load private key
	keyBytes, err := ioutil.ReadFile(s.cfg.PrivateKeyPath)
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

	hyphenDomain := strings.Replace(s.cfg.AthenzDomain, ".", "-", -1)
	host := fmt.Sprintf("%s.%s.%s", s.cfg.ServiceName, hyphenDomain, s.dnsDomain)
	commonName := fmt.Sprintf("%s.%s", s.cfg.AthenzDomain, s.cfg.ServiceName)

	subjOU := "Athenz"
	subjO := "Oath Inc."
	subjC := "US"

	subj := pkix.Name{
		CommonName:         commonName,
		OrganizationalUnit: []string{subjOU},
		Organization:       []string{subjO},
		Country:            []string{subjC},
	}

	csrData, err := generateCSR(pkSigner, subj, host, "", "")
	if err != nil {
		return nil, err
	}

	// if we're given a certificate then we'll use that otherwise
	// we're going to generate a ntoken for our request unless
	// we're using copper argos which only uses tls and the attestation
	// data contains the authentication details

	client, err := ntokenClient(
		s.athenzURL,
		s.cfg.AthenzDomain,
		s.cfg.ServiceName,
		s.cfg.KeyVersion,
		s.athenzRootCA,
		s.athenzPrincipleHeader,
		keyBytes,
	)
	if err != nil {
		return nil, err
	}

	// if we're given provider then we're going to use our
	// copper argos model to request the certificate
	expiryTime32 := int32(0)
	req := &zts.InstanceRefreshRequest{
		Csr:        csrData,
		KeyId:      s.cfg.KeyVersion,
		ExpiryTime: &expiryTime32,
	}

	// request a tls certificate for this service
	identity, err := client.PostInstanceRefreshRequest(zts.CompoundName(s.cfg.AthenzDomain), zts.SimpleName(s.cfg.ServiceName), req)
	if err != nil {
		return nil, err
	}

	certificate := identity.Certificate
	caCertificates := identity.CaCertBundle

	if s.intermediateCert {
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

func getNToken(domain, service, keyID string, keyBytes []byte) (string, error) {

	if keyID == "" {
		return "", errors.New("Missing key-version for the specified private key")
	}

	// get token builder instance
	builder, err := zmssvctoken.NewTokenBuilder(domain, service, keyBytes, keyID)
	if err != nil {
		return "", err
	}

	// set optional attributes
	builder.SetExpiration(10 * time.Minute)

	// get a token instance that always gives you unexpired tokens values
	// safe for concurrent use
	tok := builder.Token()

	// get a token for use
	return tok.Value()
}

func ntokenClient(ztsURL, domain, service, keyID, caCertFile, hdr string, keyBytes []byte) (*zts.ZTSClient, error) {

	ntoken, err := getNToken(domain, service, keyID, keyBytes)
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
