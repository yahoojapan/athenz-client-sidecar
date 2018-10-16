package service

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"os"

	"ghe.corp.yahoo.co.jp/athenz/athenz-tenant-sidecar/config"
	"github.com/pkg/errors"
)

var (
	ErrTLSCertOrKeyNotFound = errors.New("Cert/Key path not found")
)

func NewTLSConfig(cfg config.TLS) (*tls.Config, error) {
	cert := os.Getenv(cfg.CertKey)
	key := os.Getenv(cfg.KeyKey)
	ca := os.Getenv(cfg.CAKey)

	t := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.CurveP521,
			tls.CurveP384,
			tls.CurveP256,
			tls.X25519,
		},
		SessionTicketsDisabled: true,
		ClientAuth:             tls.NoClientCert,
	}

	if cert == "" || key == "" {
		return nil, ErrTLSCertOrKeyNotFound
	}

	crt, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return nil, err
	}
	t.Certificates = make([]tls.Certificate, 1)
	t.Certificates[0] = crt

	if ca != "" {
		pool, err := NewX509CertPool(ca)
		if err != nil {
			return nil, err
		}
		t.ClientCAs = pool
		t.ClientAuth = tls.RequireAndVerifyClientCert
	}

	t.BuildNameToCertificate()
	return t, nil
}

func NewX509CertPool(path string) (*x509.CertPool, error) {
	var pool *x509.CertPool
	c, err := ioutil.ReadFile(path)
	if err == nil && c != nil {
		pool, err = x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(c) {
			err = errors.New("Certification Failed")
		}
	}
	return pool, err
}
