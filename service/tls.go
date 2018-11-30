package service

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"

	"ghe.corp.yahoo.co.jp/athenz/athenz-tenant-sidecar/config"
	"github.com/pkg/errors"
)

var (
	// ErrTLSCertOrKeyNotFound represents an error that TLS cert or key is not found on the specified file path.
	ErrTLSCertOrKeyNotFound = errors.New("Cert/Key path not found")
)

// NewTLSConfig returns a *tls.Config struct or error.
// It reads TLS configuration and initializes *tls.Config struct.
// It initializes TLS configuration, for example the CA certificate and key to start TLS server.
// Server and CA Certificate, and private key will be read from files from file paths defined in environment variables.
func NewTLSConfig(cfg config.TLS) (*tls.Config, error) {
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

	cert := config.GetActualValue(cfg.CertKey)
	key := config.GetActualValue(cfg.KeyKey)
	ca := config.GetActualValue(cfg.CAKey)

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

// NewX509CertPool returns *x509.CertPool struct or error.
// The CertPool will read the certificate from the path, and append the content to the system certificate pool.
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
