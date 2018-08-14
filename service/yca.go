package service

import (
	"ghe.corp.yahoo.co.jp/athenz/hcc-k8s/config"
	"git.corp.yahoo.co.jp/go/ycaclient"
)

type YCA interface {
	GetCertificate(appID string) (string, error)
	Close()
}

type yca struct {
	store *ycaclient.CertStore
}

func NewYCA(cfg config.YCA, prov TokenProvider) (YCA, error) {
	cert, err := ycaclient.Open(ycaclient.Config{
		Container: &ycaclient.ContainerConfig{
			Hostname:      cfg.Hostname,
			IPAddress:     cfg.IP,
			TokenProvider: prov,
		},
	})
	if err != nil {
		return nil, err
	}

	return &yca{
		store: cert,
	}, nil
}

//GetCertificate is get YCA cert
func (y *yca) GetCertificate(appID string) (string, error) {

	cert, err := y.store.Certificate(appID)
	if err != nil {
		return "", err
	}

	return cert, nil
}

//Close yca connetciton close
func (y *yca) Close() {
	ycaclient.Close()
}
