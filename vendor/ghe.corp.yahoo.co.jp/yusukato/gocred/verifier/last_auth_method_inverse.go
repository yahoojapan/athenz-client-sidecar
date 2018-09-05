package verifier

import (
	"errors"

	"ghe.corp.yahoo.co.jp/yusukato/gocred/cookie"
)

const (
	//LastAuthMethodInverseClaim is palyload key name
	LastAuthMethodInverseClaim = "vcx/amr"
)

// LastAuthMethodInverseVerifier cookie verifier
type LastAuthMethodInverseVerifier struct {
	amrValues []string
}

func (l *LastAuthMethodInverseVerifier) Verify(payload *cookie.Payload) error {
	amr := payload.Vcx.Amr
	for _, v1 := range l.amrValues {
		for _, v2 := range amr {
			if v1 == v2 {
				return errors.New("failed LastAuthMethodInverseVerifier")
			}
		}
	}
	return nil
}
