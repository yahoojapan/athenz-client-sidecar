package verifier

import (
	"errors"

	"ghe.corp.yahoo.co.jp/yusukato/gocred/cookie"
)

const (
	//LastAuthMethodClaim is palyload key name
	LastAuthMethodClaim = "vcx/amr"
)

// LastAuthMethodVerifier cookie verifier
type LastAuthMethodVerifier struct {
	amrValues []string
}

func (l *LastAuthMethodVerifier) Verify(payload *cookie.Payload) error {
	amr := payload.Vcx.Amr
	for _, v1 := range l.amrValues {
		for _, v2 := range amr {
			if v1 == v2 {
				return nil
			}
		}
	}
	return errors.New("failed LastAuthMethodVerifier")
}
