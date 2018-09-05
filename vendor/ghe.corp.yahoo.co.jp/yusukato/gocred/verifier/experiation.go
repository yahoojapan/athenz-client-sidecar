package verifier

import (
	"errors"
	"time"

	"ghe.corp.yahoo.co.jp/yusukato/gocred/cookie"
)

const (
	//ExpirationClaim is palyload key name
	ExpirationClaim = "exp"
)

// ExpirationVerifier cookie verifier
type ExpirationVerifier struct {
	leeway int
}

func (a *ExpirationVerifier) Verify(payload *cookie.Payload) error {

	// Payload aatの値にsecを加え、現在時刻と比較
	if payload.Experiation.Add(time.Duration(a.leeway)).After(time.Now()) {
		return nil
	}

	return errors.New("failed ExpirationVerifier")
}
