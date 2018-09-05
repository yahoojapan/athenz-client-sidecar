package verifier

import (
	"errors"
	"time"

	"ghe.corp.yahoo.co.jp/yusukato/gocred/cookie"
)

const (
	//LastAuthTimeClaim is palyload key name
	LastAuthTimeClaim = "vcx/aat"
)

// LastAuthTimeVerifier cookie verifier
type LastAuthTimeVerifier struct {
	sec int
}

func (a *LastAuthTimeVerifier) Verify(payload *cookie.Payload) error {

	tm := time.Unix(int64(payload.Vcx.Aat), 0)

	// Payload aatの値にsecを加え、現在時刻と比較
	if tm.Add(time.Duration(a.sec)).After(time.Now()) {
		return nil
	}

	return errors.New("failed LastAuthTimeVerifier")
}
