package verifier

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"

	"ghe.corp.yahoo.co.jp/yusukato/gocred/cookie"
)

const (
	//CookieSyncClaim is palyload key name
	CookieSyncClaim = "th"
)

// CookieSyncVerifier cookie verifier
type cookieSyncVerifier struct {
	cookie string
}

func NewCookieSync(tcookie string) *cookieSyncVerifier {
	return &cookieSyncVerifier{
		cookie: tcookie,
	}
}

func (c *cookieSyncVerifier) Verify(payload *cookie.Payload) error {
	t := sha256.Sum256([]byte(c.cookie))
	t1 := base64.StdEncoding.EncodeToString(t[0:16])
	t2 := strings.Replace(t1, "+", "-", -1)
	t3 := strings.Replace(t2, "/", "_", -1)
	th := strings.TrimRight(t3, "=")

	if th != payload.Th {
		return errors.New("failed CookieSyncVerifier")
	}

	return nil
}
