package gocred

import (
	"ghe.corp.yahoo.co.jp/yusukato/gocred/cookie"
	"ghe.corp.yahoo.co.jp/yusukato/gocred/verifier"
)

type Cred interface {
	GetCredential() *cookie.Payload
	GUID() string
}

type cred struct {
	nCookie cookie.NCookie
	tCookie cookie.TCookie
}

func New(ncookie, tcookie, keyID, keyData string) (Cred, error) {

	nc, err := cookie.NewNCookie(ncookie)
	if err != nil {
		return nil, err
	}
	tc := cookie.NewTCookie(tcookie, keyID, keyData)

	tc.AddVerifier(verifier.CookieSyncClaim, verifier.NewCookieSync(tcookie))
	tc.AddVerifier(verifier.AudienceClaim, verifier.NewAudience(""))

	return &cred{
		nCookie: nc,
		tCookie: tc,
	}, nil
}

func (c *cred) GetCredential() *cookie.Payload {
	return c.nCookie.GetPayload()
}

func (c *cred) AddVerifier(key string, v cookie.Verifier) {
	c.tCookie.AddVerifier(key, v)
}

func (c *cred) GUID() string {
	return c.nCookie.GetPayload().GUID
}
