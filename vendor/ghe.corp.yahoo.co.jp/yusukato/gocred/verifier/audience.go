package verifier

import (
	"errors"

	"ghe.corp.yahoo.co.jp/yusukato/gocred/cookie"
)

const (
	//AudienceClaim is palyload key name
	AudienceClaim = "aud"
)

// AudienceVerifier cookie verifier
type audienceVerifier struct {
	RequiredAud string
}

func NewAudience(aud string) *audienceVerifier {
	return &audienceVerifier{
		RequiredAud: aud,
	}
}

func (a *audienceVerifier) Verify(payload *cookie.Payload) error {

	if a.RequiredAud == "" {
		return nil
	}

	aud := payload.Audience
	if a.RequiredAud == "" {
		if aud == "" {
			return nil
		}
	}

	if aud == "" {
		return errors.New("error: Audience is empty")
	}

	return errors.New("failed AudienceVerifier")
}
