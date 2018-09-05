package cookie

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

type NCookie interface {
	isValid(t TCookie) error
	GetPayload() *Payload
}

type nCookie struct {
	Header  *Header
	Payload *Payload
	Token   string
}

type Header struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Typ       string `json:"typ"`
}

type Payload struct {
	YID            string `json:"sub"`
	GUID           string `json:"guid"`
	Issuer         string `json:"iss"`
	Th             string `json:"th"`
	Iat            int    `json:"iat"`
	ExperiationRaw int64  `json:"exp"`
	Experiation    time.Time
	JWTID          string `json:"jti"`
	Audience       string `json:"aud"`
	Lcx            struct {
		Aat int      `json:"aat"`
		Amr []string `json:"amr"`
	} `json:"lcx"`
	Vcx struct {
		Aat int      `json:"aat"`
		Amr []string `json:"amr"`
	} `json:"vcx"`
	Hist []string `json:"hist"`
}

const (
	ncookie = "_n"
)

var (
	ErrInvalidNCookie    = errors.New("Invalid NCookie")
	ErrKeyIDNotFound     = errors.New("KeyID not found")
	ErrNoSubjectINCookie = errors.New("no subject in this cookie")
	ErrNoIssuerINCookie  = errors.New("no issuer in this cookie")
)

func NewNCookie(NCookieRaw string) (NCookie, error) {
	var err error
	//JWTをパースしてデコードpayloadオブジェクトを取得
	ncSlice := strings.Split(NCookieRaw, ".")
	if len(ncSlice) < 2 {
		return nil, ErrInvalidNCookie
	}

	nc := &nCookie{
		Header:  new(Header),
		Payload: new(Payload),
		Token:   NCookieRaw,
	}

	parse := func(cookie string, i interface{}) error {
		// RawStdEncoding omits padding
		encoded, err := base64.RawStdEncoding.
			DecodeString(strings.NewReplacer("-", "+", "_", "/").Replace(cookie))

		if err != nil {
			return err
		}

		return json.NewDecoder(bytes.NewBuffer(encoded)).Decode(&i)
	}

	err = parse(ncSlice[0], &nc.Header)
	if err != nil {
		return nil, err
	}

	err = parse(ncSlice[1], &nc.Payload)
	if err != nil {
		return nil, err
	}
	nc.Payload.Experiation = time.Unix(nc.Payload.ExperiationRaw, 0)

	return nc, nil
}

func (n *nCookie) isValid(t TCookie) error {
	keyData, ok := t.Get(n.Header.KeyID)
	if !ok {
		return ErrKeyIDNotFound
	}

	token, err := jwt.Parse(n.Token, func(token *jwt.Token) (interface{}, error) {
		if n.Header.Algorithm != jwt.SigningMethodRS256.Alg() {
			return false, errors.New("Unexpected signing method: " + n.Header.Algorithm)
		}
		return jwt.ParseRSAPublicKeyFromPEM([]byte(keyData))
	})

	if err != nil {
		return err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return errors.New("Claims type is not jwt.MapClaims")
	}

	//Payload check
	err = n.Payload.Check(claims)
	if err != nil {
		return err
	}

	t.VerifyAll(func(_ string, v Verifier) bool {
		if v != nil {
			err = v.Verify(n.Payload)
			if err != nil {
				return false
			}
		}
		return true
	})

	return err
}

func (n *nCookie) GetPayload() *Payload {
	return n.Payload
}

//Check is JWT Payload alidation
func (p *Payload) Check(claims jwt.MapClaims) error {
	switch {
	case claims["sub"] == "":
		return ErrNoSubjectINCookie
	case claims["iss"] == "":
		return ErrNoIssuerINCookie
	case claims["iat"] == "":
		return errors.New("no issued-at in this cookie")
	case claims["exp"] == "":
		return errors.New("no expiration in this cookie")
	case claims["jti"] == "":
		return errors.New("no JWT-Token-ID in this cookie")
	case claims["th"] == "":
		return errors.New("no th in this cookie")
	}
	return nil
}
