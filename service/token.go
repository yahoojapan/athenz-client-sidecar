package service

import (
	"context"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"ghe.corp.yahoo.co.jp/athenz/athenz-tenant-sidecar/config"
	"github.com/kpango/glg"
	"github.com/pkg/errors"
	"github.com/yahoo/athenz/libs/go/zmssvctoken"
)

type TokenVerifier interface {
	StartTokenUpdater(context.Context) TokenVerifier
	GetTokenProvider() TokenProvider
	SetHostname(host string) error
	SetIPAddr(ip string) error
}

type token struct {
	tokenFilePath   string
	token           *atomic.Value
	validateToken   bool
	started         bool
	tokenExpiration time.Duration
	refreshDuration time.Duration
	builder         zmssvctoken.TokenBuilder
}

type TokenProvider func() (string, error)

var (
	ErrTokenNotFound = errors.New("Error:\ttoken not found")
)

func NewTokenService(cfg config.Token) (TokenVerifier, error) {
	dur, err := time.ParseDuration(cfg.RefreshDuration)
	if err != nil {
		return nil, fmt.Errorf("invalid token refresh duration %s, %v", cfg.RefreshDuration, err)
	}

	exp, err := time.ParseDuration(cfg.Expiration)
	if err != nil {
		return nil, fmt.Errorf("invalid token expiration %s, %v", cfg.Expiration, err)
	}

	keyData, err := ioutil.ReadFile(config.GetValue(cfg.PrivateKeyEnvName))
	if err != nil && keyData == nil {
		if cfg.NTokenPath == "" {
			return nil, fmt.Errorf("invalid token certificate %v", err)
		}
	}

	athenzDomain := config.GetValue(cfg.AthenzDomain)
	serviceName := config.GetValue(cfg.ServiceName)
	builder, err := zmssvctoken.NewTokenBuilder(
		athenzDomain,
		serviceName,
		keyData,
		cfg.KeyVersion)

	if err != nil {
		return nil, fmt.Errorf("failed to create ZMS SVC Token Builder\nAthenzDomain:\t%s\nServiceName:\t%s\nKeyVersion:\t%s\nError: %v", athenzDomain, serviceName, cfg.KeyVersion, err)
	}

	return &token{
		token:           new(atomic.Value),
		tokenFilePath:   cfg.NTokenPath,
		validateToken:   cfg.ValidateToken,
		tokenExpiration: exp,
		refreshDuration: dur,
		builder:         builder,
	}, nil
}

func (t *token) StartTokenUpdater(ctx context.Context) TokenVerifier {
	go func() {
		t.started = true
		var err error
		ticker := time.NewTicker(t.refreshDuration)
		for {
			select {
			case <-ctx.Done():
				ticker.Stop()
				t.started = false
				return
			case <-ticker.C:
				err = t.update()
				if err != nil {
					glg.Error(err)
				}
			}
		}
	}()
	return t
}

func (t *token) GetTokenProvider() TokenProvider {
	return t.getToken
}

func (t *token) getToken() (string, error) {
	tok := t.token.Load()
	if tok == nil {
		return "", ErrTokenNotFound
	}
	return tok.(string), nil
}

func (t *token) SetHostname(host string) error {
	t.builder.SetHostname(host)
	if t.started {
		return t.update()
	}
	return nil
}

func (t *token) SetIPAddr(ip string) error {
	t.builder.SetIPAddress(ip)
	if t.started {
		return t.update()
	}
	return nil
}

func (t *token) setToken(token string) {
	t.token.Store(token)
}

func (t *token) loadToken() (ntoken string, err error) {
	if t.tokenFilePath == "" {
		// k8s secret
		t.builder.SetExpiration(t.tokenExpiration)

		ntoken, err = t.builder.Token().Value()
		if err != nil {
			return "", err
		}

	} else {
		// Copper Argos
		var tok []byte
		tok, err = ioutil.ReadFile(t.tokenFilePath)
		if err != nil {
			return "", err
		}

		ntoken = strings.TrimRight(*(*string)(unsafe.Pointer(&tok)), "\r\n")
	}

	if t.validateToken {
		err = newRawToken(ntoken).isValid()
		if err != nil {
			return "", fmt.Errorf("invalid server identity token:\t%s", err.Error())
		}
	}
	return ntoken, nil
}

func (t *token) update() error {
	token, err := t.loadToken()
	if err != nil {
		return err
	}
	t.setToken(token)
	return nil
}

type rawToken struct {
	domain     string
	name       string
	signature  string
	expiration time.Time
}

func newRawToken(token string) *rawToken {
	t := new(rawToken)
	for _, field := range strings.Split(token, ";") {
		parts := strings.SplitN(field, "=", 2)
		if len(parts) != 2 {
			continue
		}
		switch parts[0] {
		case "d": // Domain
			t.domain = parts[1]
		case "n": // Name
			t.name = parts[1]
		case "s": // Signature
			t.signature = parts[1]
		case "e": // Expiration
			parsed, err := strconv.ParseInt(parts[1], 0, 64)
			if err != nil {
				t.expiration = time.Now().Add(time.Second * 30)
			} else {
				t.expiration = time.Unix(parsed, 0)
			}
		}
	}
	return t
}

func (r *rawToken) isValid() error {
	switch {
	case r.domain == "":
		return fmt.Errorf("no domain in token")
	case r.name == "":
		return fmt.Errorf("no name in token")
	case r.signature == "":
		return fmt.Errorf("no signature in token")
	case r.expiration.Before(time.Now()):
		return fmt.Errorf("token has expired")
	}
	return nil
}
