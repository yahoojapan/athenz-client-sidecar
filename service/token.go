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

// TokenService represent a interface for user to get the token, and automatically update the token
type TokenService interface {
	StartTokenUpdater(context.Context) TokenService
	GetToken() (string, error)
	GetTokenProvider() TokenProvider
}

type token struct {
	tokenFilePath   string
	token           *atomic.Value
	validateToken   bool
	tokenExpiration time.Duration
	refreshDuration time.Duration
	builder         zmssvctoken.TokenBuilder
}

type rawToken struct {
	domain     string
	name       string
	signature  string
	expiration time.Time
}

// TokenProvider represents a token provider function to get the role token
type TokenProvider func() (string, error)

var (
	// ErrTokenNotFound represent a error the the token is not found
	ErrTokenNotFound = errors.New("Error:\ttoken not found")
)

// NewTokenService return TokenService
// This function will initialize information the required to generate the token (for example, RefreshDuration, Expiration, PrivateKey, etc).
func NewTokenService(cfg config.Token, hcCfg config.HC) (TokenService, error) {
	dur, err := time.ParseDuration(cfg.RefreshDuration)
	if err != nil {
		return nil, fmt.Errorf("invalid token refresh duration %s, %v", cfg.RefreshDuration, err)
	}

	exp, err := time.ParseDuration(cfg.Expiration)
	if err != nil {
		return nil, fmt.Errorf("invalid token expiration %s, %v", cfg.Expiration, err)
	}

	keyData, err := ioutil.ReadFile(config.GetActualValue(cfg.PrivateKeyPath))
	if err != nil && keyData == nil {
		if cfg.NTokenPath == "" {
			return nil, fmt.Errorf("invalid token certificate %v", err)
		}
	}

	athenzDomain := config.GetActualValue(cfg.AthenzDomain)
	serviceName := config.GetActualValue(cfg.ServiceName)
	hostname := config.GetActualValue(hcCfg.Hostname)
	ipAddr := config.GetActualValue(hcCfg.IP)

	return (&token{
		token:           new(atomic.Value),
		tokenFilePath:   cfg.NTokenPath,
		validateToken:   cfg.ValidateToken,
		tokenExpiration: exp,
		refreshDuration: dur,
	}).createTokenBuilder(athenzDomain, serviceName, cfg.KeyVersion, keyData, hostname, ipAddr)
}

// StartTokenUpdater return TokenService
// This function will start a goroutine to update the token periodically, and store the token into memory
func (t *token) StartTokenUpdater(ctx context.Context) TokenService {
	go func() {
		var err error
		err = t.update()
		if err != nil {
			glg.Error(err)
		}

		ticker := time.NewTicker(t.refreshDuration)
		for {
			select {
			case <-ctx.Done():
				ticker.Stop()
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

// GetTokenProvider returns a function pointer to get the token.
func (t *token) GetTokenProvider() TokenProvider {
	return t.GetToken
}

// GetToken return a token string or error
// This function is thread-safe. This function will return the token stored in the atomic variable, or return the error when the token is not initialized or cannot be generated
func (t *token) GetToken() (string, error) {
	tok := t.token.Load()
	if tok == nil {
		return "", ErrTokenNotFound
	}
	return tok.(string), nil
}

// createTokenBuilder return a TokenService or error
// This function will initialize a token builder with athenz domain, service name, key version and the signature private key
// , and return a TokenService containing the token builder
func (t *token) createTokenBuilder(athenzDomain, serviceName, keyVersion string, keyData []byte, hostname, ipAddr string) (TokenService, error) {
	builder, err := zmssvctoken.NewTokenBuilder(
		athenzDomain,
		serviceName,
		keyData,
		keyVersion)

	if err != nil {
		return nil, fmt.Errorf("failed to create ZMS SVC Token Builder\nAthenzDomain:\t%s\nServiceName:\t%s\nKeyVersion:\t%s\nError: %v", athenzDomain, serviceName, keyVersion, err)
	}

	builder.SetHostname(hostname)
	builder.SetIPAddress(ipAddr)

	t.builder = builder

	return t, nil
}

// loadToken return a n-token string, or error
// This function return n-token, which is generated with the token builder. If the ntoken_path is set in the yaml (Copper Argos),
// this function will directly return the token file content.
// If ntoken_path is not set (k8s secret), the builder will read the private key from environment variable (private_key_env_name), and generate and sign a new token and return.
// This function can also validate the token generated or read. If validate_token flag is on, this function will verify the token first before this function return.
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

func (t *token) setToken(token string) {
	t.token.Store(token)
}

// newRawToken returns the rawToken pointer.
// This function parse the token string, and transform to rawToken struct.
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

// isValid returns error from validating the rawToken struct.
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
