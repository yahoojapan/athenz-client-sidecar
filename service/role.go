package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/kpango/fastime"
	"github.com/kpango/gache"
	ntokend "github.com/kpango/ntokend"
	"github.com/pkg/errors"
	"github.com/yahoojapan/athenz-client-sidecar/config"
	"golang.org/x/sync/singleflight"
)

// RoleService represent a interface to automatically refresh the role token, and a role token provider function pointer.
type RoleService interface {
	StartRoleUpdater(context.Context) RoleService
	GetRoleProvider() RoleProvider
}

// roleService represent the implementation of athenz RoleService
type roleService struct {
	cfg                   config.Role
	token                 ntokend.TokenProvider
	athenzURL             string
	athenzPrincipleHeader string
	domainRoleCache       gache.Gache
	group                 singleflight.Group
	expiry                time.Duration
	httpClient            *http.Client
}

type cacheData struct {
	token             *RoleToken
	domain            string
	role              string
	proxyForPrincipal string
	minExpiry         time.Duration
	maxExpiry         time.Duration
}

// RoleToken represent the basic information of the role token.
type RoleToken struct {
	Token      string `json:"token"`
	ExpiryTime int64  `json:"expiryTime"`
}

// RoleProvider represent a function pointer to get the role token.
type RoleProvider func(ctx context.Context, domain string, role string, proxyForPrincipal string, minExpiry time.Duration, maxExpiry time.Duration) (*RoleToken, error)

var (
	// ErrRoleTokenRequestFailed represent an error when failed to fetch the role token from RoleProvider.
	ErrRoleTokenRequestFailed = errors.New("Failed to fetch RoleToken")

	// defaultExpiry represent the default token expiry time.
	defaultExpiry = time.Minute * 120 // https://github.com/yahoo/athenz/blob/master/utils/zts-roletoken/zts-roletoken.go#L42
)

// NewRoleService returns a RoleService to update and get the role token from athenz.
func NewRoleService(cfg config.Role, token ntokend.TokenProvider) RoleService {
	dur, err := time.ParseDuration(cfg.TokenExpiry)
	if err != nil {
		dur = defaultExpiry
	}

	var cp *x509.CertPool
	var httpClient *http.Client
	if len(cfg.AthenzRootCA) != 0 {
		certPath := config.GetActualValue(cfg.AthenzRootCA)
		_, err := os.Stat(certPath)
		if !os.IsNotExist(err) {
			cp, err = NewX509CertPool(certPath)
			if err != nil {
				cp = nil
			}
		}
	}
	if cp != nil {
		httpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: cp,
				},
			},
		}
	} else {
		httpClient = http.DefaultClient
	}

	return &roleService{
		cfg:                   cfg,
		token:                 token,
		athenzURL:             cfg.AthenzURL,
		athenzPrincipleHeader: cfg.PrincipalAuthHeaderName,
		domainRoleCache:       gache.New(),
		expiry:                dur,
		httpClient:            httpClient,
	}
}

// StartRoleUpdater returns RoleService.
// This function will setup a expiry hook to role token caches, and refresh the role token when it needs.
func (r *roleService) StartRoleUpdater(ctx context.Context) RoleService {
	r.domainRoleCache.EnableExpiredHook().SetExpiredHook(r.handleExpiredHook).StartExpired(ctx, r.expiry/5)
	return r
}

// GetRoleProvider returns a function pointer to get the role token.
func (r *roleService) GetRoleProvider() RoleProvider {
	return r.getRoleToken
}

// getRoleToken returns RoleToken struct or error.
// This function will return the role token stored inside the cache, or fetch the role token from athenz when corresponding role token cannot be found in the cache.
func (r *roleService) getRoleToken(ctx context.Context, domain, role, proxyForPrincipal string, minExpiry, maxExpiry time.Duration) (*RoleToken, error) {
	tok, ok := r.getCache(domain, role, proxyForPrincipal)
	if !ok {
		return r.updateRoleToken(ctx, domain, role, proxyForPrincipal, minExpiry, maxExpiry)
	}
	return tok, nil
}

// handleExpiredHook is a handler function for gache expired hook
func (r *roleService) handleExpiredHook(fctx context.Context, key string) {
	domain, role := decode(key)
	r.updateRoleToken(fctx, domain, role, "", r.expiry, r.expiry)
}

// updateRoleToken returns RoleToken struct or error.
// This function ask athenz to generate role token and return, or return any error when generating the role token.
func (r *roleService) updateRoleToken(ctx context.Context, domain, role, proxyForPrincipal string, minExpiry, maxExpiry time.Duration) (*RoleToken, error) {

	tok, err, _ := r.group.Do(encode(domain, role), func() (interface{}, error) {
		// get the role token
		tok, err := r.token()
		if err != nil {
			return nil, err
		}

		// concat URL string and url parameters
		u := getRoleTokenAthenzURL(r.athenzURL, domain, role, minExpiry, maxExpiry, proxyForPrincipal)

		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}

		req.Header.Set(r.athenzPrincipleHeader, tok)

		// send http request
		res, err := r.httpClient.Do(req.WithContext(ctx))

		if err != nil {
			return nil, err
		}
		defer func() {
			if res != nil {
				io.Copy(ioutil.Discard, res.Body)
				if res.Body != nil {
					res.Body.Close()
				}
			}
		}()

		if res.StatusCode != http.StatusOK {
			return nil, ErrRoleTokenRequestFailed
		}

		// decode the token as a role token
		var data *RoleToken
		err = json.NewDecoder(res.Body).Decode(&data)
		if err != nil {
			return nil, err
		}

		// set the token into cache
		r.domainRoleCache.SetWithExpire(encode(domain, role), &cacheData{
			token:             data,
			domain:            domain,
			role:              role,
			proxyForPrincipal: proxyForPrincipal,
			minExpiry:         minExpiry,
			maxExpiry:         maxExpiry,
		}, time.Unix(data.ExpiryTime, 0).Sub(fastime.Now())-time.Minute)
		return data, nil
	})

	if err != nil {
		return nil, err
	}

	return tok.(*RoleToken), nil
}

func (r *roleService) getCache(domain, role, principal string) (*RoleToken, bool) {
	val, ok := r.domainRoleCache.Get(encode(domain, role))
	if !ok {
		return nil, false
	}
	return val.(*cacheData).token, ok
}

func encode(domain, role string) string {
	return fmt.Sprintf("%s-%s", domain, role)
}

func decode(key string) (string, string) {
	keys := strings.SplitN(key, "-", 3)
	if len(keys) < 2 {
		return key, ""
	}
	return keys[0], keys[1]
}

func getRoleTokenAthenzURL(athenzURL, domain, role string, minExpiry, maxExpiry time.Duration, proxyForPrincipal string) string {
	u := fmt.Sprintf("https://%s/domain/%s/token?role=%s", strings.TrimPrefix(strings.TrimPrefix(athenzURL, "https://"), "http://"), domain, url.QueryEscape(role))

	switch {
	case minExpiry > 0:
		u += fmt.Sprintf("&minExpiryTime=%d", minExpiry)
		fallthrough
	case maxExpiry > 0:
		u += fmt.Sprintf("&maxExpiryTime=%d", maxExpiry)
		fallthrough
	case proxyForPrincipal != "":
		u += fmt.Sprintf("&proxyForPrincipal=%s", proxyForPrincipal)
	}

	return u
}
