/*
Copyright (C)  2018 Yahoo Japan Corporation Athenz team.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package service

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kpango/fastime"
	"github.com/kpango/gache"
	"github.com/kpango/glg"
	ntokend "github.com/kpango/ntokend"
	"github.com/pkg/errors"
	"github.com/yahoojapan/athenz-client-sidecar/config"
	"golang.org/x/sync/singleflight"
)

// AccessService represents an interface to automatically refresh the access token, and a access token provider function pointer.
type AccessService interface {
	StartAccessUpdater(context.Context) <-chan error
	RefreshAccessTokenCache(ctx context.Context) <-chan error
	GetAccessProvider() AccessProvider
}

// accessService represents the implementation of Athenz AccessService
type accessService struct {
	cfg                   config.Access
	token                 ntokend.TokenProvider
	athenzURL             string
	athenzPrincipleHeader string
	tokenCache            gache.Gache
	group                 singleflight.Group
	expiry                time.Duration
	httpClient            *http.Client

	refreshInterval  time.Duration
	errRetryMaxCount int
	errRetryInterval time.Duration
}

type accessCacheData struct {
	token             *AccessTokenResponse
	domain            string
	role              string
	proxyForPrincipal string
	expiresIn         int64
}

// AccessProvider represents a function pointer to retrieve the access token.
type AccessProvider func(ctx context.Context, domain string, role string, proxyForPrincipal string, expiresIn int64) (*AccessTokenResponse, error)

var (
	// ErrAccessTokenRequestFailed represents the error when failed to fetch the access token from Athenz server.
	ErrAccessTokenRequestFailed = errors.New("Failed to fetch AccessToken")
	scopeSeparator              = " "
)

// NewAccessService returns a AccessService to update and get the access token from Athenz.
func NewAccessService(cfg config.Access, token ntokend.TokenProvider) (AccessService, error) {
	var (
		err              error
		exp              = defaultTokenExpiry
		refreshInterval  = defaultRefreshInterval
		errRetryInterval = defaultErrRetryInterval
	)

	if cfg.TokenExpiry != "" {
		if exp, err = time.ParseDuration(cfg.TokenExpiry); err != nil {
			return nil, errors.Wrap(ErrInvalidSetting, "TokenExpiry: "+err.Error())
		}
	}
	if cfg.RefreshInterval != "" {
		if refreshInterval, err = time.ParseDuration(cfg.RefreshInterval); err != nil {
			return nil, errors.Wrap(ErrInvalidSetting, "RefreshInterval: "+err.Error())
		}
	}
	if cfg.ErrRetryInterval != "" {
		if errRetryInterval, err = time.ParseDuration(cfg.ErrRetryInterval); err != nil {
			return nil, errors.Wrap(ErrInvalidSetting, "ErrRetryInterval: "+err.Error())
		}
	}

	// if user set the expiry time and refresh duration > expiry time then return error
	if exp != 0 && refreshInterval > exp {
		return nil, errors.Wrap(ErrInvalidSetting, "refresh interval > token expiry time")
	}

	errRetryMaxCount := defaultErrRetryMaxCount
	if cfg.ErrRetryMaxCount > 0 {
		errRetryMaxCount = cfg.ErrRetryMaxCount
	} else if cfg.ErrRetryMaxCount != 0 {
		return nil, errors.Wrap(ErrInvalidSetting, "ErrRetryMaxCount < 0")
	}

	var cp *x509.CertPool
	var httpClient *http.Client
	if len(cfg.AthenzRootCA) > 0 {
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

	return &accessService{
		cfg:                   cfg,
		token:                 token,
		athenzURL:             cfg.AthenzURL,
		athenzPrincipleHeader: cfg.PrincipalAuthHeaderName,
		tokenCache:            gache.New(),
		expiry:                exp,
		httpClient:            httpClient,
		refreshInterval:       refreshInterval,
		errRetryMaxCount:      errRetryMaxCount,
		errRetryInterval:      errRetryInterval,
	}, nil
}

// AccessTokenResponse represents the AccessTokenResponse from postAccessTokenRequest.
type AccessTokenResponse struct {
	// AccessToken
	AccessToken string `json:"access_token"`

	// TokenType e.g. Bearer
	TokenType string `json:"token_type"`

	// Expiry in seconds
	ExpiresIn int64 `json:"expires_in,omitempty" rdl:"optional"`

	// Scope of the access token e.g. openid (delimited by space)
	Scope string `json:"scope,omitempty" rdl:"optional"`

	// RefreshToken
	RefreshToken string `json:"refresh_token,omitempty" rdl:"optional"`

	// IdToken
	IdToken string `json:"id_token,omitempty" rdl:"optional"`
}

// StartAccessUpdater returns AccessService.
// This function will periodically refresh the access token.
func (a *accessService) StartAccessUpdater(ctx context.Context) <-chan error {
	glg.Info("Starting access token updater")

	ech := make(chan error, 100)
	go func() {
		defer close(ech)

		ticker := time.NewTicker(a.refreshInterval)
		for {
			select {
			case <-ctx.Done():
				glg.Info("Stopping access token updater")
				ticker.Stop()
				ech <- ctx.Err()
				return
			case <-ticker.C:
				for err := range a.RefreshAccessTokenCache(ctx) {
					ech <- errors.Wrap(err, "error update access token")
				}
			}
		}
	}()

	a.tokenCache.StartExpired(ctx, expiryCheckInterval)
	a.tokenCache.EnableExpiredHook().SetExpiredHook(func(ctx context.Context, k string) {
		glg.Warnf("the following cache is expired, key: %v", k)
	})
	return ech
}

// GetAccessProvider returns a function pointer to get the accesss token.
func (a *accessService) GetAccessProvider() AccessProvider {
	return a.getAccessToken
}

// getAccessToken returns AccessTokenResponse struct or error.
// This function will return the access token stored inside the cache, or fetch the access token from Athenz when corresponding access token cannot be found in the cache.
func (a *accessService) getAccessToken(ctx context.Context, domain, role, proxyForPrincipal string, expiresIn int64) (*AccessTokenResponse, error) {
	tok, ok := a.getCache(domain, role, proxyForPrincipal)
	if !ok {
		return a.updateAccessToken(ctx, domain, role, proxyForPrincipal, expiresIn)
	}
	return tok, nil
}

// refreshAccessTokenCache returns the error channel when it is updated.
func (a *accessService) RefreshAccessTokenCache(ctx context.Context) <-chan error {
	glg.Info("refreshAccessTokenCache started")

	echan := make(chan error, a.tokenCache.Len()*(a.errRetryMaxCount+1))
	go func() {
		defer close(echan)

		a.tokenCache.Foreach(ctx, func(key string, val interface{}, exp int64) bool {
			domain, role, principal := decode(key)
			cd := val.(*accessCacheData)

			for err := range a.updateAccessTokenWithRetry(ctx, domain, role, principal, cd.expiresIn) {
				echan <- err
			}
			return true
		})
	}()

	return echan
}

func (a *accessService) updateAccessTokenWithRetry(ctx context.Context, domain, role, proxyForPrincipal string, expiresIn int64) <-chan error {
	glg.Debugf("updateAccessTokenWithRetry started, domain: %s, role: %s, proxyForPrincipal: %s, expiresIn: %d", domain, role, proxyForPrincipal, expiresIn)

	echan := make(chan error, a.errRetryMaxCount+1)
	go func() {
		defer close(echan)

		for i := 0; i <= a.errRetryMaxCount; i++ {
			if _, err := a.updateAccessToken(ctx, domain, role, proxyForPrincipal, expiresIn); err != nil {
				echan <- err
				time.Sleep(a.errRetryInterval)
			} else {
				glg.Debug("update success")
				break
			}
		}
	}()

	return echan
}

// updateAccessToken returns AccessTokenResponse struct or error.
// This function ask Athenz to generate access token and return, or return any error when generating the access token.
func (a *accessService) updateAccessToken(ctx context.Context, domain, role, proxyForPrincipal string, expiresIn int64) (*AccessTokenResponse, error) {
	key := encode(domain, role, proxyForPrincipal)
	expTimeDelta := fastime.Now().Add(time.Minute)

	at, err, _ := a.group.Do(key, func() (interface{}, error) {
		at, e := a.fetchAccessToken(ctx, domain, role, proxyForPrincipal, expiresIn)
		if e != nil {
			return nil, e
		}

		a.tokenCache.SetWithExpire(key, &accessCacheData{
			token:             at,
			domain:            domain,
			role:              role,
			proxyForPrincipal: proxyForPrincipal,
			expiresIn:         expiresIn,
		}, time.Unix(at.ExpiresIn, 0).Sub(expTimeDelta))

		glg.Debugf("token is cached, domain: %s, role: %s, proxyForPrincipal: %s, expiry time: %v", domain, role, proxyForPrincipal, at.ExpiresIn)
		return at, nil
	})
	if err != nil {
		return nil, err
	}

	return at.(*AccessTokenResponse), err
}

// fetchAccessToken fetches the access token from Athenz server, and returns the AccessTokenResponse or any error occurred.
func (a *accessService) fetchAccessToken(ctx context.Context, domain, role, proxyForPrincipal string, expiry int64) (*AccessTokenResponse, error) {
	glg.Debugf("get access token, domain: %s, role: %s, proxyForPrincipal: %s, expiry: %d", domain, role, proxyForPrincipal, expiry)

	// get the n-token
	cred, err := a.token()
	if err != nil {
		return nil, err
	}

	// create scope
	glg.Debugf("roleSeparater: %s, scopeSeparator: %s", roleSeparater, scopeSeparator)
	scope := createScope(domain, role)

	// prepare request object
	req, err := a.createPostAccessTokenRequest(scope, proxyForPrincipal, expiry, cred)
	if err != nil {
		glg.Debugf("fail to create request object, error: %s", err)
		return nil, err
	}
	glg.Debugf("request url: %v", req.URL)

	res, err := a.httpClient.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	// process response
	defer flushAndClose(res.Body)
	if res.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		if _, err := buf.ReadFrom(res.Body); err != nil {
			glg.Debugf("cannot read response body, err: %v", err)
		}
		glg.Debugf("error return from server, response:%+v, body: %v", res, buf.String())
		return nil, ErrAccessTokenRequestFailed
	}

	var atRes *AccessTokenResponse
	if err = json.NewDecoder(res.Body).Decode(&atRes); err != nil {
		return nil, err
	}

	return atRes, nil
}

func createScope(domain, role string) string {
	var scope string
	if role != "" {
		roles := strings.Split(role, roleSeparater)
		var scopes []string
		for _, r := range roles {
			scopes = append(scopes, domain+":role."+r)
		}
		scope = strings.Join(scopes, scopeSeparator)
	} else {
		scope = domain + ":domain"
	}
	return scope
}

func (a *accessService) getCache(domain, role, principal string) (*AccessTokenResponse, bool) {
	val, ok := a.tokenCache.Get(encode(domain, role, principal))
	if !ok {
		return nil, false
	}
	return val.(*accessCacheData).token, ok
}

// createGetAccessTokenRequest creates Athenz's postAccessTokenRequest.
func (a *accessService) createPostAccessTokenRequest(scope, proxyForPrincipal string, expiry int64, token string) (*http.Request, error) {
	u := fmt.Sprintf("https://%s/oauth2/token", strings.TrimPrefix(strings.TrimPrefix(a.athenzURL, "https://"), "http://"))

	// create URL query
	q := url.Values{}
	q.Add("grant_type", "client_credentials")
	q.Add("scope", scope)
	if proxyForPrincipal != "" {
		q.Add("proxy_for_principal", proxyForPrincipal)
	}
	if expiry <= 0 {
		expiry = int64(a.expiry / time.Second)
	}
	if expiry > 0 {
		q.Add("expires_in", strconv.FormatInt(expiry, 10))
	}

	// create request
	req, err := http.NewRequest(http.MethodPost, u, strings.NewReader(q.Encode()))
	if err != nil {
		glg.Debugf("fail to create request object, error: %s", err)
		return nil, err
	}

	// set authenication token
	req.Header.Set(a.athenzPrincipleHeader, token)

	return req, nil
}
