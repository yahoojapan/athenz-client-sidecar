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
	"github.com/kpango/glg"
	ntokend "github.com/kpango/ntokend"
	"github.com/pkg/errors"
	"github.com/yahoojapan/athenz-client-sidecar/config"
	"golang.org/x/sync/singleflight"
)

// RoleService represent a interface to automatically refresh the role token, and a role token provider function pointer.
type RoleService interface {
	StartRoleUpdater(context.Context) <-chan error
	RefreshRoleTokenCache(ctx context.Context) <-chan error
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

	refreshInterval  time.Duration
	errRetryMaxCount int
	errRetryInterval time.Duration
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

	// ErrInvalidSetting represent an error when the config file is invalid.
	ErrInvalidSetting = errors.New("Invalid config")

	// defaultExpiry represent the default token expiry time.
	defaultExpiry = time.Minute * 240 // https://github.com/yahoo/athenz/blob/master/utils/zts-roletoken/zts-roletoken.go#L42

	// defaultRefreshInterval represent the default token refresh interval.
	defaultRefreshInterval = time.Minute * 59

	// defaultErrRetryMaxCount represent the default maximum error retry count.
	defaultErrRetryMaxCount = 5

	// defaultErrRetryInterval represent the default error retry interval.
	defaultErrRetryInterval = time.Second * 5

	// separater of the internal cache key name.
	cacheKeySeparater = ";"
)

// NewRoleService returns a RoleService to update and get the role token from athenz.
func NewRoleService(cfg config.Role, token ntokend.TokenProvider) (RoleService, error) {
	dur, err := time.ParseDuration(cfg.TokenExpiry)
	if err != nil {
		dur = defaultExpiry
	}

	refreshInterval, err := time.ParseDuration(cfg.RefreshInterval)
	if err != nil {
		refreshInterval = defaultRefreshInterval
	}

	if refreshInterval > dur {
		return nil, errors.Wrap(ErrInvalidSetting, "refresh interval > token expiry time")
	}

	errRetryMaxCount := defaultErrRetryMaxCount
	if cfg.ErrRetryMaxCount > 0 {
		errRetryMaxCount = cfg.ErrRetryMaxCount
	}

	errRetryInterval, err := time.ParseDuration(cfg.ErrRetryInterval)
	if err != nil {
		errRetryInterval = defaultErrRetryInterval
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

	return &roleService{
		cfg:                   cfg,
		token:                 token,
		athenzURL:             cfg.AthenzURL,
		athenzPrincipleHeader: cfg.PrincipalAuthHeaderName,
		domainRoleCache:       gache.New(),
		expiry:                dur,
		httpClient:            httpClient,
		refreshInterval:       refreshInterval,
		errRetryMaxCount:      errRetryMaxCount,
		errRetryInterval:      errRetryInterval,
	}, nil
}

// StartRoleUpdater returns RoleService.
// This function will setup a expiry hook to role token caches, and refresh the role token when it needs.
func (r *roleService) StartRoleUpdater(ctx context.Context) <-chan error {
	glg.Info("Starting role token updater")

	ech := make(chan error, 100)
	go func() {
		defer close(ech)

		ticker := time.NewTicker(r.refreshInterval)
		for {
			select {
			case <-ctx.Done():
				glg.Info("Stopping role token updater")
				ticker.Stop()
				ech <- ctx.Err()
				return
			case <-ticker.C:
				for err := range r.RefreshRoleTokenCache(ctx) {
					ech <- errors.Wrap(err, "error update role token")
				}
			}
		}
	}()

	r.domainRoleCache.EnableExpiredHook().SetExpiredHook(r.handleExpiredHook).StartExpired(ctx, r.expiry/5)
	return ech
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

// refreshRoleTokenCache returns the error channel when it is updated.
func (r *roleService) RefreshRoleTokenCache(ctx context.Context) <-chan error {
	glg.Info("refreshRoleTokenCache started")

	echan := make(chan error)
	go func() {
		defer close(echan)

		r.domainRoleCache.Foreach(ctx, func(key string, val interface{}, exp int64) bool {
			domain, role, principal := decode(key)
			for err := range r.updateRoleTokenWithRetry(ctx, domain, role, principal, r.expiry, r.expiry) {
				echan <- err
			}
			return true
		})
	}()

	return echan
}

// handleExpiredHook is a handler function for gache expired hook
func (r *roleService) handleExpiredHook(ctx context.Context, key string) {
	glg.Debugf("handleExpiredHook(), key: %s", key)
	domain, role, principal := decode(key)
	glg.Debugf("decoded: %s, %s, %s", domain, role, principal)
	_, err := r.updateRoleToken(ctx, domain, role, principal, r.expiry, r.expiry)
	glg.Errorf("err: %v", err)
}

func (r *roleService) updateRoleTokenWithRetry(ctx context.Context, domain, role, proxyForPrincipal string, minExpiry, maxExpiry time.Duration) <-chan error {
	glg.Debugf("updateRoleTokenWithRetry started, domain: %s, role: %s, proxyForPrincipal: %s, minExpiry: %s, maxExpiry: %s", domain, role, proxyForPrincipal, minExpiry, maxExpiry)

	echan := make(chan error, r.errRetryMaxCount)
	go func() {
		defer close(echan)

		for i := 0; i < r.errRetryMaxCount; i++ {
			glg.Debugf("time: %v", i)
			if _, err := r.updateRoleToken(ctx, domain, role, proxyForPrincipal, minExpiry, maxExpiry); err != nil {
				echan <- err
				time.Sleep(r.errRetryInterval)
			} else {
				break
			}
		}
	}()

	return echan
}

// updateRoleToken returns RoleToken struct or error.
// This function ask athenz to generate role token and return, or return any error when generating the role token.
func (r *roleService) updateRoleToken(ctx context.Context, domain, role, proxyForPrincipal string, minExpiry, maxExpiry time.Duration) (*RoleToken, error) {
	key := encode(domain, role, proxyForPrincipal)

	rt, err, _ := r.group.Do(key, func() (interface{}, error) {
		rt, e := r.fetchRoleToken(ctx, domain, role, proxyForPrincipal, minExpiry, maxExpiry)
		if e != nil {
			return nil, e
		}

		r.domainRoleCache.SetWithExpire(key, &cacheData{
			token:             rt,
			domain:            domain,
			role:              role,
			proxyForPrincipal: proxyForPrincipal,
			minExpiry:         minExpiry,
			maxExpiry:         maxExpiry,
		}, time.Unix(rt.ExpiryTime, 0).Sub(fastime.Now()))

		return rt, nil
	})
	if err != nil {
		return nil, err
	}

	return rt.(*RoleToken), err
}

// fetchRoleToken fetch the role token from Athenz server, and return the decoded role token and any error if occurred.
func (r *roleService) fetchRoleToken(ctx context.Context, domain, role, proxyForPrincipal string, minExpiry, maxExpiry time.Duration) (*RoleToken, error) {
	glg.Debugf("get role token, domain: %s, role: %s, proxyForPrincipal: %s, minExpiry: %s, maxExpiry: %s", domain, role, proxyForPrincipal, minExpiry, maxExpiry)

	// get the n-token
	tok, err := r.token()
	if err != nil {
		return nil, err
	}

	// prepare request object
	u := r.getRoleTokenAthenzURL(domain, role, minExpiry, maxExpiry, proxyForPrincipal)
	glg.Debugf("url: %v", u)
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		glg.Debugf("fail to create request object, error: %s", err)
		return nil, err
	}
	req.Header.Set(r.athenzPrincipleHeader, tok)

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
		ioutil.ReadAll(res.Body)
		return nil, ErrRoleTokenRequestFailed
	}

	var data *RoleToken
	if err = json.NewDecoder(res.Body).Decode(&data); err != nil {
		return nil, err
	}

	return data, nil
}

func (r *roleService) getCache(domain, role, principal string) (*RoleToken, bool) {
	val, ok := r.domainRoleCache.Get(encode(domain, role, principal))
	if !ok {
		return nil, false
	}
	return val.(*cacheData).token, ok
}

func encode(domain, role, principal string) string {
	s := []string{domain, role, principal}
	if principal == "" {
		return strings.Join(s[:2], cacheKeySeparater)
	}
	return strings.Join(s, cacheKeySeparater)
}

func decode(key string) (string, string, string) {
	keys := strings.SplitN(key, cacheKeySeparater, 3)
	res := []string{"", "", ""}
	for i, v := range keys {
		res[i] = v
	}
	return res[0], res[1], res[2]
}

func (r *roleService) getRoleTokenAthenzURL(domain, role string, minExpiry, maxExpiry time.Duration, proxyForPrincipal string) string {
	u := fmt.Sprintf("https://%s/domain/%s/token?role=%s", strings.TrimPrefix(strings.TrimPrefix(r.athenzURL, "https://"), "http://"), domain, url.QueryEscape(role))

	minExp := r.expiry
	if minExpiry > 0 {
		minExp = minExpiry
	}
	u += fmt.Sprintf("&minExpiryTime=%d", minExp/time.Second)

	maxExp := r.expiry
	if maxExpiry > 0 {
		maxExp = maxExpiry
	}
	u += fmt.Sprintf("&maxExpiryTime=%d", maxExp/time.Second)

	if proxyForPrincipal != "" {
		u += fmt.Sprintf("&proxyForPrincipal=%s", proxyForPrincipal)
	}

	return u
}
