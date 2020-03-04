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
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"sort"
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

// RoleService represent an interface to automatically refresh the role token, and a role token provider function pointer.
type RoleService interface {
	StartRoleUpdater(context.Context) <-chan error
	RefreshRoleTokenCache(ctx context.Context) <-chan error
	GetRoleProvider() RoleProvider
}

// roleService represent the implementation of Athenz RoleService
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
	minExpiry         int64
	maxExpiry         int64
}

// RoleToken represent the basic information of the role token.
type RoleToken struct {
	Token      string `json:"token"`
	ExpiryTime int64  `json:"expiryTime"`
}

// RoleProvider represent a function pointer to get the role token.
type RoleProvider func(ctx context.Context, domain string, role string, proxyForPrincipal string, minExpiry int64, maxExpiry int64) (*RoleToken, error)

var (
	// ErrRoleTokenRequestFailed represent an error when failed to fetch the role token from RoleProvider.
	ErrRoleTokenRequestFailed = errors.New("Failed to fetch RoleToken")

	// ErrInvalidSetting represent an error when the config file is invalid.
	ErrInvalidSetting = errors.New("Invalid config")
)

const (
	// defaultTokenExpiry represents the default role token expiration. (0 implies unspecified.)
	defaultTokenExpiry = time.Duration(0)

	// defaultRefreshInterval represents the default token refresh interval.
	defaultRefreshInterval = time.Minute * 30

	// defaultErrRetryMaxCount represents the default maximum error retry count.
	defaultErrRetryMaxCount = 5

	// defaultErrRetryInterval represents the default error retry interval.
	defaultErrRetryInterval = time.Second * 5

	// cacheKeySeparator is the separator of the internal cache key name.
	cacheKeySeparator = ";"

	// roleSeparator is the separator of the role names
	roleSeparator = ","

	// expiryCheckInterval represents default cache expiration check interval
	expiryCheckInterval = time.Minute
)

// NewRoleService returns a RoleService to update and get the role token from Athenz.
func NewRoleService(cfg config.Role, token ntokend.TokenProvider) (RoleService, error) {
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

	return &roleService{
		cfg:                   cfg,
		token:                 token,
		athenzURL:             cfg.AthenzURL,
		athenzPrincipleHeader: cfg.PrincipalAuthHeaderName,
		domainRoleCache:       gache.New(),
		expiry:                exp,
		httpClient:            httpClient,
		refreshInterval:       refreshInterval,
		errRetryMaxCount:      errRetryMaxCount,
		errRetryInterval:      errRetryInterval,
	}, nil
}

// StartRoleUpdater returns RoleService.
// This function will periodically refresh the role token.
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

	r.domainRoleCache.StartExpired(ctx, expiryCheckInterval)
	r.domainRoleCache.EnableExpiredHook().SetExpiredHook(func(ctx context.Context, k string) {
		glg.Warnf("the following cache is expired, key: %v", k)
	})
	return ech
}

// GetRoleProvider returns a function pointer to get the role token.
func (r *roleService) GetRoleProvider() RoleProvider {
	return r.getRoleToken
}

// getRoleToken returns RoleToken struct or error.
// This function will return the role token stored inside the cache, or fetch the role token from Athenz when corresponding role token cannot be found in the cache.
func (r *roleService) getRoleToken(ctx context.Context, domain, role, proxyForPrincipal string, minExpiry, maxExpiry int64) (*RoleToken, error) {
	tok, ok := r.getCache(domain, role, proxyForPrincipal)
	if !ok {
		return r.updateRoleToken(ctx, domain, role, proxyForPrincipal, minExpiry, maxExpiry)
	}
	return tok, nil
}

// RefreshRoleTokenCache returns the error channel when it is updated.
func (r *roleService) RefreshRoleTokenCache(ctx context.Context) <-chan error {
	glg.Info("RefreshRoleTokenCache started")

	echan := make(chan error, r.domainRoleCache.Len()*(r.errRetryMaxCount+1))
	go func() {
		defer close(echan)

		r.domainRoleCache.Foreach(ctx, func(key string, val interface{}, exp int64) bool {
			domain, role, principal := decode(key)
			cd := val.(*cacheData)

			for err := range r.updateRoleTokenWithRetry(ctx, domain, role, principal, cd.minExpiry, cd.maxExpiry) {
				echan <- err
			}
			return true
		})
	}()

	return echan
}

// updateRoleTokenWithRetry wraps updateRoleToken with retry logic.
func (r *roleService) updateRoleTokenWithRetry(ctx context.Context, domain, role, proxyForPrincipal string, minExpiry, maxExpiry int64) <-chan error {
	glg.Debugf("updateRoleTokenWithRetry started, domain: %s, role: %s, proxyForPrincipal: %s, minExpiry: %d, maxExpiry: %d", domain, role, proxyForPrincipal, minExpiry, maxExpiry)

	echan := make(chan error, r.errRetryMaxCount+1)
	go func() {
		defer close(echan)

		for i := 0; i <= r.errRetryMaxCount; i++ {
			if _, err := r.updateRoleToken(ctx, domain, role, proxyForPrincipal, minExpiry, maxExpiry); err != nil {
				echan <- err
				time.Sleep(r.errRetryInterval)
			} else {
				glg.Debug("update success")
				break
			}
		}
	}()

	return echan
}

// updateRoleToken returns RoleToken struct or error.
// This function ask Athenz to generate role token and return, or return any error when generating the role token.
func (r *roleService) updateRoleToken(ctx context.Context, domain, role, proxyForPrincipal string, minExpiry, maxExpiry int64) (*RoleToken, error) {
	key := encode(domain, role, proxyForPrincipal)
	expTimeDelta := fastime.Now().Add(time.Minute)

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
		}, time.Unix(rt.ExpiryTime, 0).Sub(expTimeDelta))

		glg.Debugf("token is cached, domain: %s, role: %s, proxyForPrincipal: %s, expiry time: %v", domain, role, proxyForPrincipal, rt.ExpiryTime)
		return rt, nil
	})
	if err != nil {
		return nil, err
	}

	return rt.(*RoleToken), err
}

// fetchRoleToken fetch the role token from Athenz server, and return the decoded role token and any error if occurred.
func (r *roleService) fetchRoleToken(ctx context.Context, domain, role, proxyForPrincipal string, minExpiry, maxExpiry int64) (*RoleToken, error) {
	glg.Debugf("get role token, domain: %s, role: %s, proxyForPrincipal: %s, minExpiry: %d, maxExpiry: %d", domain, role, proxyForPrincipal, minExpiry, maxExpiry)

	// get the n-token
	tok, err := r.token()
	if err != nil {
		return nil, err
	}

	// prepare request object
	req, err := r.createGetRoleTokenRequest(domain, role, minExpiry, maxExpiry, proxyForPrincipal, tok)
	if err != nil {
		glg.Debugf("fail to create request object, error: %s", err)
		return nil, err
	}
	glg.Debugf("request url: %v", req.URL)

	res, err := r.httpClient.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	defer flushAndClose(res.Body)
	if res.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		if _, err := buf.ReadFrom(res.Body); err != nil {
			glg.Debugf("cannot read response body, err: %v", err)
		}
		glg.Debugf("error return from server, response:%+v, body: %v", res, buf.String())
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

func (r *roleService) createGetRoleTokenRequest(domain, role string, minExpiry, maxExpiry int64, proxyForPrincipal, token string) (*http.Request, error) {
	u := fmt.Sprintf("https://%s/domain/%s/token", strings.TrimPrefix(strings.TrimPrefix(r.athenzURL, "https://"), "http://"), domain)

	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		glg.Debugf("fail to create request object, error: %s", err)
		return nil, err
	}

	getParamValue := func(dur int64) string {
		return strconv.FormatInt(dur, 10)
	}

	// create URL query
	q := req.URL.Query()

	if role != "" {
		q.Add("role", role)
	}

	minExp := int64(r.expiry / time.Second)
	if minExpiry > 0 {
		minExp = minExpiry
	}
	if minExp > 0 {
		q.Add("minExpiryTime", getParamValue(minExp))
	}

	// set max expiry only if user specifiy it
	if maxExpiry > 0 {
		q.Add("maxExpiryTime", getParamValue(maxExpiry))
	}

	if proxyForPrincipal != "" {
		q.Add("proxyForPrincipal", proxyForPrincipal)
	}

	req.URL.RawQuery = q.Encode()

	// set authenication token
	req.Header.Set(r.athenzPrincipleHeader, token)

	return req, nil
}

func encode(domain, role, principal string) string {
	roles := strings.Split(role, roleSeparator)
	sort.Strings(roles)

	s := []string{domain, strings.Join(roles, roleSeparator), principal}
	if principal == "" {
		return strings.Join(s[:2], cacheKeySeparator)
	}
	return strings.Join(s, cacheKeySeparator)
}

func decode(key string) (string, string, string) {
	keys := strings.SplitN(key, cacheKeySeparator, 3)
	res := make([]string, 3)
	copy(res, keys)
	return res[0], res[1], res[2]
}

// flushAndClose helps to flush and close a ReadCloser. Used for request body internal.
// Returns if there is any errors.
func flushAndClose(rc io.ReadCloser) error {
	if rc != nil {
		// flush
		_, err := io.Copy(ioutil.Discard, rc)
		if err != nil {
			return err
		}
		// close
		return rc.Close()
	}
	return nil
}
