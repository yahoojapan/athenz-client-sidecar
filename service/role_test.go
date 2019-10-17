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
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/kpango/gache"
	"github.com/kpango/glg"
	ntokend "github.com/kpango/ntokend"
	"github.com/pkg/errors"
	"github.com/yahoojapan/athenz-client-sidecar/config"
	"golang.org/x/sync/singleflight"
)

func TestNewRoleService(t *testing.T) {
	type args struct {
		cfg   config.Role
		token ntokend.TokenProvider
	}
	type test struct {
		name      string
		args      args
		checkFunc func(got, want RoleService) error
		want      RoleService
		wantErr   error
	}
	tests := []test{
		func() test {
			args := args{
				cfg: config.Role{
					TokenExpiry:             "5s",
					AthenzURL:               "dummy",
					PrincipalAuthHeaderName: "dummyAuthHeader",
					RefreshInterval:         "1s",
				},
				token: func() (string, error) {
					return "", nil
				},
			}
			return test{
				name: "NewRoleService return correct",
				args: args,
				checkFunc: func(got, want RoleService) error {
					gotS := got.(*roleService)
					wantS := want.(*roleService)
					if !reflect.DeepEqual(gotS.cfg, wantS.cfg) ||
						reflect.ValueOf(gotS.token).Pointer() != reflect.ValueOf(wantS.token).Pointer() ||
						!reflect.DeepEqual(gotS.athenzURL, wantS.athenzURL) ||
						!reflect.DeepEqual(gotS.athenzPrincipleHeader, wantS.athenzPrincipleHeader) ||
						//!reflect.DeepEqual(gotS.domainRoleCache, wantS.domainRoleCache) ||
						!reflect.DeepEqual(gotS.expiry, wantS.expiry) {

						return fmt.Errorf("got: %+v, want: %+v", got, want)
					}
					return nil
				},
				want: &roleService{
					cfg:                   args.cfg,
					token:                 args.token,
					athenzURL:             args.cfg.AthenzURL,
					athenzPrincipleHeader: args.cfg.PrincipalAuthHeaderName,
					domainRoleCache:       gache.New(),
					expiry: func() time.Duration {
						dur, _ := time.ParseDuration(args.cfg.TokenExpiry)
						return dur
					}(),
				},
			}
		}(),
		func() test {
			args := args{
				cfg: config.Role{
					AthenzURL:               "dummy",
					PrincipalAuthHeaderName: "dummyAuthHeader",
				},
				token: func() (string, error) {
					return "", nil
				},
			}
			return test{
				name: "NewRoleService default values",
				args: args,
				checkFunc: func(got, want RoleService) error {
					gotS := got.(*roleService)
					wantS := want.(*roleService)
					if !reflect.DeepEqual(gotS.cfg, wantS.cfg) ||
						reflect.ValueOf(gotS.token).Pointer() != reflect.ValueOf(wantS.token).Pointer() ||
						!reflect.DeepEqual(gotS.athenzURL, wantS.athenzURL) ||
						!reflect.DeepEqual(gotS.athenzPrincipleHeader, wantS.athenzPrincipleHeader) ||
						//!reflect.DeepEqual(gotS.domainRoleCache, wantS.domainRoleCache) ||
						!reflect.DeepEqual(gotS.expiry, wantS.expiry) ||
						!reflect.DeepEqual(gotS.refreshInterval, wantS.refreshInterval) ||
						!reflect.DeepEqual(gotS.errRetryMaxCount, wantS.errRetryMaxCount) ||
						!reflect.DeepEqual(gotS.errRetryInterval, wantS.errRetryInterval) {

						return fmt.Errorf("got: %+v, want: %+v", got, want)
					}
					return nil
				},
				want: &roleService{
					cfg:                   args.cfg,
					token:                 args.token,
					athenzURL:             args.cfg.AthenzURL,
					athenzPrincipleHeader: args.cfg.PrincipalAuthHeaderName,
					domainRoleCache:       gache.New(),
					expiry:                defaultExpiry,
					errRetryInterval:      defaultErrRetryInterval,
					errRetryMaxCount:      defaultErrRetryMaxCount,
					refreshInterval:       defaultRefreshInterval,
				},
			}
		}(),
		func() test {
			args := args{
				cfg: config.Role{
					AthenzURL:               "dummy",
					PrincipalAuthHeaderName: "dummyAuthHeader",
					RefreshInterval:         "60s",
					TokenExpiry:             "1s",
				},
				token: func() (string, error) {
					return "", nil
				},
			}
			return test{
				name:    "NewRoleService return error when refresh interval > token expiry",
				args:    args,
				wantErr: errors.Wrap(ErrInvalidSetting, "refresh interval > token expiry time"),
			}
		}(),
		func() test {
			cnt := 10
			args := args{
				cfg: config.Role{
					AthenzURL:               "dummy",
					PrincipalAuthHeaderName: "dummyAuthHeader",
					ErrRetryMaxCount:        cnt,
				},
				token: func() (string, error) {
					return "", nil
				},
			}
			return test{
				name: "NewRoleService specific ErrRetryMaxCount",
				args: args,
				checkFunc: func(got, want RoleService) error {
					gotS := got.(*roleService)
					wantS := want.(*roleService)
					if !reflect.DeepEqual(gotS.cfg, wantS.cfg) ||
						reflect.ValueOf(gotS.token).Pointer() != reflect.ValueOf(wantS.token).Pointer() ||
						!reflect.DeepEqual(gotS.athenzURL, wantS.athenzURL) ||
						!reflect.DeepEqual(gotS.athenzPrincipleHeader, wantS.athenzPrincipleHeader) ||
						//!reflect.DeepEqual(gotS.domainRoleCache, wantS.domainRoleCache) ||
						!reflect.DeepEqual(gotS.expiry, wantS.expiry) ||
						!reflect.DeepEqual(gotS.refreshInterval, wantS.refreshInterval) ||
						!reflect.DeepEqual(gotS.errRetryMaxCount, wantS.errRetryMaxCount) ||
						!reflect.DeepEqual(gotS.errRetryInterval, wantS.errRetryInterval) {

						return fmt.Errorf("got: %+v, want: %+v", got, want)
					}
					return nil
				},
				want: &roleService{
					cfg:                   args.cfg,
					token:                 args.token,
					athenzURL:             args.cfg.AthenzURL,
					athenzPrincipleHeader: args.cfg.PrincipalAuthHeaderName,
					domainRoleCache:       gache.New(),
					expiry:                defaultExpiry,
					errRetryInterval:      defaultErrRetryInterval,
					errRetryMaxCount:      cnt,
					refreshInterval:       defaultRefreshInterval,
				},
			}
		}(),
		func() test {
			args := args{
				cfg: config.Role{
					AthenzURL:               "dummy",
					PrincipalAuthHeaderName: "dummyAuthHeader",
					AthenzRootCA:            "assets/dummyCa.pem",
				},
				token: func() (string, error) {
					return "", nil
				},
			}
			return test{
				name: "NewRoleService contains valid athenz rootCA",
				args: args,
				checkFunc: func(got, want RoleService) error {
					gotS := got.(*roleService)
					wantS := want.(*roleService)
					if !reflect.DeepEqual(gotS.cfg, wantS.cfg) ||
						reflect.ValueOf(gotS.token).Pointer() != reflect.ValueOf(wantS.token).Pointer() ||
						!reflect.DeepEqual(gotS.athenzURL, wantS.athenzURL) ||
						!reflect.DeepEqual(gotS.athenzPrincipleHeader, wantS.athenzPrincipleHeader) ||
						//!reflect.DeepEqual(gotS.domainRoleCache, wantS.domainRoleCache) ||
						!reflect.DeepEqual(gotS.expiry, wantS.expiry) ||
						!reflect.DeepEqual(gotS.refreshInterval, wantS.refreshInterval) ||
						!reflect.DeepEqual(gotS.errRetryMaxCount, wantS.errRetryMaxCount) ||
						!reflect.DeepEqual(gotS.errRetryInterval, wantS.errRetryInterval) {

						return fmt.Errorf("got: %+v, want: %+v", got, want)
					}
					cp, _ := NewX509CertPool(args.cfg.AthenzRootCA)
					t := gotS.httpClient.Transport.(*http.Transport)
					if !reflect.DeepEqual(t.TLSClientConfig.RootCAs, cp) {
						return fmt.Errorf("cert not match, got: %+v, want: %+v", t, cp)
					}

					return nil
				},
				want: &roleService{
					cfg:                   args.cfg,
					token:                 args.token,
					athenzURL:             args.cfg.AthenzURL,
					athenzPrincipleHeader: args.cfg.PrincipalAuthHeaderName,
					domainRoleCache:       gache.New(),
					expiry:                defaultExpiry,
					errRetryInterval:      defaultErrRetryInterval,
					errRetryMaxCount:      defaultErrRetryMaxCount,
					refreshInterval:       defaultRefreshInterval,
				},
			}
		}(),
		func() test {
			args := args{
				cfg: config.Role{
					AthenzURL:               "dummy",
					PrincipalAuthHeaderName: "dummyAuthHeader",
					AthenzRootCA:            "assets/invalid_dummyCa.pem",
				},
				token: func() (string, error) {
					return "", nil
				},
			}
			return test{
				name: "NewRoleService contains invalid athenz rootCA",
				args: args,
				checkFunc: func(got, want RoleService) error {
					gotS := got.(*roleService)
					wantS := want.(*roleService)
					if !reflect.DeepEqual(gotS.cfg, wantS.cfg) ||
						reflect.ValueOf(gotS.token).Pointer() != reflect.ValueOf(wantS.token).Pointer() ||
						!reflect.DeepEqual(gotS.athenzURL, wantS.athenzURL) ||
						!reflect.DeepEqual(gotS.athenzPrincipleHeader, wantS.athenzPrincipleHeader) ||
						//!reflect.DeepEqual(gotS.domainRoleCache, wantS.domainRoleCache) ||
						!reflect.DeepEqual(gotS.expiry, wantS.expiry) ||
						!reflect.DeepEqual(gotS.refreshInterval, wantS.refreshInterval) ||
						!reflect.DeepEqual(gotS.errRetryMaxCount, wantS.errRetryMaxCount) ||
						!reflect.DeepEqual(gotS.errRetryInterval, wantS.errRetryInterval) {

						return fmt.Errorf("got: %+v, want: %+v", got, want)
					}
					if gotS.httpClient != http.DefaultClient {
						return fmt.Errorf("http client not match, got: %+v, want: %+v", gotS.httpClient, http.DefaultClient)
					}

					return nil
				},
				want: &roleService{
					cfg:                   args.cfg,
					token:                 args.token,
					athenzURL:             args.cfg.AthenzURL,
					athenzPrincipleHeader: args.cfg.PrincipalAuthHeaderName,
					domainRoleCache:       gache.New(),
					expiry:                defaultExpiry,
					errRetryInterval:      defaultErrRetryInterval,
					errRetryMaxCount:      defaultErrRetryMaxCount,
					refreshInterval:       defaultRefreshInterval,
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewRoleService(tt.args.cfg, tt.args.token)

			if tt.wantErr == nil && err != nil {
				t.Errorf("failed to instantiate, err: %v", err)
				return
			} else if tt.wantErr != nil {
				if tt.wantErr.Error() != err.Error() {
					t.Errorf("error not the same, want: %v, got: %v", tt.wantErr, err)
				}
			}

			if tt.checkFunc != nil {
				if err := tt.checkFunc(got, tt.want); err != nil {
					t.Errorf("NewRoleService() err: %v", err)
				}
			}
		})
	}
}

func Test_roleService_StartRoleUpdater(t *testing.T) {
	type fields struct {
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
	type args struct {
		ctx context.Context
	}
	type test struct {
		name      string
		fields    fields
		args      args
		checkFunc func(RoleService, <-chan error) error
		afterFunc func()
		want      RoleService
	}
	tests := []test{
		func() test {
			dummyTok := "dummyToken"
			dummyExpTime := int64(1)
			dummyToken := fmt.Sprintf(`{"token":"%v", "expiryTime": %v}`, dummyTok, dummyExpTime)
			dummyRoleToken := &RoleToken{
				Token:      dummyToken,
				ExpiryTime: dummyExpTime,
			}

			// set the first token into cache
			domainRoleCache := gache.New()

			// create dummy server to mock the updateRoleToken
			dummyTok2 := "dummyToken2"
			dummyToken2 := fmt.Sprintf(`{"token":"%v", "expiryTime": %v}`, dummyTok2, dummyExpTime)

			var sampleHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, dummyToken2)
			})
			dummyServer := httptest.NewTLSServer(sampleHandler)

			domainRoleCache.SetWithExpire("dummyDomain;dummyRole", &cacheData{
				token: dummyRoleToken,
			}, time.Minute)

			return test{
				name: "StartRoleUpdater can update cache periodically",
				fields: fields{
					httpClient:            dummyServer.Client(),
					domainRoleCache:       domainRoleCache,
					expiry:                time.Second,
					athenzURL:             dummyServer.URL,
					athenzPrincipleHeader: "Athenz-Principal",
					token: func() (string, error) {
						return "dummy ntoken", nil
					},
					refreshInterval:  time.Second,
					errRetryMaxCount: 5,
					errRetryInterval: time.Second,
				},
				args: args{
					ctx: context.Background(),
				},
				checkFunc: func(rs RoleService, errs <-chan error) error {
					roleTok1, ok := domainRoleCache.Get("dummyDomain;dummyRole")
					if !ok {
						return fmt.Errorf("cannot get first role token")
					}

					time.Sleep(time.Second * 2)

					roleTok2, ok := domainRoleCache.Get("dummyDomain;dummyRole")
					if !ok {
						return fmt.Errorf("cannot get second role token")
					}

					if reflect.DeepEqual(roleTok1, roleTok2) {
						return fmt.Errorf("Token did not updated, role token 1: %v, role token 2: %v", roleTok1, roleTok2)
					}

					return nil
				},
				afterFunc: func() {
					dummyServer.Close()
					domainRoleCache.Stop()
					domainRoleCache.Clear()
				},
			}
		}(),
		func() test {
			dummyTok := "dummyToken"
			dummyExpTime := int64(99999999)
			dummyToken := fmt.Sprintf(`{"token":"%v", "expiryTime": %v}`, dummyTok, dummyExpTime)
			dummyRoleToken := &RoleToken{
				Token:      dummyToken,
				ExpiryTime: dummyExpTime,
			}

			domainRoleCache := gache.New()
			domainRoleCache.SetWithExpire("dummyDomain;dummyRole", &cacheData{
				token: dummyRoleToken,
			}, time.Minute)

			dummyTok2 := "dummyToken2"
			dummyToken2 := fmt.Sprintf(`{"token":"%v", "expiryTime": %v}`, dummyTok2, dummyExpTime)

			var sampleHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, dummyToken2)
			})
			dummyServer := httptest.NewTLSServer(sampleHandler)

			return test{
				name: "StartRoleUpdater can update cache using expired hook",
				fields: fields{
					httpClient:            dummyServer.Client(),
					domainRoleCache:       domainRoleCache,
					expiry:                time.Second * 2,
					athenzURL:             dummyServer.URL,
					athenzPrincipleHeader: "Athenz-Principal",
					token: func() (string, error) {
						return "dummy ntoken", nil
					},
					refreshInterval:  time.Hour,
					errRetryMaxCount: 5,
					errRetryInterval: time.Second,
				},
				args: args{
					ctx: context.Background(),
				},
				checkFunc: func(rs RoleService, errs <-chan error) error {
					roleTok1, ok := domainRoleCache.Get("dummyDomain;dummyRole")
					if !ok {
						return fmt.Errorf("cannot get first role token")
					}

					time.Sleep(time.Second * 1)

					roleTok2, ok := domainRoleCache.Get("dummyDomain;dummyRole")
					if !ok {
						return fmt.Errorf("cannot get second role token")
					}

					if !reflect.DeepEqual(roleTok1, roleTok2) {
						return fmt.Errorf("Token did not updated, role token 1: %v, role token 2: %v", roleTok1, roleTok2)
					}

					return nil
				},
				afterFunc: func() {
					dummyServer.Close()
				},
			}
		}(),
	}
	m := sync.Mutex{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &roleService{
				cfg:                   tt.fields.cfg,
				token:                 tt.fields.token,
				athenzURL:             tt.fields.athenzURL,
				athenzPrincipleHeader: tt.fields.athenzPrincipleHeader,
				domainRoleCache:       tt.fields.domainRoleCache,
				group:                 tt.fields.group,
				expiry:                tt.fields.expiry,
				httpClient:            tt.fields.httpClient,
				refreshInterval:       tt.fields.refreshInterval,
				errRetryMaxCount:      tt.fields.errRetryMaxCount,
				errRetryInterval:      tt.fields.errRetryInterval,
			}
			got := r.StartRoleUpdater(tt.args.ctx)
			if err := tt.checkFunc(r, got); err != nil {
				t.Errorf("roleService.StartRoleUpdater(), error: %v", err)
			}
			if tt.afterFunc != nil {
				m.Lock()
				tt.afterFunc()
				m.Unlock()
			}
		})
	}
}

func Test_roleService_GetRoleProvider(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "provider exactly return",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := NewRoleService(config.Role{}, nil)
			if got := r.GetRoleProvider(); got == nil {
				t.Error("provier is nil")
			}
		})
	}
}

func Test_roleService_getRoleToken(t *testing.T) {
	type fields struct {
		cfg                   config.Role
		token                 ntokend.TokenProvider
		athenzURL             string
		athenzPrincipleHeader string
		domainRoleCache       gache.Gache
		group                 singleflight.Group
		expiry                time.Duration
		httpClient            *http.Client
	}
	type args struct {
		ctx               context.Context
		domain            string
		role              string
		proxyForPrincipal string
		minExpiry         time.Duration
		maxExpiry         time.Duration
	}
	type test struct {
		name      string
		fields    fields
		args      args
		afterFunc func() error
		want      *RoleToken
		wantErr   error
	}
	tests := []test{
		func() test {
			dummyTok := "dummyToken"
			dummyExpTime := int64(999999999)
			dummyToken := fmt.Sprintf(`{"token":"%v", "expiryTime": %v}`, dummyTok, dummyExpTime)

			var sampleHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, dummyToken)
			})
			dummyServer := httptest.NewTLSServer(sampleHandler)

			return test{
				name: "getRoleToken returns correct",
				fields: fields{
					httpClient:      dummyServer.Client(),
					domainRoleCache: gache.New(),
					token: func() (string, error) {
						return dummyToken, nil
					},
					athenzURL:             dummyServer.URL,
					athenzPrincipleHeader: "Athenz-Principal",
				},
				args: args{
					ctx:               context.Background(),
					domain:            "dummyDomain",
					role:              "dummyRole",
					proxyForPrincipal: "dummyProxy",
					minExpiry:         time.Second,
					maxExpiry:         time.Second,
				},
				afterFunc: func() error {
					dummyServer.Close()
					return nil
				},
				want: &RoleToken{
					Token:      dummyTok,
					ExpiryTime: dummyExpTime,
				},
			}
		}(),
		func() test {
			var sampleHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			})
			dummyServer := httptest.NewTLSServer(sampleHandler)

			return test{
				name: "getRoleToken returns error",
				fields: fields{
					httpClient:      dummyServer.Client(),
					domainRoleCache: gache.New(),
					token: func() (string, error) {
						return "", nil
					},
					athenzURL:             dummyServer.URL,
					athenzPrincipleHeader: "Athenz-Principal",
				},
				args: args{
					ctx:               context.Background(),
					domain:            "dummyDomain",
					role:              "dummyRole",
					proxyForPrincipal: "dummyProxy",
					minExpiry:         time.Second,
					maxExpiry:         time.Second,
				},
				afterFunc: func() error {
					dummyServer.Close()
					return nil
				},
				wantErr: ErrRoleTokenRequestFailed,
			}
		}(),
		func() test {
			dummyTok := "dummyToken"
			dummyExpTime := int64(999999999)
			dummyRoleToken := &RoleToken{
				Token:      dummyTok,
				ExpiryTime: dummyExpTime,
			}
			gac := gache.New()
			gac.Set("dummyDomain;dummyRole;dummyProxy", &cacheData{
				token: dummyRoleToken,
			})

			return test{
				name: "getRoleToken return from cache",
				fields: fields{
					domainRoleCache: gac,
				},
				args: args{
					ctx:               context.Background(),
					domain:            "dummyDomain",
					role:              "dummyRole",
					proxyForPrincipal: "dummyProxy",
				},
				want: dummyRoleToken,
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.afterFunc != nil {
				defer tt.afterFunc()
			}

			r := &roleService{
				cfg:                   tt.fields.cfg,
				token:                 tt.fields.token,
				athenzURL:             tt.fields.athenzURL,
				athenzPrincipleHeader: tt.fields.athenzPrincipleHeader,
				domainRoleCache:       tt.fields.domainRoleCache,
				group:                 tt.fields.group,
				expiry:                tt.fields.expiry,
				httpClient:            tt.fields.httpClient,
			}
			got, err := r.getRoleToken(tt.args.ctx, tt.args.domain, tt.args.role, tt.args.proxyForPrincipal, tt.args.minExpiry, tt.args.maxExpiry)
			if tt.wantErr == nil && err != nil {
				t.Errorf("failed to instantiate, err: %v", err)
				return
			} else if tt.wantErr != nil {
				if tt.wantErr.Error() != err.Error() {
					t.Errorf("error not the same, want: %v, got: %v", tt.wantErr, err)
				}
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("roleService.getRoleToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_roleService_RefreshRoleTokenCache(t *testing.T) {
	type fields struct {
		cfg                   config.Role
		token                 ntokend.TokenProvider
		athenzURL             string
		athenzPrincipleHeader string
		domainRoleCache       gache.Gache
		group                 singleflight.Group
		expiry                time.Duration
		httpClient            *http.Client
		refreshInterval       time.Duration
		errRetryMaxCount      int
		errRetryInterval      time.Duration
	}
	type args struct {
		ctx context.Context
	}
	type test struct {
		name      string
		fields    fields
		args      args
		checkFunc func(<-chan error) error
		afterFunc func() error
	}
	tests := []test{
		func() test {
			var sampleHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				newToken := `{ "token": "newToken", "expiryTime":99999 }`
				fmt.Fprint(w, newToken)
			})
			dummyServer := httptest.NewTLSServer(sampleHandler)

			roleCache := gache.New()
			data := &cacheData{
				token:             nil,
				domain:            "dummyDomain",
				role:              "dummyRole",
				proxyForPrincipal: "",
				minExpiry:         time.Minute,
				maxExpiry:         time.Minute,
			}
			roleCache.SetWithExpire("dummyDomain;dummyRole", data, time.Minute)

			return test{
				name: "Refresh role token cache success",
				fields: fields{
					token: func() (string, error) {
						return "dummyNToken", nil
					},
					athenzURL:             dummyServer.URL,
					athenzPrincipleHeader: "dummy",
					domainRoleCache:       roleCache,
					expiry:                time.Minute,
					httpClient:            dummyServer.Client(),
					refreshInterval:       time.Second,
					errRetryMaxCount:      5,
					errRetryInterval:      time.Second,
				},
				args: args{
					ctx: context.Background(),
				},
				checkFunc: func(errChan <-chan error) error {
					for e := range errChan {
						return e
					}

					newCache, ok := roleCache.Get("dummyDomain;dummyRole")
					if !ok {
						return errors.New("cannot get new token")
					}

					tok := newCache.(*cacheData).token
					if tok == nil {
						return errors.New("updated token is nil")
					}
					if tok.Token != "newToken" {
						return errors.New("new token not updated")
					}

					return nil
				},
			}
		}(),
		func() test {
			var sampleHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				newToken := `{ "token": "newToken", "expiryTime":99999 }`
				fmt.Fprint(w, newToken)
			})
			dummyServer := httptest.NewTLSServer(sampleHandler)

			roleCache := gache.New()
			data := &cacheData{
				token:             nil,
				domain:            "dummyDomain",
				role:              "dummyRole",
				proxyForPrincipal: "",
				minExpiry:         time.Minute,
				maxExpiry:         time.Minute,
			}
			roleCache.SetWithExpire("dummyDomain;dummyRole", data, time.Minute)

			data1 := &cacheData{
				token:             nil,
				domain:            "dummyDomain1",
				role:              "dummyRole1",
				proxyForPrincipal: "",
				minExpiry:         time.Minute,
				maxExpiry:         time.Minute,
			}
			roleCache.SetWithExpire("dummyDomain1;dummyRole1", data1, time.Minute)

			return test{
				name: "Refresh multiple role token cache success",
				fields: fields{
					token: func() (string, error) {
						return "dummyNToken", nil
					},
					athenzURL:             dummyServer.URL,
					athenzPrincipleHeader: "dummy",
					domainRoleCache:       roleCache,
					expiry:                time.Minute,
					httpClient:            dummyServer.Client(),
					refreshInterval:       time.Second,
					errRetryMaxCount:      5,
					errRetryInterval:      time.Second,
				},
				args: args{
					ctx: context.Background(),
				},
				checkFunc: func(errChan <-chan error) error {
					for e := range errChan {
						return e
					}

					checkCache := func(k string) error {
						newCache, ok := roleCache.Get(k)
						if !ok {
							return errors.New("cannot get new token")
						}

						tok := newCache.(*cacheData).token
						if tok == nil {
							return errors.New("updated token is nil")
						}
						if tok.Token != "newToken" {
							return errors.New("new token not updated")
						}
						return nil
					}

					if err := checkCache("dummyDomain;dummyRole"); err != nil {
						return err
					}
					if err := checkCache("dummyDomain1;dummyRole1"); err != nil {
						return err
					}

					return nil
				},
			}
		}(),
		func() test {
			dummyTok := "newToken"
			i := 0
			var sampleHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if i < 3 {
					w.WriteHeader(http.StatusInternalServerError)
				} else {
					newToken := `{ "token": "newToken", "expiryTime":99999 }`
					fmt.Fprint(w, newToken)
				}
				i++
			})
			dummyServer := httptest.NewTLSServer(sampleHandler)

			domainRoleCache := gache.New()
			data := &cacheData{
				token:             nil,
				domain:            "dummyDomain",
				role:              "dummyRole",
				proxyForPrincipal: "dummyProxy",
				minExpiry:         time.Minute,
				maxExpiry:         time.Minute,
			}
			domainRoleCache.SetWithExpire("dummyDomain;dummyRole;dummyProxy", data, time.Minute)

			return test{
				name: "RefreshRoleTokenCache success with retry",
				fields: fields{
					httpClient:      dummyServer.Client(),
					domainRoleCache: domainRoleCache,
					token: func() (string, error) {
						return "dummyToken", nil
					},
					athenzURL:             dummyServer.URL,
					athenzPrincipleHeader: "Athenz-Principal",
					errRetryMaxCount:      10,
				},
				args: args{
					ctx: context.Background(),
				},
				checkFunc: func(echan <-chan error) error {
					errs := make([]error, 0, 3)
					for err := range echan {
						glg.Debug(err)
						errs = append(errs, err)
					}

					// check the length
					if len(errs) != 3 {
						return errors.Errorf("len(err) = %v, errors: %v", len(errs), errs)
					}

					// check errors
					for _, err := range errs {
						if err != ErrRoleTokenRequestFailed {
							return errors.Errorf("Unexpected error: %v", err)
						}
					}

					tok, ok := domainRoleCache.Get("dummyDomain;dummyRole;dummyProxy")
					if !ok {
						return errors.New("token does not set to the cache")
					}

					if tok.(*cacheData).token.Token != dummyTok {
						return errors.New("invalid token set on the cache")
					}

					return nil
				},
				afterFunc: func() error {
					dummyServer.Close()
					return nil
				},
			}
		}(),
		func() test {
			dummyTok := "newToken"
			var sampleHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			})
			dummyServer := httptest.NewTLSServer(sampleHandler)

			domainRoleCache := gache.New()
			data := &cacheData{
				token: &RoleToken{
					Token:      dummyTok,
					ExpiryTime: int64(99999999),
				},
				domain:            "dummyDomain",
				role:              "dummyRole",
				proxyForPrincipal: "dummyProxy",
				minExpiry:         time.Minute,
				maxExpiry:         time.Minute,
			}
			domainRoleCache.SetWithExpire("dummyDomain;dummyRole;dummyProxy", data, time.Minute)

			return test{
				name: "RefreshRoleTokenCache failed",
				fields: fields{
					httpClient:      dummyServer.Client(),
					domainRoleCache: domainRoleCache,
					token: func() (string, error) {
						return "dummyToken", nil
					},
					athenzURL:             dummyServer.URL,
					athenzPrincipleHeader: "Athenz-Principal",
					errRetryMaxCount:      10,
				},
				args: args{
					ctx: context.Background(),
				},
				checkFunc: func(echan <-chan error) error {
					errs := make([]error, 0, 10)
					for err := range echan {
						glg.Debug(err)
						errs = append(errs, err)
					}

					// check the length
					if len(errs) != 10 {
						return errors.Errorf("len(err) = %v, errors: %v", len(errs), errs)
					}

					// check errors
					for _, err := range errs {
						if err != ErrRoleTokenRequestFailed {
							return errors.Errorf("Unexpected error: %v", err)
						}
					}

					// the cache will not be deleted even the fetch is failed
					tok, ok := domainRoleCache.Get("dummyDomain;dummyRole;dummyProxy")
					if !ok {
						return errors.New("token does not set to the cache")
					}

					if tok.(*cacheData).token.Token != dummyTok {
						return errors.New("invalid token set on the cache")
					}

					return nil
				},
				afterFunc: func() error {
					dummyServer.Close()
					return nil
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.afterFunc != nil {
				defer tt.afterFunc()
			}
			r := &roleService{
				cfg:                   tt.fields.cfg,
				token:                 tt.fields.token,
				athenzURL:             tt.fields.athenzURL,
				athenzPrincipleHeader: tt.fields.athenzPrincipleHeader,
				domainRoleCache:       tt.fields.domainRoleCache,
				group:                 tt.fields.group,
				expiry:                tt.fields.expiry,
				httpClient:            tt.fields.httpClient,
				refreshInterval:       tt.fields.refreshInterval,
				errRetryMaxCount:      tt.fields.errRetryMaxCount,
				errRetryInterval:      tt.fields.errRetryInterval,
			}
			got := r.RefreshRoleTokenCache(tt.args.ctx)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("roleService.RefreshRoleTokenCache() error: %s", err)
			}
		})
	}
}

func Test_roleService_handleExpiredHook(t *testing.T) {
	type fields struct {
		cfg                   config.Role
		token                 ntokend.TokenProvider
		athenzURL             string
		athenzPrincipleHeader string
		domainRoleCache       gache.Gache
		group                 singleflight.Group
		expiry                time.Duration
		httpClient            *http.Client
	}
	type args struct {
		fctx context.Context
		key  string
	}
	type test struct {
		name   string
		fields fields
		args   args
	}
	tests := []test{
		func() test {
			dummyTok := "dummyToken"
			dummyExpTime := int64(999999999)
			dummyToken := fmt.Sprintf(`{"token":"%v", "expiryTime": %v}`, dummyTok, dummyExpTime)

			var sampleHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, dummyToken)
			})
			dummyServer := httptest.NewTLSServer(sampleHandler)

			return test{
				name: "handleExpiredHook can run",
				fields: fields{
					httpClient:      dummyServer.Client(),
					domainRoleCache: gache.New(),
					token: func() (string, error) {
						return "dummyToken", nil
					},
					athenzURL:             dummyServer.URL,
					athenzPrincipleHeader: "Athenz-Principal",
				},
				args: args{
					fctx: context.Background(),
					key:  "dummyDomain;dummyRole",
				},
			}

		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &roleService{
				cfg:                   tt.fields.cfg,
				token:                 tt.fields.token,
				athenzURL:             tt.fields.athenzURL,
				athenzPrincipleHeader: tt.fields.athenzPrincipleHeader,
				domainRoleCache:       tt.fields.domainRoleCache,
				group:                 tt.fields.group,
				expiry:                tt.fields.expiry,
				httpClient:            tt.fields.httpClient,
			}
			r.handleExpiredHook(tt.args.fctx, tt.args.key)
		})
	}
}

func Test_roleService_updateRoleTokenWithRetry(t *testing.T) {
	type fields struct {
		cfg                   config.Role
		token                 ntokend.TokenProvider
		athenzURL             string
		athenzPrincipleHeader string
		domainRoleCache       gache.Gache
		group                 singleflight.Group
		expiry                time.Duration
		httpClient            *http.Client
		refreshInterval       time.Duration
		errRetryMaxCount      int
		errRetryInterval      time.Duration
	}
	type args struct {
		ctx               context.Context
		domain            string
		role              string
		proxyForPrincipal string
		minExpiry         time.Duration
		maxExpiry         time.Duration
	}
	type test struct {
		name      string
		fields    fields
		args      args
		want      <-chan error
		checkFunc func(<-chan error) error
		afterFunc func() error
	}
	tests := []test{
		func() test {
			dummyTok := "dummyToken"
			dummyExpTime := int64(999999999)
			dummyToken := fmt.Sprintf(`{"token":"%v", "expiryTime": %v}`, dummyTok, dummyExpTime)

			var sampleHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, dummyToken)
			})
			dummyServer := httptest.NewTLSServer(sampleHandler)

			domainRoleCache := gache.New()

			return test{
				name: "updateRoleTokenWithRetry success",
				fields: fields{
					httpClient:      dummyServer.Client(),
					domainRoleCache: domainRoleCache,
					token: func() (string, error) {
						return dummyToken, nil
					},
					athenzURL:             dummyServer.URL,
					athenzPrincipleHeader: "Athenz-Principal",
					errRetryMaxCount:      10,
				},
				args: args{
					ctx:               context.Background(),
					domain:            "dummyDomain",
					role:              "dummyRole",
					proxyForPrincipal: "dummyProxy",
				},
				checkFunc: func(echan <-chan error) error {
					for err := range echan {
						return errors.Wrap(err, "Unexpected error occurred")
					}

					tok, ok := domainRoleCache.Get("dummyDomain;dummyRole;dummyProxy")
					if !ok {
						return errors.New("token donot set to the cache")
					}

					if tok.(*cacheData).token.Token != dummyTok {
						return errors.New("invalid token set on the cache")
					}

					return nil
				},
				afterFunc: func() error {
					dummyServer.Close()
					return nil
				},
			}
		}(),
		func() test {
			dummyTok := "dummyToken"
			dummyExpTime := int64(999999999)
			dummyToken := fmt.Sprintf(`{"token":"%v", "expiryTime": %v}`, dummyTok, dummyExpTime)

			i := 0
			var sampleHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if i < 3 {
					w.WriteHeader(http.StatusInternalServerError)
				} else {
					fmt.Fprintf(w, dummyToken)
				}
				i++
			})
			dummyServer := httptest.NewTLSServer(sampleHandler)

			domainRoleCache := gache.New()

			return test{
				name: "updateRoleTokenWithRetry success with retry",
				fields: fields{
					httpClient:      dummyServer.Client(),
					domainRoleCache: domainRoleCache,
					token: func() (string, error) {
						return dummyToken, nil
					},
					athenzURL:             dummyServer.URL,
					athenzPrincipleHeader: "Athenz-Principal",
					errRetryMaxCount:      10,
				},
				args: args{
					ctx:               context.Background(),
					domain:            "dummyDomain",
					role:              "dummyRole",
					proxyForPrincipal: "dummyProxy",
				},
				checkFunc: func(echan <-chan error) error {
					errs := make([]error, 0, 3)
					for err := range echan {
						glg.Debug(err)
						errs = append(errs, err)
					}

					// check the length
					if len(errs) != 3 {
						return errors.Errorf("len(err) = %v", len(errs))
					}

					// check errors
					for _, err := range errs {
						if err != ErrRoleTokenRequestFailed {
							return errors.Errorf("Unexpected error: %v", err)
						}
					}

					tok, ok := domainRoleCache.Get("dummyDomain;dummyRole;dummyProxy")
					if !ok {
						return errors.New("token donot set to the cache")
					}

					if tok.(*cacheData).token.Token != dummyTok {
						return errors.New("invalid token set on the cache")
					}

					return nil
				},
				afterFunc: func() error {
					dummyServer.Close()
					return nil
				},
			}
		}(),
		func() test {
			dummyToken := "tok"
			// create a dummy server that returns a dummy token
			var sampleHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			})
			dummyServer := httptest.NewTLSServer(sampleHandler)

			domainRoleCache := gache.New()

			return test{
				name: "updateRoleTokenWithRetry returns error",
				fields: fields{
					httpClient:      dummyServer.Client(),
					domainRoleCache: domainRoleCache,
					token: func() (string, error) {
						return dummyToken, nil
					},
					athenzURL:             dummyServer.URL,
					athenzPrincipleHeader: "Athenz-Principal",
					errRetryMaxCount:      10,
				},
				args: args{
					ctx:               context.Background(),
					domain:            "dummyDomain",
					role:              "dummyRole",
					proxyForPrincipal: "dummyProxy",
				},
				checkFunc: func(echan <-chan error) error {
					errs := make([]error, 0, 10)
					for err := range echan {
						glg.Debug(err)
						errs = append(errs, err)
					}

					// check the length
					if len(errs) != 10 {
						return errors.Errorf("len(err) = %v", len(errs))
					}

					// check errors
					for _, err := range errs {
						if err != ErrRoleTokenRequestFailed {
							return errors.Errorf("Unexpected error: %v", err)
						}
					}

					return nil
				},
				afterFunc: func() error {
					dummyServer.Close()
					return nil
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer tt.afterFunc()
			r := &roleService{
				cfg:                   tt.fields.cfg,
				token:                 tt.fields.token,
				athenzURL:             tt.fields.athenzURL,
				athenzPrincipleHeader: tt.fields.athenzPrincipleHeader,
				domainRoleCache:       tt.fields.domainRoleCache,
				group:                 tt.fields.group,
				expiry:                tt.fields.expiry,
				httpClient:            tt.fields.httpClient,
				refreshInterval:       tt.fields.refreshInterval,
				errRetryMaxCount:      tt.fields.errRetryMaxCount,
				errRetryInterval:      tt.fields.errRetryInterval,
			}
			got := r.updateRoleTokenWithRetry(tt.args.ctx, tt.args.domain, tt.args.role, tt.args.proxyForPrincipal, tt.args.minExpiry, tt.args.maxExpiry)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("roleService.updateRoleTokenWithRetry(). error: %v", err)
			}
		})
	}
}

func Test_roleService_updateRoleToken(t *testing.T) {
	type fields struct {
		cfg                   config.Role
		token                 ntokend.TokenProvider
		athenzURL             string
		athenzPrincipleHeader string
		domainRoleCache       gache.Gache
		group                 singleflight.Group
		expiry                time.Duration
		httpClient            *http.Client
	}
	type args struct {
		ctx               context.Context
		domain            string
		role              string
		proxyForPrincipal string
		minExpiry         time.Duration
		maxExpiry         time.Duration
	}
	type test struct {
		name       string
		fields     fields
		args       args
		beforeFunc func() error
		checkFunc  func(got, want *RoleToken) error
		afterFunc  func() error
		want       *RoleToken
		wantErr    error
	}
	tests := []test{
		func() test {
			dummyTok := "dummyToken"
			dummyExpTime := int64(999999999)
			dummyToken := fmt.Sprintf(`{"token":"%v", "expiryTime": %v}`, dummyTok, dummyExpTime)

			var sampleHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, dummyToken)
			})
			dummyServer := httptest.NewTLSServer(sampleHandler)

			return test{
				name: "updateRoleToken returns correct",
				fields: fields{
					httpClient:      dummyServer.Client(),
					domainRoleCache: gache.New(),
					token: func() (string, error) {
						return dummyToken, nil
					},
					athenzURL:             dummyServer.URL,
					athenzPrincipleHeader: "Athenz-Principal",
				},
				args: args{
					ctx:               context.Background(),
					domain:            "dummyDomain",
					role:              "dummyRole",
					proxyForPrincipal: "dummyProxy",
					minExpiry:         time.Second,
					maxExpiry:         time.Second,
				},
				afterFunc: func() error {
					dummyServer.Close()
					return nil
				},
				want: &RoleToken{
					Token:      dummyTok,
					ExpiryTime: dummyExpTime,
				},
			}
		}(),
		func() test {
			dummyErr := fmt.Errorf("Dummy error")
			return test{
				name: "updateRoleToken token returns error",
				fields: fields{
					httpClient:      nil,
					domainRoleCache: gache.New(),
					token: func() (string, error) {
						return "", dummyErr
					},
					athenzPrincipleHeader: "Athenz-Principal",
				},
				args: args{
					ctx:               context.Background(),
					domain:            "dummyDomain",
					role:              "dummyRole",
					proxyForPrincipal: "dummyProxy",
					minExpiry:         time.Second,
					maxExpiry:         time.Second,
				},
				wantErr: dummyErr,
			}
		}(),
		func() test {
			dummyTok := "dummyToken"
			dummyExpTime := int64(999999999)
			dummyToken := fmt.Sprintf(`{"token":"%v", "expiryTime": %v}`, dummyTok, dummyExpTime)

			var sampleHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, dummyToken)
			})
			dummyServer := httptest.NewTLSServer(sampleHandler)

			return test{
				name: "updateRoleToken new request returns error",
				fields: fields{
					httpClient:      dummyServer.Client(),
					domainRoleCache: gache.New(),
					token: func() (string, error) {
						return "", nil
					},
					athenzURL:             "127.0.0.1:9876",
					athenzPrincipleHeader: "Athenz-Principal",
				},
				args: args{
					ctx:               context.Background(),
					domain:            "dummyDomain",
					role:              "dummyRole",
					proxyForPrincipal: "dummyProxy",
					minExpiry:         time.Second,
					maxExpiry:         time.Second,
				},
				wantErr: fmt.Errorf("Get https://127.0.0.1:9876/domain/dummyDomain/token?role=dummyRole&minExpiryTime=1&maxExpiryTime=1&proxyForPrincipal=dummyProxy: dial tcp 127.0.0.1:9876: connect: connection refused"),
			}
		}(),
		func() test {
			dummyTok := "dummyToken"
			dummyExpTime := int64(999999999)
			dummyToken := fmt.Sprintf(`{"token":"%v", "expiryTime": %v}`, dummyTok, dummyExpTime)

			var sampleHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			})
			dummyServer := httptest.NewTLSServer(sampleHandler)

			return test{
				name: "updateRoleToken get token error",
				fields: fields{
					httpClient:      dummyServer.Client(),
					domainRoleCache: gache.New(),
					token: func() (string, error) {
						return dummyToken, nil
					},
					athenzURL:             dummyServer.URL,
					athenzPrincipleHeader: "Athenz-Principal",
				},
				args: args{
					ctx:               context.Background(),
					domain:            "dummyDomain",
					role:              "dummyRole",
					proxyForPrincipal: "dummyProxy",
					minExpiry:         time.Second,
					maxExpiry:         time.Second,
				},
				afterFunc: func() error {
					dummyServer.Close()
					return nil
				},
				wantErr: ErrRoleTokenRequestFailed,
			}
		}(),
		func() test {
			dummyToken := "dummyToken"

			var sampleHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, dummyToken)
			})
			dummyServer := httptest.NewTLSServer(sampleHandler)

			return test{
				name: "updateRoleToken decode token error",
				fields: fields{
					httpClient:      dummyServer.Client(),
					domainRoleCache: gache.New(),
					token: func() (string, error) {
						return dummyToken, nil
					},
					athenzURL:             dummyServer.URL,
					athenzPrincipleHeader: "Athenz-Principal",
				},
				args: args{
					ctx:               context.Background(),
					domain:            "dummyDomain",
					role:              "dummyRole",
					proxyForPrincipal: "dummyProxy",
					minExpiry:         time.Second,
					maxExpiry:         time.Second,
				},
				afterFunc: func() error {
					dummyServer.Close()
					return nil
				},
				wantErr: fmt.Errorf("invalid character 'd' looking for beginning of value"),
			}
		}(),
		func() test {
			dummyTok := "dummyToken"
			dummyExpTime := int64(999999999)
			dummyToken := fmt.Sprintf(`{"token":"%v", "expiryTime": %v}`, dummyTok, dummyExpTime)

			var sampleHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, dummyToken)
			})
			dummyServer := httptest.NewTLSServer(sampleHandler)

			roleRoleCache := gache.New()

			return test{
				name: "updateRoleToken set token in cache",
				fields: fields{
					httpClient:      dummyServer.Client(),
					domainRoleCache: roleRoleCache,
					token: func() (string, error) {
						return dummyToken, nil
					},
					athenzURL:             dummyServer.URL,
					athenzPrincipleHeader: "Athenz-Principal",
				},
				args: args{
					ctx:               context.Background(),
					domain:            "dummyDomain",
					role:              "dummyRole",
					proxyForPrincipal: "dummyProxy",
					minExpiry:         time.Second,
					maxExpiry:         time.Second,
				},
				checkFunc: func(got, want *RoleToken) error {
					_, ok := roleRoleCache.Get("dummyDomain;dummyRole;dummyProxy")
					if !ok {
						return fmt.Errorf("element cannot found in cache")
					}
					return nil
				},
				afterFunc: func() error {
					dummyServer.Close()
					return nil
				},
			}
		}(),
		func() test {
			dummyTok := "dummyToken"
			dummyExpTime := int64(999999999)
			dummyToken := fmt.Sprintf(`{"token":"%v", "expiryTime": %v}`, dummyTok, dummyExpTime)

			// create a dummy server that returns a dummy token
			var sampleHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, dummyToken)
			})
			dummyServer := httptest.NewTLSServer(sampleHandler)

			domainRoleCache := gache.New()

			// set another dummy token and see if it is updated
			dummyTok2 := "dummyToken2"
			dummyToken2 := fmt.Sprintf(`{"token":"%v", "expiryTime": %v}`, dummyTok2, dummyExpTime)
			dummyRoleToke2 := &RoleToken{
				Token:      dummyToken2,
				ExpiryTime: dummyExpTime,
			}
			domainRoleCache.SetWithExpire("dummyDomain;dummyRole", &cacheData{
				token: dummyRoleToke2,
			}, time.Second)

			return test{
				name: "updateRoleToken update token in cache",
				fields: fields{
					httpClient:      dummyServer.Client(),
					domainRoleCache: domainRoleCache,
					token: func() (string, error) {
						return dummyToken, nil
					},
					athenzURL:             dummyServer.URL,
					athenzPrincipleHeader: "Athenz-Principal",
				},
				args: args{
					ctx:               context.Background(),
					domain:            "dummyDomain",
					role:              "dummyRole",
					proxyForPrincipal: "dummyProxy",
					minExpiry:         time.Second,
					maxExpiry:         time.Second,
				},
				checkFunc: func(got, want *RoleToken) error {
					tok, ok := domainRoleCache.Get("dummyDomain;dummyRole;dummyProxy")
					if !ok {
						return fmt.Errorf("element cannot found in cache")
					}
					if tok.(*cacheData).token.Token != dummyTok {
						return fmt.Errorf("Token not updated")
					}
					return nil
				},
				afterFunc: func() error {
					dummyServer.Close()
					return nil
				},
			}
		}(),
	}
	for _, tt := range tests {
		if tt.afterFunc != nil {
			defer tt.afterFunc()
		}
		t.Run(tt.name, func(t *testing.T) {
			r := &roleService{
				cfg:                   tt.fields.cfg,
				token:                 tt.fields.token,
				athenzURL:             tt.fields.athenzURL,
				athenzPrincipleHeader: tt.fields.athenzPrincipleHeader,
				domainRoleCache:       tt.fields.domainRoleCache,
				group:                 tt.fields.group,
				expiry:                tt.fields.expiry,
				httpClient:            tt.fields.httpClient,
			}

			got, err := r.updateRoleToken(tt.args.ctx, tt.args.domain, tt.args.role, tt.args.proxyForPrincipal, tt.args.minExpiry, tt.args.maxExpiry)
			if tt.wantErr == nil && err != nil {
				t.Errorf("failed to instantiate, err: %v", err)
				return
			} else if tt.wantErr != nil {
				if tt.wantErr.Error() != err.Error() {
					t.Errorf("error not the same, want: %v, got: %v", tt.wantErr, err)
				}
			}

			if tt.checkFunc != nil {
				if err := tt.checkFunc(got, tt.want); err != nil {
					t.Errorf("roleService.updateRoleToken() = %v", err)
				}
			} else {
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("roleService.updateRoleToken() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func Test_roleService_fetchRoleToken(t *testing.T) {
	type fields struct {
		cfg                   config.Role
		token                 ntokend.TokenProvider
		athenzURL             string
		athenzPrincipleHeader string
		domainRoleCache       gache.Gache
		group                 singleflight.Group
		expiry                time.Duration
		httpClient            *http.Client
		refreshInterval       time.Duration
		errRetryMaxCount      int
		errRetryInterval      time.Duration
	}
	type args struct {
		ctx               context.Context
		domain            string
		role              string
		proxyForPrincipal string
		minExpiry         time.Duration
		maxExpiry         time.Duration
	}
	type test struct {
		name    string
		fields  fields
		args    args
		want    *RoleToken
		wantErr error
	}
	tests := []test{
		func() test {
			dummyTok := "dummyToken"
			dummyExpTime := int64(999999999)
			dummyToken := fmt.Sprintf(`{"token":"%v", "expiryTime": %v}`, dummyTok, dummyExpTime)

			var sampleHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, dummyToken)
				w.WriteHeader(http.StatusOK)
			})
			dummyServer := httptest.NewTLSServer(sampleHandler)

			return test{
				name: "fetch role token success",
				fields: fields{
					token: func() (string, error) {
						return "dummyNtoken", nil
					},
					athenzURL:             dummyServer.URL,
					athenzPrincipleHeader: "dummy-header",
					httpClient:            dummyServer.Client(),
				},
				args: args{
					ctx:               context.Background(),
					domain:            "dummyDomain",
					role:              "dummyRole",
					proxyForPrincipal: "dummyProxy",
					minExpiry:         time.Hour,
					maxExpiry:         time.Hour,
				},
				want: &RoleToken{
					Token:      dummyTok,
					ExpiryTime: dummyExpTime,
				},
			}
		}(),
		func() test {
			dummyTok := "dummyToken"
			dummyExpTime := int64(999999999)
			dummyToken := fmt.Sprintf(`{"token":"%v", "expiryTime": %v}`, dummyTok, dummyExpTime)

			var sampleHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, dummyToken)
				w.WriteHeader(http.StatusOK)
			})
			dummyServer := httptest.NewTLSServer(sampleHandler)

			dummyErr := errors.New("dummy error")
			return test{
				name: "ntoken provider return error",
				fields: fields{
					token: func() (string, error) {
						return "", dummyErr
					},
					athenzURL:             dummyServer.URL,
					athenzPrincipleHeader: "dummy-header",
					httpClient:            dummyServer.Client(),
				},
				args: args{
					ctx:               context.Background(),
					domain:            "dummyDomain",
					role:              "dummyRole",
					proxyForPrincipal: "dummyProxy",
					minExpiry:         time.Hour,
					maxExpiry:         time.Hour,
				},
				wantErr: dummyErr,
			}
		}(),
		func() test {
			dummyTok := "dummyToken"
			dummyExpTime := int64(999999999)
			dummyToken := fmt.Sprintf(`{"token":"%v", "expiryTime": %v}`, dummyTok, dummyExpTime)

			var sampleHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, dummyToken)
				w.WriteHeader(http.StatusOK)
			})
			dummyServer := httptest.NewTLSServer(sampleHandler)

			return test{
				name: "invalid athenz url set",
				fields: fields{
					token: func() (string, error) {
						return "dummyNToken", nil
					},
					athenzURL:             "dummyAthenzURL",
					athenzPrincipleHeader: "dummy-header",
					httpClient:            dummyServer.Client(),
				},
				args: args{
					ctx:               context.Background(),
					domain:            "dummyDomain",
					role:              "dummyRole",
					proxyForPrincipal: "dummyProxy",
					minExpiry:         time.Hour,
					maxExpiry:         time.Hour,
				},
				wantErr: errors.New("Get https://dummyAthenzURL/domain/dummyDomain/token?role=dummyRole&minExpiryTime=3600&maxExpiryTime=3600&proxyForPrincipal=dummyProxy: dial tcp: lookup dummyAthenzURL: no such host"),
			}
		}(),
		func() test {
			var sampleHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			})
			dummyServer := httptest.NewTLSServer(sampleHandler)

			return test{
				name: "athenz server return error",
				fields: fields{
					token: func() (string, error) {
						return "dummyNToken", nil
					},
					athenzURL:             dummyServer.URL,
					athenzPrincipleHeader: "dummy-header",
					httpClient:            dummyServer.Client(),
				},
				args: args{
					ctx:               context.Background(),
					domain:            "dummyDomain",
					role:              "dummyRole",
					proxyForPrincipal: "dummyProxy",
					minExpiry:         time.Hour,
					maxExpiry:         time.Hour,
				},
				wantErr: ErrRoleTokenRequestFailed,
			}
		}(),
		func() test {
			dummyTok := "dummyToken"

			var sampleHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, dummyTok)
				w.WriteHeader(http.StatusOK)
			})
			dummyServer := httptest.NewTLSServer(sampleHandler)

			return test{
				name: "athenz server return invalid role token",
				fields: fields{
					token: func() (string, error) {
						return "dummyNToken", nil
					},
					athenzURL:             dummyServer.URL,
					athenzPrincipleHeader: "dummy-header",
					httpClient:            dummyServer.Client(),
				},
				args: args{
					ctx:               context.Background(),
					domain:            "dummyDomain",
					role:              "dummyRole",
					proxyForPrincipal: "dummyProxy",
					minExpiry:         time.Hour,
					maxExpiry:         time.Hour,
				},
				wantErr: errors.New("invalid character 'd' looking for beginning of value"),
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &roleService{
				cfg:                   tt.fields.cfg,
				token:                 tt.fields.token,
				athenzURL:             tt.fields.athenzURL,
				athenzPrincipleHeader: tt.fields.athenzPrincipleHeader,
				domainRoleCache:       tt.fields.domainRoleCache,
				group:                 tt.fields.group,
				expiry:                tt.fields.expiry,
				httpClient:            tt.fields.httpClient,
				refreshInterval:       tt.fields.refreshInterval,
				errRetryMaxCount:      tt.fields.errRetryMaxCount,
				errRetryInterval:      tt.fields.errRetryInterval,
			}
			got, err := r.fetchRoleToken(tt.args.ctx, tt.args.domain, tt.args.role, tt.args.proxyForPrincipal, tt.args.minExpiry, tt.args.maxExpiry)
			if err != nil {
				if tt.wantErr == nil {
					t.Errorf("roleService.fetchRoleToken() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if err.Error() != tt.wantErr.Error() {
					t.Errorf("roleService.fetchRoleToken() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
			} else if tt.wantErr != nil {
				t.Errorf("roleService.fetchRoleToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("roleService.fetchRoleToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_roleService_getCache(t *testing.T) {
	type fields struct {
		cfg                   config.Role
		token                 ntokend.TokenProvider
		athenzURL             string
		athenzPrincipleHeader string
		domainRoleCache       gache.Gache
		group                 singleflight.Group
		expiry                time.Duration
	}
	type args struct {
		domain    string
		role      string
		principal string
	}
	type test struct {
		name   string
		fields fields
		args   args
		want   *RoleToken
		want1  bool
	}
	tests := []test{
		func() test {
			return test{
				name: "getCache return not ok (cache not exist)",
				fields: fields{
					domainRoleCache: gache.New(),
				},
				args: args{
					domain:    "dummyDomain",
					role:      "dummyRole",
					principal: "principal",
				},
				want:  nil,
				want1: false,
			}
		}(),
		func() test {
			dummyTok := "dummyToken"
			dummyExpTime := int64(999999999)
			dummyToken := fmt.Sprintf(`{"token":"%v", "expiryTime": %v}`, dummyTok, dummyExpTime)

			roleToken := &RoleToken{
				Token:      dummyToken,
				ExpiryTime: dummyExpTime,
			}

			domainRoleCache := gache.New()
			domainRoleCache.Set("dummyDomain;dummyRole;principal", &cacheData{
				token: roleToken,
			})

			return test{
				name: "getCache return cache value",
				fields: fields{
					domainRoleCache: domainRoleCache,
				},
				args: args{
					domain:    "dummyDomain",
					role:      "dummyRole",
					principal: "principal",
				},
				want:  roleToken,
				want1: true,
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &roleService{
				cfg:                   tt.fields.cfg,
				token:                 tt.fields.token,
				athenzURL:             tt.fields.athenzURL,
				athenzPrincipleHeader: tt.fields.athenzPrincipleHeader,
				domainRoleCache:       tt.fields.domainRoleCache,
				group:                 tt.fields.group,
				expiry:                tt.fields.expiry,
			}
			got, got1 := r.getCache(tt.args.domain, tt.args.role, tt.args.principal)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("roleService.getCache() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("roleService.getCache() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func Test_encode(t *testing.T) {
	type args struct {
		domain    string
		role      string
		principal string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Encode correct",
			args: args{
				domain:    "dummyDomain",
				role:      "dummyRole",
				principal: "dummyPrincipal",
			},
			want: "dummyDomain;dummyRole;dummyPrincipal",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := encode(tt.args.domain, tt.args.role, tt.args.principal); got != tt.want {
				t.Errorf("encode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_decode(t *testing.T) {
	type args struct {
		key string
	}
	tests := []struct {
		name  string
		args  args
		want  string
		want1 string
		want2 string
	}{
		{
			name: "decode correct",
			args: args{
				key: "dummyDomain;dummyRole",
			},
			want:  "dummyDomain",
			want1: "dummyRole",
			want2: "",
		},
		{
			name: "decode correct no hyphen",
			args: args{
				key: "dummyDomain",
			},
			want:  "dummyDomain",
			want1: "",
			want2: "",
		},
		{
			name: "decode correct 3 hyphen",
			args: args{
				key: "dummyDomain;domainRole;dummy1;dummy2",
			},
			want:  "dummyDomain",
			want1: "domainRole",
			want2: "dummy1;dummy2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, got2 := decode(tt.args.key)
			if got != tt.want {
				t.Errorf("decode() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("decode() got1 = %v, want %v", got1, tt.want1)
			}
			if got2 != tt.want2 {
				t.Errorf("decode() got2 = %v, want %v", got2, tt.want2)
			}
		})
	}
}

func Test_getRoleTokenAthenzURL(t *testing.T) {
	type fields struct {
		cfg                   config.Role
		token                 ntokend.TokenProvider
		athenzURL             string
		athenzPrincipleHeader string
		domainRoleCache       gache.Gache
		group                 singleflight.Group
		expiry                time.Duration
	}
	type args struct {
		athenzURL         string
		domain            string
		role              string
		minExpiry         time.Duration
		maxExpiry         time.Duration
		proxyForPrincipal string
	}
	tests := []struct {
		name   string
		args   args
		want   string
		fields fields
	}{
		{
			name: "getRoleTokenAthenzURL correct",
			args: args{
				domain:            "dummyDomain",
				role:              "dummyRole",
				minExpiry:         time.Second,
				maxExpiry:         time.Second,
				proxyForPrincipal: "dummyProxyForPrincipal",
			},
			fields: fields{
				athenzURL: "dummyUURL",
			},

			want: "https://dummyUURL/domain/dummyDomain/token?role=dummyRole&minExpiryTime=1&maxExpiryTime=1&proxyForPrincipal=dummyProxyForPrincipal",
		},
		{
			name: "getRoleTokenAthenzURL correct null minExpiry",
			args: args{
				domain:            "dummyDomain",
				role:              "dummyRole",
				maxExpiry:         time.Second,
				proxyForPrincipal: "dummyProxyForPrincipal",
			},
			fields: fields{
				athenzURL: "dummyUURL",
				expiry:    time.Minute,
			},
			want: "https://dummyUURL/domain/dummyDomain/token?role=dummyRole&minExpiryTime=60&maxExpiryTime=1&proxyForPrincipal=dummyProxyForPrincipal",
		},
		{
			name: "getRoleTokenAthenzURL correct null maxExpiry",
			args: args{
				domain:            "dummyDomain",
				role:              "dummyRole",
				minExpiry:         time.Second,
				proxyForPrincipal: "dummyProxyForPrincipal",
			},
			fields: fields{
				athenzURL: "dummyUURL",
				expiry:    time.Minute,
			},
			want: "https://dummyUURL/domain/dummyDomain/token?role=dummyRole&minExpiryTime=1&maxExpiryTime=60&proxyForPrincipal=dummyProxyForPrincipal",
		},
		{
			name: "getRoleTokenAthenzURL correct null proxyForPrincipal",
			args: args{
				domain:    "dummyDomain",
				role:      "dummyRole",
				minExpiry: time.Second,
				maxExpiry: time.Second,
			},
			fields: fields{
				athenzURL: "dummyUURL",
			},
			want: "https://dummyUURL/domain/dummyDomain/token?role=dummyRole&minExpiryTime=1&maxExpiryTime=1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &roleService{
				cfg:                   tt.fields.cfg,
				token:                 tt.fields.token,
				athenzURL:             tt.fields.athenzURL,
				athenzPrincipleHeader: tt.fields.athenzPrincipleHeader,
				domainRoleCache:       tt.fields.domainRoleCache,
				group:                 tt.fields.group,
				expiry:                tt.fields.expiry,
			}
			if got := r.getRoleTokenAthenzURL(tt.args.domain, tt.args.role, tt.args.minExpiry, tt.args.maxExpiry, tt.args.proxyForPrincipal); got != tt.want {
				t.Errorf("getRoleTokenAthenzURL() = %v, want %v", got, tt.want)
			}
		})
	}
}
