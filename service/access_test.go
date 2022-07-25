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
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kpango/fastime"
	"github.com/kpango/gache"
	"github.com/kpango/ntokend"
	"github.com/pkg/errors"
	"github.com/yahoojapan/athenz-client-sidecar/v2/config"
)

func TestNewAccessService(t *testing.T) {
	type args struct {
		cfg   config.AccessToken
		token ntokend.TokenProvider
	}
	type test struct {
		name      string
		args      args
		checkFunc func(got, want AccessService) error
		want      AccessService
		wantErr   error
	}
	dummyTokenProvider := func() (string, error) { return "", nil }
	tests := []test{
		func() test {
			args := args{
				cfg: config.AccessToken{
					Enable:              true,
					Expiry:              "5s",
					AthenzURL:           "dummy",
					PrincipalAuthHeader: "dummyAuthHeader",
					RefreshPeriod:       "1s",
				},
				token: dummyTokenProvider,
			}
			return test{
				name: "NewAccessService return correct",
				args: args,
				checkFunc: func(got, want AccessService) error {
					gotS := got.(*accessService)
					wantS := want.(*accessService)
					if !reflect.DeepEqual(gotS.cfg, wantS.cfg) ||
						reflect.ValueOf(gotS.token).Pointer() != reflect.ValueOf(wantS.token).Pointer() ||
						!reflect.DeepEqual(gotS.athenzURL, wantS.athenzURL) ||
						!reflect.DeepEqual(gotS.athenzPrincipleHeader, wantS.athenzPrincipleHeader) ||
						//!reflect.DeepEqual(gotS.tokenCache, wantS.tokenCache) ||
						!reflect.DeepEqual(gotS.expiry, wantS.expiry) {

						return fmt.Errorf("got: %+v, want: %+v", got, want)
					}
					return nil
				},
				want: &accessService{
					cfg:                   args.cfg,
					token:                 args.token,
					athenzURL:             args.cfg.AthenzURL,
					athenzPrincipleHeader: args.cfg.PrincipalAuthHeader,
					tokenCache:            gache.New(),
					expiry: func() time.Duration {
						dur, _ := time.ParseDuration(args.cfg.Expiry)
						return dur
					}(),
				},
			}
		}(),
		func() test {
			args := args{
				cfg: config.AccessToken{
					Enable:              true,
					AthenzURL:           "dummy",
					PrincipalAuthHeader: "dummyAuthHeader",
				},
				token: dummyTokenProvider,
			}
			return test{
				name: "NewAccessService default values",
				args: args,
				checkFunc: func(got, want AccessService) error {
					gotS := got.(*accessService)
					wantS := want.(*accessService)
					if !reflect.DeepEqual(gotS.cfg, wantS.cfg) ||
						reflect.ValueOf(gotS.token).Pointer() != reflect.ValueOf(wantS.token).Pointer() ||
						!reflect.DeepEqual(gotS.athenzURL, wantS.athenzURL) ||
						!reflect.DeepEqual(gotS.athenzPrincipleHeader, wantS.athenzPrincipleHeader) ||
						//!reflect.DeepEqual(gotS.tokenCache, wantS.tokenCache) ||
						!reflect.DeepEqual(gotS.expiry, wantS.expiry) ||
						!reflect.DeepEqual(gotS.refreshPeriod, wantS.refreshPeriod) ||
						!reflect.DeepEqual(gotS.errRetryMaxCount, wantS.errRetryMaxCount) ||
						!reflect.DeepEqual(gotS.errRetryInterval, wantS.errRetryInterval) {

						return fmt.Errorf("got: %+v, want: %+v", got, want)
					}
					return nil
				},
				want: &accessService{
					cfg:                   args.cfg,
					token:                 args.token,
					athenzURL:             args.cfg.AthenzURL,
					athenzPrincipleHeader: args.cfg.PrincipalAuthHeader,
					tokenCache:            gache.New(),
					expiry:                0,
					errRetryInterval:      defaultErrRetryInterval,
					errRetryMaxCount:      defaultErrRetryMaxCount,
					refreshPeriod:         defaultRefreshPeriod,
				},
			}
		}(),
		func() test {
			args := args{
				cfg: config.AccessToken{
					Enable: true,
					Expiry: "1x",
				},
			}
			return test{
				name:    "NewAccessService return error with Expiry of invalid format",
				args:    args,
				wantErr: errors.Wrap(ErrInvalidSetting, `Expiry: time: unknown unit "x" in duration "1x"`),
			}
		}(),
		func() test {
			args := args{
				cfg: config.AccessToken{
					Enable:        true,
					RefreshPeriod: "1x",
				},
			}
			return test{
				name:    "NewAccessService return error with RefreshPeriod of invalid format",
				args:    args,
				wantErr: errors.Wrap(ErrInvalidSetting, `RefreshPeriod: time: unknown unit "x" in duration "1x"`),
			}
		}(),
		func() test {
			args := args{
				cfg: config.AccessToken{
					Enable: true,
					Retry: config.Retry{
						Delay: "1x",
					},
				},
			}
			return test{
				name:    "NewAccessService return error with ErrRetryInterval of invalid format",
				args:    args,
				wantErr: errors.Wrap(ErrInvalidSetting, `ErrRetryInterval: time: unknown unit "x" in duration "1x"`),
			}
		}(),
		func() test {
			args := args{
				cfg: config.AccessToken{
					Enable: true,
					Retry: config.Retry{
						Attempts: -1,
					},
				},
			}
			return test{
				name:    "NewAccessService return error with ErrRetryMaxCount < 0",
				args:    args,
				wantErr: errors.Wrap(ErrInvalidSetting, "ErrRetryMaxCount < 0"),
			}
		}(),
		func() test {
			args := args{
				cfg: config.AccessToken{
					Enable:              true,
					AthenzURL:           "dummy",
					PrincipalAuthHeader: "dummyAuthHeader",
					RefreshPeriod:       "60s",
					Expiry:              "1s",
				},
				token: dummyTokenProvider,
			}
			return test{
				name:    "NewAccessService return error when refresh period > token expiry",
				args:    args,
				wantErr: errors.Wrap(ErrInvalidSetting, "refresh period > token expiry time"),
			}
		}(),
		func() test {
			cnt := 10
			args := args{
				cfg: config.AccessToken{
					Enable:              true,
					AthenzURL:           "dummy",
					PrincipalAuthHeader: "dummyAuthHeader",
					Retry: config.Retry{
						Attempts: cnt,
					},
				},
				token: dummyTokenProvider,
			}
			return test{
				name: "NewAccessService specific ErrRetryMaxCount",
				args: args,
				checkFunc: func(got, want AccessService) error {
					gotS := got.(*accessService)
					wantS := want.(*accessService)
					if !reflect.DeepEqual(gotS.cfg, wantS.cfg) ||
						reflect.ValueOf(gotS.token).Pointer() != reflect.ValueOf(wantS.token).Pointer() ||
						!reflect.DeepEqual(gotS.athenzURL, wantS.athenzURL) ||
						!reflect.DeepEqual(gotS.athenzPrincipleHeader, wantS.athenzPrincipleHeader) ||
						//!reflect.DeepEqual(gotS.tokenCache, wantS.tokenCache) ||
						!reflect.DeepEqual(gotS.expiry, wantS.expiry) ||
						!reflect.DeepEqual(gotS.refreshPeriod, wantS.refreshPeriod) ||
						!reflect.DeepEqual(gotS.errRetryMaxCount, wantS.errRetryMaxCount) ||
						!reflect.DeepEqual(gotS.errRetryInterval, wantS.errRetryInterval) {

						return fmt.Errorf("got: %+v, want: %+v", got, want)
					}
					return nil
				},
				want: &accessService{
					cfg:                   args.cfg,
					token:                 args.token,
					athenzURL:             args.cfg.AthenzURL,
					athenzPrincipleHeader: args.cfg.PrincipalAuthHeader,
					tokenCache:            gache.New(),
					expiry:                0,
					errRetryInterval:      defaultErrRetryInterval,
					errRetryMaxCount:      cnt,
					refreshPeriod:         defaultRefreshPeriod,
				},
			}
		}(),
		func() test {
			args := args{
				cfg: config.AccessToken{
					Enable:              true,
					AthenzURL:           "dummy",
					PrincipalAuthHeader: "dummyAuthHeader",
					AthenzCAPath:        "../test/data/dummyCa.pem",
				},
				token: dummyTokenProvider,
			}
			cp, err := NewX509CertPool(args.cfg.AthenzCAPath)
			if err != nil {
				panic(err)
			}
			return test{
				name: "NewAccessService contains valid Athenz rootCA",
				args: args,
				checkFunc: func(got, want AccessService) error {
					gotS := got.(*accessService)
					wantS := want.(*accessService)
					if !reflect.DeepEqual(gotS.cfg, wantS.cfg) ||
						reflect.ValueOf(gotS.token).Pointer() != reflect.ValueOf(wantS.token).Pointer() ||
						!reflect.DeepEqual(gotS.athenzURL, wantS.athenzURL) ||
						!reflect.DeepEqual(gotS.athenzPrincipleHeader, wantS.athenzPrincipleHeader) ||
						//!reflect.DeepEqual(gotS.tokenCache, wantS.tokenCache) ||
						!reflect.DeepEqual(gotS.expiry, wantS.expiry) ||
						// !reflect.DeepEqual(gotS.rootCAs, wantS.rootCAs.Subjects()) ||
						!reflect.DeepEqual(gotS.refreshPeriod, wantS.refreshPeriod) ||
						!reflect.DeepEqual(gotS.errRetryMaxCount, wantS.errRetryMaxCount) ||
						!reflect.DeepEqual(gotS.errRetryInterval, wantS.errRetryInterval) {

						return fmt.Errorf("got: %+v, want: %+v", got, want)
					}

					return nil
				},
				want: &accessService{
					cfg:                   args.cfg,
					token:                 args.token,
					athenzURL:             args.cfg.AthenzURL,
					athenzPrincipleHeader: args.cfg.PrincipalAuthHeader,
					tokenCache:            gache.New(),
					expiry:                0,
					rootCAs:               cp,
					errRetryInterval:      defaultErrRetryInterval,
					errRetryMaxCount:      defaultErrRetryMaxCount,
					refreshPeriod:         defaultRefreshPeriod,
				},
			}
		}(),
		func() test {
			args := args{
				cfg: config.AccessToken{
					Enable:              true,
					AthenzURL:           "dummy",
					PrincipalAuthHeader: "dummyAuthHeader",
					CertPath:            "../test/data/dummyClient.crt",
					CertKeyPath:         "../test/data/dummyClient.key",
				},
				token: nil,
			}
			return test{
				name: "NewAccessService contains valid client certificate",
				args: args,
				checkFunc: func(got, want AccessService) error {
					gotS := got.(*accessService)
					wantS := want.(*accessService)
					if !reflect.DeepEqual(gotS.cfg, wantS.cfg) ||
						// reflect.ValueOf(gotS.token).Pointer() != reflect.ValueOf(wantS.token).Pointer() ||
						!reflect.DeepEqual(gotS.athenzURL, wantS.athenzURL) ||
						!reflect.DeepEqual(gotS.athenzPrincipleHeader, wantS.athenzPrincipleHeader) ||
						//!reflect.DeepEqual(gotS.tokenCache, wantS.tokenCache) ||
						!reflect.DeepEqual(gotS.expiry, wantS.expiry) ||
						!reflect.DeepEqual(gotS.certPath, wantS.certPath) ||
						!reflect.DeepEqual(gotS.certKeyPath, wantS.certKeyPath) ||
						!reflect.DeepEqual(gotS.refreshPeriod, wantS.refreshPeriod) ||
						!reflect.DeepEqual(gotS.errRetryMaxCount, wantS.errRetryMaxCount) ||
						!reflect.DeepEqual(gotS.errRetryInterval, wantS.errRetryInterval) {

						return fmt.Errorf("got: %+v, want: %+v", got, want)
					}

					return nil
				},
				want: &accessService{
					cfg:                   args.cfg,
					token:                 args.token,
					athenzURL:             args.cfg.AthenzURL,
					athenzPrincipleHeader: args.cfg.PrincipalAuthHeader,
					tokenCache:            gache.New(),
					expiry:                0,
					certPath:              "../test/data/dummyClient.crt",
					certKeyPath:           "../test/data/dummyClient.key",
					errRetryInterval:      defaultErrRetryInterval,
					errRetryMaxCount:      defaultErrRetryMaxCount,
					refreshPeriod:         defaultRefreshPeriod,
				},
			}
		}(),
		func() test {
			args := args{
				cfg: config.AccessToken{
					Enable:              true,
					AthenzURL:           "dummy",
					PrincipalAuthHeader: "dummyAuthHeader",
					CertPath:            "../test/data/dummyClient.crt",
					CertKeyPath:         "../test/data/dummyClient.key",
				},
				token: dummyTokenProvider,
			}
			return test{
				name: "NewAccessService that ntokend takes priority over client certificate",
				args: args,
				checkFunc: func(got, want AccessService) error {
					gotS := got.(*accessService)
					wantS := want.(*accessService)
					if !reflect.DeepEqual(gotS.cfg, wantS.cfg) ||
						// reflect.ValueOf(gotS.token).Pointer() != reflect.ValueOf(wantS.token).Pointer() ||
						!reflect.DeepEqual(gotS.athenzURL, wantS.athenzURL) ||
						!reflect.DeepEqual(gotS.athenzPrincipleHeader, wantS.athenzPrincipleHeader) ||
						//!reflect.DeepEqual(gotS.tokenCache, wantS.tokenCache) ||
						!reflect.DeepEqual(gotS.expiry, wantS.expiry) ||
						!reflect.DeepEqual(gotS.certPath, wantS.certPath) ||
						!reflect.DeepEqual(gotS.certKeyPath, wantS.certKeyPath) ||
						!reflect.DeepEqual(gotS.refreshPeriod, wantS.refreshPeriod) ||
						!reflect.DeepEqual(gotS.errRetryMaxCount, wantS.errRetryMaxCount) ||
						!reflect.DeepEqual(gotS.errRetryInterval, wantS.errRetryInterval) {

						return fmt.Errorf("got: %+v, want: %+v", got, want)
					}

					// check client certificate in TLS client config
					gotClient := gotS.httpClient.Load().(*http.Client)
					if gotClient.Transport.(*http.Transport).TLSClientConfig.Certificates != nil {
						return errors.New("Unexpected client certificate is set.")
					}

					return nil
				},
				want: &accessService{
					cfg:                   args.cfg,
					token:                 args.token,
					athenzURL:             args.cfg.AthenzURL,
					athenzPrincipleHeader: args.cfg.PrincipalAuthHeader,
					tokenCache:            gache.New(),
					expiry:                0,
					certPath:              "",
					certKeyPath:           "",
					errRetryInterval:      defaultErrRetryInterval,
					errRetryMaxCount:      defaultErrRetryMaxCount,
					refreshPeriod:         defaultRefreshPeriod,
				},
			}
		}(),
		{
			name: "NewAccessService disabled",
			args: args{
				cfg: config.AccessToken{},
			},
			wantErr: ErrDisabled,
		},
		{
			name: "NewAccessService no credentials",
			args: args{
				cfg: config.AccessToken{
					Enable:   true,
					CertPath: "",
				},
			},
			wantErr: errors.Wrap(ErrInvalidSetting, "Neither NToken nor client certificate is set."),
		},
		{
			name: "NewAccessService with non-existing Athenz rootCA",
			args: args{
				cfg: config.AccessToken{
					Enable:       true,
					AthenzCAPath: "../test/data/non_exist.pem",
				},
				token: dummyTokenProvider,
			},
			wantErr: errors.Wrap(ErrInvalidSetting, "Athenz CA not exist"),
		},
		{
			name: "NewAccessService with invalid Athenz rootCA",
			args: args{
				cfg: config.AccessToken{
					Enable:       true,
					AthenzCAPath: "../test/data/invalid_dummyCa.pem",
				},
				token: dummyTokenProvider,
			},
			wantErr: errors.Wrap(ErrInvalidSetting, "Certification Failed"),
		},
		{
			name: "NewAccessService with non-existing client certificate",
			args: args{
				cfg: config.AccessToken{
					Enable:   true,
					CertPath: "../test/data/non_exist.pem",
				},
				token: nil,
			},
			wantErr: errors.Wrap(ErrInvalidSetting, "client certificate not found"),
		},
		{
			name: "NewAccessService with non-existing client certificate key",
			args: args{
				cfg: config.AccessToken{
					Enable:      true,
					CertPath:    "../test/data/dummyClient.crt",
					CertKeyPath: "../test/data/non_exist.key",
				},
				token: nil,
			},
			wantErr: errors.Wrap(ErrInvalidSetting, "client certificate key not found"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewAccessService(tt.args.cfg, tt.args.token)

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
					t.Errorf("NewAccessService() err: %v", err)
				}
			}
		})
	}
}

func Test_accessService_StartAccessUpdater(t *testing.T) {
	type fields struct {
		cfg                   config.AccessToken
		token                 ntokend.TokenProvider
		athenzURL             string
		athenzPrincipleHeader string
		tokenCache            gache.Gache
		expiry                time.Duration
		httpClient            atomic.Value
		refreshPeriod         time.Duration
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
		checkFunc func(AccessService, <-chan error) error
		afterFunc func() error
	}
	tests := []test{
		func() test {
			dummyExpTime := int64(1)
			dummyToken := "dummyToken"
			dummyAccessToken := &AccessTokenResponse{
				AccessToken: dummyToken,
				ExpiresIn:   dummyExpTime,
			}

			tokenCache := gache.New()
			tokenCache.SetWithExpire("dummyDomain;dummyRole", &accessCacheData{
				token: dummyAccessToken,
			}, time.Minute)

			// create dummy server to mock the updateAccessToken
			dummyToken2 := `{"access_token":"dummyToken2","token_type":"Bearer","expires_in":1000,"scope":"dummyDomain2:dummyRole2"}"`

			var sampleHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, dummyToken2)
			})
			dummyServer := httptest.NewTLSServer(sampleHandler)

			var httpClient atomic.Value
			httpClient.Store(dummyServer.Client())
			return test{
				name: "StartAccessUpdater can update cache periodically",
				fields: fields{
					httpClient:            httpClient,
					tokenCache:            tokenCache,
					expiry:                time.Second,
					athenzURL:             dummyServer.URL,
					athenzPrincipleHeader: "Athenz-Principal",
					token: func() (string, error) {
						return "dummy N-token", nil
					},
					refreshPeriod:    time.Second,
					errRetryMaxCount: 5,
					errRetryInterval: time.Second,
				},
				args: args{
					ctx: context.Background(),
				},
				checkFunc: func(as AccessService, errs <-chan error) error {
					accessTok1, ok := tokenCache.Get("dummyDomain;dummyRole")
					if !ok {
						return fmt.Errorf("cannot get first access token")
					}

					time.Sleep(time.Second * 2)

					accessTok2, ok := tokenCache.Get("dummyDomain;dummyRole")
					if !ok {
						return fmt.Errorf("cannot get second access token")
					}

					if reflect.DeepEqual(accessTok1, accessTok2) {
						return fmt.Errorf("Token did not updated, access token 1: %v, access token 2: %v", accessTok1, accessTok2)
					}

					return nil
				},
				afterFunc: func() error {
					dummyServer.Close()
					tokenCache.Stop()
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
					newToken := `{"access_token":"newToken","token_type":"Bearer","expires_in":1000,"scope":"dummyDomain:dummyRole"}"`
					fmt.Fprint(w, newToken)
				}
				i++
			})
			dummyServer := httptest.NewTLSServer(sampleHandler)

			tokenCache := gache.New()
			data := &accessCacheData{
				token:             nil,
				domain:            "dummyDomain",
				role:              "dummyRole",
				proxyForPrincipal: "dummyProxy",
				expiresIn:         60,
			}
			tokenCache.SetWithExpire("dummyDomain;dummyRole;dummyProxy", data, time.Minute)

			ctx, cancel := context.WithCancel(context.Background())

			var httpClient atomic.Value
			httpClient.Store(dummyServer.Client())
			return test{
				name: "RefreshAccessTokenCache success with retry",
				fields: fields{
					httpClient: httpClient,
					tokenCache: tokenCache,
					token: func() (string, error) {
						return "dummyToken", nil
					},
					athenzURL:             dummyServer.URL,
					athenzPrincipleHeader: "Athenz-Principal",
					errRetryMaxCount:      9,
					refreshPeriod:         time.Millisecond * 100,
					errRetryInterval:      time.Millisecond,
					expiry:                time.Millisecond * 200,
				},
				args: args{
					ctx: ctx,
				},
				checkFunc: func(as AccessService, echan <-chan error) error {
					time.Sleep(time.Second)
					cancel()

					errs := make([]error, 0, 3)
					for err := range echan {
						if err != context.Canceled {
							errs = append(errs, err)
						}
					}

					// check the length
					if len(errs) != 3 {
						return errors.Errorf("len(err) = %v, errors: %v", len(errs), errs)
					}

					// check errors
					for _, err := range errs {
						if err.Error() != errors.Wrap(ErrAccessTokenRequestFailed, "error update access token").Error() {
							return errors.Errorf("Unexpected error: %v, want: %v", err, errors.Wrap(ErrAccessTokenRequestFailed, "error update access token"))
						}
					}

					tok, ok := tokenCache.Get("dummyDomain;dummyRole;dummyProxy")
					if !ok {
						return errors.New("token does not set to the cache")
					}

					if tok.(*accessCacheData).token.AccessToken != dummyTok {
						return errors.New("invalid token set on the cache")
					}

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

			tokenCache := gache.New()
			data := &accessCacheData{
				token: &AccessTokenResponse{
					AccessToken: dummyTok,
					ExpiresIn:   int64(99999999),
				},
				domain:            "dummyDomain",
				role:              "dummyRole",
				proxyForPrincipal: "dummyProxy",
				expiresIn:         60,
			}
			tokenCache.SetWithExpire("dummyDomain;dummyRole;dummyProxy", data, time.Minute)

			ctx, cancel := context.WithCancel(context.Background())

			var httpClient atomic.Value
			httpClient.Store(dummyServer.Client())
			return test{
				name: "RefreshAccessTokenCache failed",
				fields: fields{
					httpClient: httpClient,
					tokenCache: tokenCache,
					token: func() (string, error) {
						return "dummyToken", nil
					},
					athenzURL:             dummyServer.URL,
					athenzPrincipleHeader: "Athenz-Principal",
					errRetryMaxCount:      9,
					refreshPeriod:         time.Millisecond * 700,
					errRetryInterval:      time.Millisecond,
					expiry:                time.Millisecond * 700,
				},
				args: args{
					ctx: ctx,
				},
				checkFunc: func(as AccessService, echan <-chan error) error {
					time.Sleep(time.Second)
					cancel()

					errs := make([]error, 0, 10)
					for err := range echan {
						if err != context.Canceled {
							errs = append(errs, err)
						}
					}

					// check the length
					if len(errs) != 10 {
						return errors.Errorf("len(err) = %v, errors: %v", len(errs), errs)
					}

					// check errors
					for _, err := range errs {
						if err.Error() != errors.Wrap(ErrAccessTokenRequestFailed, "error update access token").Error() {
							return errors.Errorf("Unexpected error: %v, want: %v", err, errors.Wrap(ErrAccessTokenRequestFailed, "error update access token"))
						}
					}

					// the cache will not be deleted even the fetch is failed
					tok, ok := tokenCache.Get("dummyDomain;dummyRole;dummyProxy")
					if !ok {
						return errors.New("token does not set to the cache")
					}

					if tok.(*accessCacheData).token.AccessToken != dummyTok {
						return errors.New("invalid token set on the cache")
					}

					return nil
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.afterFunc != nil {
				defer func() {
					err := tt.afterFunc()
					if err != nil {
						t.Errorf("Failed afterFunc %v", err)
					}
				}()
			}
			r := &accessService{
				cfg:                   tt.fields.cfg,
				token:                 tt.fields.token,
				athenzURL:             tt.fields.athenzURL,
				athenzPrincipleHeader: tt.fields.athenzPrincipleHeader,
				tokenCache:            tt.fields.tokenCache,
				expiry:                tt.fields.expiry,
				httpClient:            tt.fields.httpClient,
				refreshPeriod:         tt.fields.refreshPeriod,
				errRetryMaxCount:      tt.fields.errRetryMaxCount,
				errRetryInterval:      tt.fields.errRetryInterval,
			}
			got := r.StartAccessUpdater(tt.args.ctx)
			if err := tt.checkFunc(r, got); err != nil {
				t.Errorf("accessService.StartAccessUpdater(), error: %v", err)
			}
		})
	}
}

func Test_accessService_GetAccessProvider(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "provider exactly return",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := func() (string, error) { return "", nil }
			r, err := NewAccessService(config.AccessToken{
				Enable: true,
			}, token)
			if err != nil {
				t.Error(err.Error())
				return
			}
			if got := r.GetAccessProvider(); got == nil {
				t.Error("provider is nil")
				return
			}
		})
	}
}

func Test_accessService_getAccessToken(t *testing.T) {
	type fields struct {
		cfg                   config.AccessToken
		token                 ntokend.TokenProvider
		athenzURL             string
		athenzPrincipleHeader string
		tokenCache            gache.Gache
		expiry                time.Duration
		httpClient            atomic.Value
	}
	type args struct {
		ctx               context.Context
		domain            string
		role              string
		proxyForPrincipal string
		expiresIn         int64
	}
	type test struct {
		name      string
		fields    fields
		args      args
		afterFunc func() error
		want      *AccessTokenResponse
		wantErr   error
	}
	tests := []test{
		func() test {
			dummyTok := "dummyToken"
			dummyExpTime := int64(999999999)
			dummyToken := fmt.Sprintf(`{"access_token":"%v","token_type":"Bearer","expires_in":%v,"scope":"dummyDomain:dummyRole"}"`, dummyTok, dummyExpTime)

			var sampleHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, dummyToken)
			})
			dummyServer := httptest.NewTLSServer(sampleHandler)

			var httpClient atomic.Value
			httpClient.Store(dummyServer.Client())
			return test{
				name: "getAccessToken returns correct",
				fields: fields{
					httpClient: httpClient,
					tokenCache: gache.New(),
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
					expiresIn:         1,
				},
				afterFunc: func() error {
					dummyServer.Close()
					return nil
				},
				want: &AccessTokenResponse{
					AccessToken: dummyTok,
					TokenType:   "Bearer",
					Scope:       "dummyDomain:dummyRole",
					ExpiresIn:   dummyExpTime,
				},
			}
		}(),
		func() test {
			var sampleHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			})
			dummyServer := httptest.NewTLSServer(sampleHandler)

			var httpClient atomic.Value
			httpClient.Store(dummyServer.Client())
			return test{
				name: "getAccessToken returns error",
				fields: fields{
					httpClient: httpClient,
					tokenCache: gache.New(),
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
					expiresIn:         1,
				},
				afterFunc: func() error {
					dummyServer.Close()
					return nil
				},
				wantErr: ErrAccessTokenRequestFailed,
			}
		}(),
		func() test {
			dummyTok := "dummyToken"
			dummyExpTime := int64(999999999)
			dummyAccessToken := &AccessTokenResponse{
				AccessToken: dummyTok,
				TokenType:   "Bearer",
				Scope:       "dummyDomain:dummyRole",
				ExpiresIn:   dummyExpTime,
			}
			gac := gache.New()
			gac.Set("dummyDomain;dummyRole;dummyProxy", &accessCacheData{
				token: dummyAccessToken,
			})

			return test{
				name: "getAccessToken return from cache",
				fields: fields{
					tokenCache: gac,
				},
				args: args{
					ctx:               context.Background(),
					domain:            "dummyDomain",
					role:              "dummyRole",
					proxyForPrincipal: "dummyProxy",
				},
				want: dummyAccessToken,
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.afterFunc != nil {
				defer func() {
					err := tt.afterFunc()
					if err != nil {
						t.Errorf("Failed afterFunc %v", err)
					}
				}()
			}

			a := &accessService{
				cfg:                   tt.fields.cfg,
				token:                 tt.fields.token,
				athenzURL:             tt.fields.athenzURL,
				athenzPrincipleHeader: tt.fields.athenzPrincipleHeader,
				tokenCache:            tt.fields.tokenCache,
				expiry:                tt.fields.expiry,
				httpClient:            tt.fields.httpClient,
			}
			got, err := a.getAccessToken(tt.args.ctx, tt.args.domain, tt.args.role, tt.args.proxyForPrincipal, tt.args.expiresIn)
			if tt.wantErr == nil && err != nil {
				t.Errorf("failed to instantiate, err: %v", err)
				return
			} else if tt.wantErr != nil {
				if tt.wantErr.Error() != err.Error() {
					t.Errorf("error not the same, want: %v, got: %v", tt.wantErr, err)
				}
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("accessService.getAccessToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_accessService_RefreshAccessTokenCache(t *testing.T) {
	type fields struct {
		cfg                   config.AccessToken
		token                 ntokend.TokenProvider
		athenzURL             string
		athenzPrincipleHeader string
		tokenCache            gache.Gache
		expiry                time.Duration
		httpClient            atomic.Value
		refreshPeriod         time.Duration
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
				newToken := `{"access_token":"newToken","token_type":"Bearer","expires_in":99999,"scope":"dummyDomain:dummyRole"}"`
				fmt.Fprint(w, newToken)
			})
			dummyServer := httptest.NewTLSServer(sampleHandler)

			tokenCache := gache.New()
			data := &accessCacheData{
				token:             nil,
				domain:            "dummyDomain",
				role:              "dummyRole",
				proxyForPrincipal: "",
				expiresIn:         60,
			}
			tokenCache.SetWithExpire("dummyDomain;dummyRole", data, time.Minute)

			var httpClient atomic.Value
			httpClient.Store(dummyServer.Client())
			return test{
				name: "Refresh access token cache success",
				fields: fields{
					token: func() (string, error) {
						return "dummyNToken", nil
					},
					athenzURL:             dummyServer.URL,
					athenzPrincipleHeader: "dummy",
					tokenCache:            tokenCache,
					expiry:                time.Minute,
					httpClient:            httpClient,
					refreshPeriod:         time.Second,
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

					newCache, ok := tokenCache.Get("dummyDomain;dummyRole")
					if !ok {
						return errors.New("cannot get new token")
					}

					tok := newCache.(*accessCacheData).token
					if tok == nil {
						return errors.New("updated token is nil")
					}
					if tok.AccessToken != "newToken" {
						return errors.New("new token not updated")
					}

					return nil
				},
			}
		}(),
		func() test {
			var sampleHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				newToken := `{"access_token":"newToken","token_type":"Bearer","expires_in":99999,"scope":"dummyDomain:dummyRole"}"`
				fmt.Fprint(w, newToken)
			})
			dummyServer := httptest.NewTLSServer(sampleHandler)

			tokenCache := gache.New()
			data := &accessCacheData{
				token:             nil,
				domain:            "dummyDomain",
				role:              "dummyRole",
				proxyForPrincipal: "",
				expiresIn:         60,
			}
			tokenCache.SetWithExpire("dummyDomain;dummyRole", data, time.Minute)

			data1 := &accessCacheData{
				token:             nil,
				domain:            "dummyDomain1",
				role:              "dummyRole1",
				proxyForPrincipal: "",
				expiresIn:         60,
			}
			tokenCache.SetWithExpire("dummyDomain1;dummyRole1", data1, time.Minute)

			var httpClient atomic.Value
			httpClient.Store(dummyServer.Client())
			return test{
				name: "Refresh multiple access token cache success",
				fields: fields{
					token: func() (string, error) {
						return "dummyNToken", nil
					},
					athenzURL:             dummyServer.URL,
					athenzPrincipleHeader: "dummy",
					tokenCache:            tokenCache,
					expiry:                time.Minute,
					httpClient:            httpClient,
					refreshPeriod:         time.Second,
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
						newCache, ok := tokenCache.Get(k)
						if !ok {
							return errors.New("cannot get new token")
						}

						tok := newCache.(*accessCacheData).token
						if tok == nil {
							return errors.New("updated token is nil")
						}
						if tok.AccessToken != "newToken" {
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
					newToken := `{"access_token":"newToken","token_type":"Bearer","expires_in":99999,"scope":"dummyDomain:dummyRole"}"`
					fmt.Fprint(w, newToken)
				}
				i++
			})
			dummyServer := httptest.NewTLSServer(sampleHandler)

			tokenCache := gache.New()
			data := &accessCacheData{
				token:             nil,
				domain:            "dummyDomain",
				role:              "dummyRole",
				proxyForPrincipal: "dummyProxy",
				expiresIn:         60,
			}
			tokenCache.SetWithExpire("dummyDomain;dummyRole;dummyProxy", data, time.Minute)

			var httpClient atomic.Value
			httpClient.Store(dummyServer.Client())
			return test{
				name: "RefreshAccessTokenCache success with retry",
				fields: fields{
					httpClient: httpClient,
					tokenCache: tokenCache,
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
						errs = append(errs, err)
					}

					// check the length
					if len(errs) != 3 {
						return errors.Errorf("len(err) = %v, errors: %v", len(errs), errs)
					}

					// check errors
					for _, err := range errs {
						if err != ErrAccessTokenRequestFailed {
							return errors.Errorf("Unexpected error: %v", err)
						}
					}

					tok, ok := tokenCache.Get("dummyDomain;dummyRole;dummyProxy")
					if !ok {
						return errors.New("token does not set to the cache")
					}

					if tok.(*accessCacheData).token.AccessToken != dummyTok {
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

			tokenCache := gache.New()
			data := &accessCacheData{
				token: &AccessTokenResponse{
					AccessToken: dummyTok,
					TokenType:   "Bearer",
					Scope:       "dummyDomain:dummyRole",
					ExpiresIn:   int64(99999999),
				},
				domain:            "dummyDomain",
				role:              "dummyRole",
				proxyForPrincipal: "dummyProxy",
				expiresIn:         60,
			}
			tokenCache.SetWithExpire("dummyDomain;dummyRole;dummyProxy", data, time.Minute)

			var httpClient atomic.Value
			httpClient.Store(dummyServer.Client())
			return test{
				name: "RefreshAccessTokenCache failed",
				fields: fields{
					httpClient: httpClient,
					tokenCache: tokenCache,
					token: func() (string, error) {
						return "dummyToken", nil
					},
					athenzURL:             dummyServer.URL,
					athenzPrincipleHeader: "Athenz-Principal",
					errRetryMaxCount:      9,
				},
				args: args{
					ctx: context.Background(),
				},
				checkFunc: func(echan <-chan error) error {
					errs := make([]error, 0, 10)
					for err := range echan {
						errs = append(errs, err)
					}

					// check the length
					if len(errs) != 10 {
						return errors.Errorf("len(err) = %v, errors: %v", len(errs), errs)
					}

					// check errors
					for _, err := range errs {
						if err != ErrAccessTokenRequestFailed {
							return errors.Errorf("Unexpected error: %v", err)
						}
					}

					// the cache will not be deleted even the fetch is failed
					tok, ok := tokenCache.Get("dummyDomain;dummyRole;dummyProxy")
					if !ok {
						return errors.New("token does not set to the cache")
					}

					if tok.(*accessCacheData).token.AccessToken != dummyTok {
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
				defer func() {
					err := tt.afterFunc()
					if err != nil {
						t.Errorf("Failed afterFunc %v", err)
					}
				}()
			}
			a := &accessService{
				cfg:                   tt.fields.cfg,
				token:                 tt.fields.token,
				athenzURL:             tt.fields.athenzURL,
				athenzPrincipleHeader: tt.fields.athenzPrincipleHeader,
				tokenCache:            tt.fields.tokenCache,
				expiry:                tt.fields.expiry,
				httpClient:            tt.fields.httpClient,
				refreshPeriod:         tt.fields.refreshPeriod,
				errRetryMaxCount:      tt.fields.errRetryMaxCount,
				errRetryInterval:      tt.fields.errRetryInterval,
			}
			got := a.RefreshAccessTokenCache(tt.args.ctx)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("accessService.RefreshAccessTokenCache() error: %s", err)
			}
		})
	}
}

func Test_accessService_updateAccessTokenWithRetry(t *testing.T) {
	type fields struct {
		cfg                   config.AccessToken
		token                 ntokend.TokenProvider
		athenzURL             string
		athenzPrincipleHeader string
		tokenCache            gache.Gache
		expiry                time.Duration
		httpClient            atomic.Value
		refreshPeriod         time.Duration
		errRetryMaxCount      int
		errRetryInterval      time.Duration
	}
	type args struct {
		ctx               context.Context
		domain            string
		role              string
		proxyForPrincipal string
		expiresIn         int64
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
			dummyTok := "dummyToken"
			dummyExpTime := int64(999999999)
			dummyToken := fmt.Sprintf(`{"access_token":"%v","token_type":"Bearer","expires_in":%v,"scope":"dummyDomain:dummyRole"}"`, dummyTok, dummyExpTime)

			var sampleHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, dummyToken)
			})
			dummyServer := httptest.NewTLSServer(sampleHandler)

			tokenCache := gache.New()

			var httpClient atomic.Value
			httpClient.Store(dummyServer.Client())
			return test{
				name: "updateAccessTokenWithRetry success",
				fields: fields{
					httpClient: httpClient,
					tokenCache: tokenCache,
					token: func() (string, error) {
						return dummyToken, nil
					},
					athenzURL:             dummyServer.URL,
					athenzPrincipleHeader: "Athenz-Principal",
					errRetryMaxCount:      9,
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

					tok, ok := tokenCache.Get("dummyDomain;dummyRole;dummyProxy")
					if !ok {
						return errors.New("token is not set to the cache")
					}

					if tok.(*accessCacheData).token.AccessToken != dummyTok {
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
			dummyToken := fmt.Sprintf(`{"access_token":"%v","token_type":"Bearer","expires_in":%v,"scope":"dummyDomain:dummyRole"}"`, dummyTok, dummyExpTime)

			i := 0
			var sampleHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if i < 3 {
					w.WriteHeader(http.StatusInternalServerError)
				} else {
					fmt.Fprint(w, dummyToken)
				}
				i++
			})
			dummyServer := httptest.NewTLSServer(sampleHandler)

			tokenCache := gache.New()

			var httpClient atomic.Value
			httpClient.Store(dummyServer.Client())
			return test{
				name: "updateAccessTokenWithRetry success with retry",
				fields: fields{
					httpClient: httpClient,
					tokenCache: tokenCache,
					token: func() (string, error) {
						return dummyToken, nil
					},
					athenzURL:             dummyServer.URL,
					athenzPrincipleHeader: "Athenz-Principal",
					errRetryMaxCount:      9,
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
						errs = append(errs, err)
					}

					// check the length
					if len(errs) != 3 {
						return errors.Errorf("len(err) = %v", len(errs))
					}

					// check errors
					for _, err := range errs {
						if err != ErrAccessTokenRequestFailed {
							return errors.Errorf("Unexpected error: %v", err)
						}
					}

					tok, ok := tokenCache.Get("dummyDomain;dummyRole;dummyProxy")
					if !ok {
						return errors.New("token is not set to the cache")
					}

					if tok.(*accessCacheData).token.AccessToken != dummyTok {
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

			tokenCache := gache.New()

			var httpClient atomic.Value
			httpClient.Store(dummyServer.Client())
			return test{
				name: "updateAccessTokenWithRetry returns error",
				fields: fields{
					httpClient: httpClient,
					tokenCache: tokenCache,
					token: func() (string, error) {
						return dummyToken, nil
					},
					athenzURL:             dummyServer.URL,
					athenzPrincipleHeader: "Athenz-Principal",
					errRetryMaxCount:      9,
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
						errs = append(errs, err)
					}

					// check the length
					if len(errs) != 10 {
						return errors.Errorf("len(err) = %v", len(errs))
					}

					// check errors
					for _, err := range errs {
						if err != ErrAccessTokenRequestFailed {
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
			defer func() {
				err := tt.afterFunc()
				if err != nil {
					t.Errorf("Failed afterFunc %v", err)
				}
			}()
			a := &accessService{
				cfg:                   tt.fields.cfg,
				token:                 tt.fields.token,
				athenzURL:             tt.fields.athenzURL,
				athenzPrincipleHeader: tt.fields.athenzPrincipleHeader,
				tokenCache:            tt.fields.tokenCache,
				expiry:                tt.fields.expiry,
				httpClient:            tt.fields.httpClient,
				refreshPeriod:         tt.fields.refreshPeriod,
				errRetryMaxCount:      tt.fields.errRetryMaxCount,
				errRetryInterval:      tt.fields.errRetryInterval,
			}
			got := a.updateAccessTokenWithRetry(tt.args.ctx, tt.args.domain, tt.args.role, tt.args.proxyForPrincipal, tt.args.expiresIn)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("accessService.updateAccessTokenWithRetry(). error: %v", err)
			}
		})
	}
}

func Test_accessService_updateAccessToken(t *testing.T) {
	type fields struct {
		cfg                   config.AccessToken
		token                 ntokend.TokenProvider
		athenzURL             string
		athenzPrincipleHeader string
		tokenCache            gache.Gache
		expiry                time.Duration
		httpClient            atomic.Value
	}
	type args struct {
		ctx               context.Context
		domain            string
		role              string
		proxyForPrincipal string
		expiresIn         int64
	}
	type test struct {
		name      string
		fields    fields
		args      args
		checkFunc func(got, want *AccessTokenResponse) error
		afterFunc func() error
		want      *AccessTokenResponse
		wantErr   error
	}
	tests := []test{
		func() test {
			dummyTok := "dummyToken"
			dummyExpTime := int64(999999999)
			dummyToken := fmt.Sprintf(`{"access_token":"%v","token_type":"Bearer","expires_in":%v,"scope":"dummyDomain:dummyRole"}"`, dummyTok, dummyExpTime)

			var sampleHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, dummyToken)
			})
			dummyServer := httptest.NewTLSServer(sampleHandler)

			var httpClient atomic.Value
			httpClient.Store(dummyServer.Client())
			return test{
				name: "updateAccessToken returns correct",
				fields: fields{
					httpClient: httpClient,
					tokenCache: gache.New(),
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
					expiresIn:         1,
				},
				afterFunc: func() error {
					dummyServer.Close()
					return nil
				},
				want: &AccessTokenResponse{
					AccessToken: dummyTok,
					TokenType:   "Bearer",
					Scope:       "dummyDomain:dummyRole",
					ExpiresIn:   dummyExpTime,
				},
			}
		}(),
		func() test {
			dummyErr := fmt.Errorf("Dummy error")

			return test{
				name: "updateAccessToken token returns error",
				fields: fields{
					httpClient: atomic.Value{},
					tokenCache: gache.New(),
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
					expiresIn:         1,
				},
				wantErr: dummyErr,
			}
		}(),
		func() test {
			dummyTok := "dummyToken"
			dummyExpTime := int64(999999999)
			dummyToken := fmt.Sprintf(`{"access_token":"%v","token_type":"Bearer","expires_in":%v,"scope":"dummyDomain:dummyRole"}"`, dummyTok, dummyExpTime)

			var sampleHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, dummyToken)
			})
			dummyServer := httptest.NewTLSServer(sampleHandler)

			var httpClient atomic.Value
			httpClient.Store(dummyServer.Client())
			return test{
				name: "updateAccessToken new request returns error",
				fields: fields{
					httpClient: httpClient,
					tokenCache: gache.New(),
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
					expiresIn:         1,
				},
				wantErr: fmt.Errorf(`Post "https://127.0.0.1:9876/oauth2/token": dial tcp 127.0.0.1:9876: connect: connection refused`),
			}
		}(),
		func() test {
			dummyTok := "dummyToken"
			dummyExpTime := int64(999999999)
			dummyToken := fmt.Sprintf(`{"access_token":"%v","token_type":"Bearer","expires_in":%v,"scope":"dummyDomain:dummyRole"}"`, dummyTok, dummyExpTime)

			var sampleHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			})
			dummyServer := httptest.NewTLSServer(sampleHandler)

			var httpClient atomic.Value
			httpClient.Store(dummyServer.Client())
			return test{
				name: "updateAccessToken get token error",
				fields: fields{
					httpClient: httpClient,
					tokenCache: gache.New(),
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
					expiresIn:         1,
				},
				afterFunc: func() error {
					dummyServer.Close()
					return nil
				},
				wantErr: ErrAccessTokenRequestFailed,
			}
		}(),
		func() test {
			dummyToken := "dummyToken"

			var sampleHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, dummyToken)
			})
			dummyServer := httptest.NewTLSServer(sampleHandler)

			var httpClient atomic.Value
			httpClient.Store(dummyServer.Client())
			return test{
				name: "updateAccessToken decode token error",
				fields: fields{
					httpClient: httpClient,
					tokenCache: gache.New(),
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
					expiresIn:         1,
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
			dummyExpTime := fastime.Now().Add(time.Hour).UTC()
			dummyToken := fmt.Sprintf(`{"access_token":"%v","token_type":"Bearer","expires_in":%v,"scope":"dummyDomain:dummyRole"}"`, dummyTok, dummyExpTime.Unix())

			var sampleHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, dummyToken)
			})
			dummyServer := httptest.NewTLSServer(sampleHandler)

			tokenCache := gache.New()

			var httpClient atomic.Value
			httpClient.Store(dummyServer.Client())
			return test{
				name: "updateAccessToken set token in cache",
				fields: fields{
					httpClient: httpClient,
					tokenCache: tokenCache,
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
					expiresIn:         1,
				},
				checkFunc: func(got, want *AccessTokenResponse) error {
					c, exp, ok := tokenCache.GetWithExpire("dummyDomain;dummyRole;dummyProxy")
					if !ok {
						return fmt.Errorf("element cannot found in cache")
					}
					if c.(*accessCacheData).token.AccessToken != dummyTok {
						return fmt.Errorf("token not matched, got: %v, want: %v", c, dummyTok)
					}

					if math.Abs(time.Unix(0, exp).Sub(dummyExpTime).Seconds()) > (time.Minute+(time.Second*3)).Seconds()*3 {
						return errors.Errorf("cache expiry not match with policy expires, got: %d", exp)
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
			dummyExpTime := fastime.Now().Add(time.Hour).UTC()
			dummyToken := fmt.Sprintf(`{"access_token":"%v","token_type":"Bearer","expires_in":%v,"scope":"dummyDomain:dummyRole"}"`, dummyTok, dummyExpTime.Unix())

			// create a dummy server that returns a dummy token
			var sampleHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, dummyToken)
			})
			dummyServer := httptest.NewTLSServer(sampleHandler)

			tokenCache := gache.New()

			// set another dummy token and see if it is updated
			dummyTok2 := "dummyToken2"
			dummyToken2 := fmt.Sprintf(`{"access_token":"%v","token_type":"Bearer","expires_in":%v,"scope":"dummyDomain:dummyRole"}"`, dummyTok2, dummyExpTime.Unix())
			dummyAccessToke2 := &AccessTokenResponse{
				AccessToken: dummyToken2,
				TokenType:   "Bearer",
				Scope:       "dummyDomain:dummyRole",
				ExpiresIn:   dummyExpTime.UnixNano() / int64(time.Second),
			}
			tokenCache.SetWithExpire("dummyDomain;dummyRole", &accessCacheData{
				token: dummyAccessToke2,
			}, time.Second)

			var httpClient atomic.Value
			httpClient.Store(dummyServer.Client())
			return test{
				name: "updateAccessToken update token in cache",
				fields: fields{
					httpClient: httpClient,
					tokenCache: tokenCache,
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
					expiresIn:         1,
				},
				checkFunc: func(got, want *AccessTokenResponse) error {
					tok, exp, ok := tokenCache.GetWithExpire("dummyDomain;dummyRole;dummyProxy")
					if !ok {
						return fmt.Errorf("element cannot found in cache")
					}
					if tok.(*accessCacheData).token.AccessToken != dummyTok {
						return fmt.Errorf("Token not updated")
					}

					if math.Abs(time.Unix(0, exp).Sub(dummyExpTime).Seconds()) > (time.Minute+(time.Second*3)).Seconds()*3 {
						return errors.Errorf("cache expiry not match with policy expires, got: %d", exp)
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
			defer func() {
				err := tt.afterFunc()
				if err != nil {
					t.Errorf("Failed afterFunc %v", err)
				}
			}()
		}
		t.Run(tt.name, func(t *testing.T) {
			a := &accessService{
				cfg:                   tt.fields.cfg,
				token:                 tt.fields.token,
				athenzURL:             tt.fields.athenzURL,
				athenzPrincipleHeader: tt.fields.athenzPrincipleHeader,
				tokenCache:            tt.fields.tokenCache,
				expiry:                tt.fields.expiry,
				httpClient:            tt.fields.httpClient,
			}

			got, err := a.updateAccessToken(tt.args.ctx, tt.args.domain, tt.args.role, tt.args.proxyForPrincipal, tt.args.expiresIn)
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
					t.Errorf("accessService.updateAccessToken() = %v", err)
				}
			} else {
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("accessService.updateAccessToken() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func Test_accessService_fetchAccessToken(t *testing.T) {
	type fields struct {
		cfg                   config.AccessToken
		token                 ntokend.TokenProvider
		athenzURL             string
		athenzPrincipleHeader string
		tokenCache            gache.Gache
		expiry                time.Duration
		httpClient            atomic.Value
		rootCAs               *x509.CertPool
		certPath              string
		certKeyPath           string
		refreshPeriod         time.Duration
		errRetryMaxCount      int
		errRetryInterval      time.Duration
	}
	type args struct {
		ctx               context.Context
		domain            string
		role              string
		proxyForPrincipal string
		expiry            int64
	}
	type test struct {
		name      string
		fields    fields
		args      args
		want      *AccessTokenResponse
		wantErr   error
		afterFunc func() error
	}
	tests := []test{
		{
			name: "fetch access token error, invalid TLS",
			fields: fields{
				httpClient:  atomic.Value{},
				certPath:    "../test/data/invalid_dummyServer.crt",
				certKeyPath: "../test/data/invalid_dummyServer.key",
			},
			args: args{
				ctx:               context.Background(),
				domain:            "dummyDomain",
				role:              "dummyRole",
				proxyForPrincipal: "dummyProxy",
				expiry:            3600,
			},
			wantErr: errors.New("tls: failed to find any PEM data in certificate input"),
		},
		{
			name: "fetch access token error, no credentials",
			fields: fields{
				httpClient: atomic.Value{},
			},
			args: args{
				ctx:               context.Background(),
				domain:            "dummyDomain",
				role:              "dummyRole",
				proxyForPrincipal: "dummyProxy",
				expiry:            3600,
			},
			wantErr: ErrNoCredentials,
		},
		func() test {
			dummyTok := "dummyToken"
			dummyExpTime := int64(999999999)
			dummyToken := fmt.Sprintf(`{"access_token":"%v","token_type":"Bearer","expires_in":%v,"scope":"dummyDomain:dummyRole"}"`, dummyTok, dummyExpTime)

			var sampleHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.TLS.PeerCertificates == nil || r.TLS.PeerCertificates[0].Subject.CommonName != "athenz.test.syncer" {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				fmt.Fprint(w, dummyToken)
				w.WriteHeader(http.StatusOK)
			})
			dummyServer := httptest.NewUnstartedServer(sampleHandler)
			serverTLSCfg, err := NewTLSConfig(config.TLS{
				CertPath: "../test/data/dummyServer.crt",
				KeyPath:  "../test/data/dummyServer.key",
				CAPath:   "../test/data/dummyClient.crt",
			})
			if err != nil {
				panic(err)
			}
			clientCACp, err := NewX509CertPool("../test/data/dummyServer.crt")
			if err != nil {
				panic(err)
			}

			dummyServer.TLS = serverTLSCfg
			dummyServer.StartTLS()

			var httpClient atomic.Value
			httpClient.Store(dummyServer.Client())
			return test{
				name: "fetch access token success with client certificate",
				fields: fields{
					athenzURL:             dummyServer.URL,
					athenzPrincipleHeader: "dummy-header",
					httpClient:            httpClient,
					rootCAs:               clientCACp,
					certPath:              "../test/data/dummyClient.crt",
					certKeyPath:           "../test/data/dummyClient.key",
				},
				args: args{
					ctx:               context.Background(),
					domain:            "dummyDomain",
					role:              "dummyRole",
					proxyForPrincipal: "dummyProxy",
					expiry:            3600,
				},
				want: &AccessTokenResponse{
					AccessToken: dummyTok,
					TokenType:   "Bearer",
					Scope:       "dummyDomain:dummyRole",
					ExpiresIn:   dummyExpTime,
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
			dummyToken := fmt.Sprintf(`{"access_token":"%v","token_type":"Bearer","expires_in":%v,"scope":"dummyDomain:dummyRole"}"`, dummyTok, dummyExpTime)

			var sampleHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, dummyToken)
				w.WriteHeader(http.StatusOK)
			})
			dummyServer := httptest.NewTLSServer(sampleHandler)

			var httpClient atomic.Value
			httpClient.Store(dummyServer.Client())
			return test{
				name: "fetch access token success with ntoken",
				fields: fields{
					token: func() (string, error) {
						return "dummyNtoken", nil
					},
					athenzURL:             dummyServer.URL,
					athenzPrincipleHeader: "dummy-header",
					httpClient:            httpClient,
				},
				args: args{
					ctx:               context.Background(),
					domain:            "dummyDomain",
					role:              "dummyRole",
					proxyForPrincipal: "dummyProxy",
					expiry:            3600,
				},
				want: &AccessTokenResponse{
					AccessToken: dummyTok,
					TokenType:   "Bearer",
					Scope:       "dummyDomain:dummyRole",
					ExpiresIn:   dummyExpTime,
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
			dummyToken := fmt.Sprintf(`{"access_token":"%v","token_type":"Bearer","expires_in":%v,"scope":"dummyDomain:dummyRole"}"`, dummyTok, dummyExpTime)

			var sampleHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, dummyToken)
				w.WriteHeader(http.StatusOK)
			})
			dummyServer := httptest.NewTLSServer(sampleHandler)

			dummyErr := errors.New("dummy error")
			var httpClient atomic.Value
			httpClient.Store(dummyServer.Client())
			return test{
				name: "N-token provider return error",
				fields: fields{
					token: func() (string, error) {
						return "", dummyErr
					},
					athenzURL:             dummyServer.URL,
					athenzPrincipleHeader: "dummy-header",
					httpClient:            httpClient,
				},
				args: args{
					ctx:               context.Background(),
					domain:            "dummyDomain",
					role:              "dummyRole",
					proxyForPrincipal: "dummyProxy",
					expiry:            3600,
				},
				wantErr: dummyErr,
				afterFunc: func() error {
					dummyServer.Close()
					return nil
				},
			}
		}(),
		func() test {
			var sampleHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			})
			dummyServer := httptest.NewTLSServer(sampleHandler)

			var httpClient atomic.Value
			httpClient.Store(dummyServer.Client())
			return test{
				name: "Athenz server return error",
				fields: fields{
					token: func() (string, error) {
						return "dummyNToken", nil
					},
					athenzURL:             dummyServer.URL,
					athenzPrincipleHeader: "dummy-header",
					httpClient:            httpClient,
				},
				args: args{
					ctx:               context.Background(),
					domain:            "dummyDomain",
					role:              "dummyRole",
					proxyForPrincipal: "dummyProxy",
					expiry:            3600,
				},
				wantErr: ErrAccessTokenRequestFailed,
				afterFunc: func() error {
					dummyServer.Close()
					return nil
				},
			}
		}(),
		func() test {
			dummyTok := "dummyToken"

			var sampleHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, dummyTok)
				w.WriteHeader(http.StatusOK)
			})
			dummyServer := httptest.NewTLSServer(sampleHandler)

			var httpClient atomic.Value
			httpClient.Store(dummyServer.Client())
			return test{
				name: "Athenz server return invalid access token",
				fields: fields{
					token: func() (string, error) {
						return "dummyNToken", nil
					},
					athenzURL:             dummyServer.URL,
					athenzPrincipleHeader: "dummy-header",
					httpClient:            httpClient,
				},
				args: args{
					ctx:               context.Background(),
					domain:            "dummyDomain",
					role:              "dummyRole",
					proxyForPrincipal: "dummyProxy",
					expiry:            3600,
				},
				wantErr: errors.New("invalid character 'd' looking for beginning of value"),
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
				defer func() {
					err := tt.afterFunc()
					if err != nil {
						t.Errorf("Failed afterFunc %v", err)
					}
				}()
			}
			a := &accessService{
				cfg:                   tt.fields.cfg,
				token:                 tt.fields.token,
				athenzURL:             tt.fields.athenzURL,
				athenzPrincipleHeader: tt.fields.athenzPrincipleHeader,
				tokenCache:            tt.fields.tokenCache,
				expiry:                tt.fields.expiry,
				httpClient:            tt.fields.httpClient,
				rootCAs:               tt.fields.rootCAs,
				certPath:              tt.fields.certPath,
				certKeyPath:           tt.fields.certKeyPath,
				refreshPeriod:         tt.fields.refreshPeriod,
				errRetryMaxCount:      tt.fields.errRetryMaxCount,
				errRetryInterval:      tt.fields.errRetryInterval,
			}
			got, err := a.fetchAccessToken(tt.args.ctx, tt.args.domain, tt.args.role, tt.args.proxyForPrincipal, tt.args.expiry)
			if err != nil {
				if tt.wantErr == nil {
					t.Errorf("accessService.fetchAccessToken() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if err.Error() != tt.wantErr.Error() {
					t.Errorf("accessService.fetchAccessToken() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
			} else if tt.wantErr != nil {
				t.Errorf("accessService.fetchAccessToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("accessService.fetchAccessToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_createScope(t *testing.T) {
	type args struct {
		domain string
		role   string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "createScope single role",
			args: args{
				domain: "dummyDomain",
				role:   "dummyRole",
			},
			want: "dummyDomain:role.dummyRole",
		},
		{
			name: "createScope multi role",
			args: args{
				domain: "dummyDomain",
				role:   "dummyRole1,dummyRole2",
			},
			want: "dummyDomain:role.dummyRole1 dummyDomain:role.dummyRole2",
		},
		{
			name: "createScope empty role",
			args: args{
				domain: "dummyDomain",
			},
			want: "dummyDomain:domain",
		},
		{
			name: "createScope empty domain",
			args: args{
				role: "dummyRole1,dummyRole2",
			},
			want: ":role.dummyRole1 :role.dummyRole2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := createScope(tt.args.domain, tt.args.role); got != tt.want {
				t.Errorf("createScope() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_accessService_getCache(t *testing.T) {
	type fields struct {
		cfg                   config.AccessToken
		token                 ntokend.TokenProvider
		athenzURL             string
		athenzPrincipleHeader string
		tokenCache            gache.Gache
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
		want   *AccessTokenResponse
		want1  bool
	}
	tests := []test{
		func() test {
			return test{
				name: "getCache return not ok (cache not exist)",
				fields: fields{
					tokenCache: gache.New(),
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

			accessToken := &AccessTokenResponse{
				AccessToken: dummyToken,
				TokenType:   "Bearer",
				Scope:       "dummyDomain:dummyRole",
				ExpiresIn:   dummyExpTime,
			}

			tokenCache := gache.New()
			tokenCache.Set("dummyDomain;dummyRole;principal", &accessCacheData{
				token: accessToken,
			})

			return test{
				name: "getCache return cache value",
				fields: fields{
					tokenCache: tokenCache,
				},
				args: args{
					domain:    "dummyDomain",
					role:      "dummyRole",
					principal: "principal",
				},
				want:  accessToken,
				want1: true,
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &accessService{
				cfg:                   tt.fields.cfg,
				token:                 tt.fields.token,
				athenzURL:             tt.fields.athenzURL,
				athenzPrincipleHeader: tt.fields.athenzPrincipleHeader,
				tokenCache:            tt.fields.tokenCache,
				expiry:                tt.fields.expiry,
			}
			got, got1 := a.getCache(tt.args.domain, tt.args.role, tt.args.principal)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("accessService.getCache() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("accessService.getCache() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func Test_accessService_createPostAccessTokenRequest(t *testing.T) {
	type fields struct {
		cfg                   config.AccessToken
		token                 ntokend.TokenProvider
		athenzURL             string
		athenzPrincipleHeader string
		tokenCache            gache.Gache
		expiry                time.Duration
	}
	type args struct {
		scope             string
		proxyForPrincipal string
		expiry            int64
		token             string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *http.Request
		wantErr error
	}{
		{
			name: "createPostAccessTokenRequest correct",
			args: args{
				scope:             "dummyDomain:dummyRole",
				proxyForPrincipal: "dummyProxyForPrincipal",
				expiry:            1,
				token:             "dummyToken",
			},
			fields: fields{
				athenzURL:             "dummyAthenzURL",
				athenzPrincipleHeader: "dummyHeader",
			},
			want: func() *http.Request {
				q := url.Values{}
				q.Add("grant_type", "client_credentials")
				q.Add("scope", "dummyDomain:dummyRole")
				q.Add("proxy_for_principal", "dummyProxyForPrincipal")
				q.Add("expires_in", "1")

				r, _ := http.NewRequest(http.MethodPost, "https://dummyAthenzURL/oauth2/token", strings.NewReader(q.Encode()))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return r
			}(),
		},
		{
			name: "createPostAccessTokenRequest correct null expiry use default",
			args: args{
				scope:             "dummyDomain:dummyRole",
				proxyForPrincipal: "dummyProxyForPrincipal",
				token:             "dummyToken",
			},
			fields: fields{
				athenzURL:             "dummyAthenzURL",
				athenzPrincipleHeader: "dummyHeader",
				expiry:                time.Minute,
			},
			want: func() *http.Request {
				q := url.Values{}
				q.Add("grant_type", "client_credentials")
				q.Add("scope", "dummyDomain:dummyRole")
				q.Add("proxy_for_principal", "dummyProxyForPrincipal")
				q.Add("expires_in", "60")

				r, _ := http.NewRequest(http.MethodPost, "https://dummyAthenzURL/oauth2/token", strings.NewReader(q.Encode()))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return r
			}(),
		},
		{
			name: "createPostAccessTokenRequest correct null proxyForPrincipal",
			args: args{
				scope:  "dummyDomain:dummyRole",
				expiry: 1,
				token:  "dummyToken",
			},
			fields: fields{
				athenzURL:             "dummyAthenzURL",
				athenzPrincipleHeader: "dummyHeader",
			},
			want: func() *http.Request {
				q := url.Values{}
				q.Add("grant_type", "client_credentials")
				q.Add("scope", "dummyDomain:dummyRole")
				q.Add("expires_in", "1")

				r, _ := http.NewRequest(http.MethodPost, "https://dummyAthenzURL/oauth2/token", strings.NewReader(q.Encode()))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return r
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &accessService{
				cfg:                   tt.fields.cfg,
				token:                 tt.fields.token,
				athenzURL:             tt.fields.athenzURL,
				athenzPrincipleHeader: tt.fields.athenzPrincipleHeader,
				tokenCache:            tt.fields.tokenCache,
				expiry:                tt.fields.expiry,
			}
			got, err := a.createPostAccessTokenRequest(tt.args.scope, tt.args.proxyForPrincipal, tt.args.expiry)
			gotBody, readErr := ioutil.ReadAll(got.Body)
			if readErr != nil {
				t.Errorf("createPostAccessTokenRequest() err: %v", err)
			}
			wantBody, readErr := ioutil.ReadAll(tt.want.Body)
			if readErr != nil {
				t.Errorf("createPostAccessTokenRequest() err: %v", err)
			}
			if got.URL.String() != tt.want.URL.String() ||
				!reflect.DeepEqual(got.Header, tt.want.Header) ||
				string(gotBody) != string(wantBody) {

				t.Errorf("createPostAccessTokenRequest(), got: %+v, want: %+v", got, tt.want)
			}
			if err != tt.wantErr {
				t.Errorf("createPostAccessTokenRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}
