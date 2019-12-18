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
package usecase

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	ntokend "github.com/kpango/ntokend"
	"github.com/yahoojapan/athenz-client-sidecar/config"
	"github.com/yahoojapan/athenz-client-sidecar/handler"
	"github.com/yahoojapan/athenz-client-sidecar/infra"
	"github.com/yahoojapan/athenz-client-sidecar/router"
	"github.com/yahoojapan/athenz-client-sidecar/service"
)

func TestNew(t *testing.T) {
	type args struct {
		cfg config.Config
	}
	type test struct {
		name       string
		args       args
		beforeFunc func()
		checkFunc  func(Tenant, Tenant) error
		afterFunc  func()
		want       Tenant
		wantErr    error
	}
	tests := []test{
		{
			name: "Check error when new token service",
			args: args{
				cfg: config.Config{
					Token: config.Token{},
				},
			},
			wantErr: fmt.Errorf("invalid token refresh duration , time: invalid duration "),
		},
		func() test {
			keyKey := "_dummyKey_"
			key := "./assets/dummyServer.key"
			cfg := config.Config{
				Token: config.Token{
					AthenzDomain:    strings.TrimPrefix(strings.TrimSuffix(keyKey, "_"), "_"),
					ServiceName:     strings.TrimPrefix(strings.TrimSuffix(keyKey, "_"), "_"),
					PrivateKeyPath:  key,
					ValidateToken:   false,
					RefreshDuration: "1m",
					KeyVersion:      "1",
					Expiration:      "1m",
					NTokenPath:      "",
				},
				Server: config.Server{
					HealthzPath: "/dummyPath",
				},
				ServiceCert: config.ServiceCert{
					Enable: true,
				},
			}

			return test{
				name: "Check success",
				args: args{
					cfg: cfg,
				},
				want: func() Tenant {
					os.Setenv(strings.TrimPrefix(strings.TrimSuffix(keyKey, "_"), "_"), key)
					defer os.Unsetenv(strings.TrimPrefix(strings.TrimSuffix(keyKey, "_"), "_"))
					token, err := createNtokend(cfg.Token)
					if err != nil {
						panic(err)
					}
					role := service.NewRoleService(cfg.Role, token.GetTokenProvider())

					h := handler.New(
						cfg.Proxy,
						infra.NewBuffer(cfg.Proxy.BufferSize),
						token.GetTokenProvider(),
						role.GetRoleProvider(),
					)

					var svccert service.SvcCertService
					if cfg.ServiceCert.Enable {
						svccert, _ = service.NewSvcCertService(cfg, token.GetTokenProvider())
						h.EnableSvcCert(svccert.GetSvcCertProvider())
					}

					serveMux := router.New(cfg, h)
					server := service.NewServer(
						service.WithServerConfig(cfg.Server),
						service.WithServerHandler(serveMux),
					)

					return &clientd{
						cfg:    cfg,
						token:  token,
						server: server,
						role:   role,
					}
				}(),
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.beforeFunc != nil {
				tt.beforeFunc()
			}
			if tt.afterFunc != nil {
				defer tt.afterFunc()
			}

			got, err := New(tt.args.cfg)
			if tt.wantErr == nil && err != nil {
				t.Errorf("failed to instantiate, err: %v", err)
				return
			} else if tt.wantErr != nil {
				if tt.wantErr.Error() != err.Error() {
					t.Errorf("error not the same, want: %v, got: %v", tt.wantErr, err)
				}
			}

			if tt.checkFunc != nil {
				err = tt.checkFunc(got, tt.want)
				if tt.wantErr == nil && err != nil {
					t.Errorf("compare check failed, err: %v", err)
					return
				}
			}
		})
	}
}

func Test_clientd_Start(t *testing.T) {
	type fields struct {
		cfg     config.Config
		token   ntokend.TokenService
		server  service.Server
		role    service.RoleService
		svccert service.SvcCertService
	}
	type args struct {
		ctx context.Context
	}
	type test struct {
		name       string
		fields     fields
		args       args
		beforeFunc func() error
		checkFunc  func(chan []error, []error) error
		afterFunc  func()
		want       []error
	}
	tests := []test{
		func() test {
			keyKey := "_dummyKey_"
			key := "./assets/dummyServer.key"

			certKey := "_dummy_cert_"
			cert := "./assets/dummyServer.crt"

			cfg := config.Config{
				Token: config.Token{
					AthenzDomain:    strings.TrimPrefix(strings.TrimSuffix(keyKey, "_"), "_"),
					ServiceName:     strings.TrimPrefix(strings.TrimSuffix(keyKey, "_"), "_"),
					PrivateKeyPath:  key,
					ValidateToken:   false,
					RefreshDuration: "1m",
					KeyVersion:      "1",
					Expiration:      "1m",
					NTokenPath:      "",
				},
				Server: config.Server{
					HealthzPath: "/dummyPath",
					TLS: config.TLS{
						Enabled: true,
						Cert:    certKey,
						Key:     keyKey,
					},
				},
				ServiceCert: config.ServiceCert{
					AthenzRootCA:    "./assets/dummyCa.pem",
					RefreshDuration: "",
				},
			}

			ctx, cancelFunc := context.WithCancel(context.Background())

			os.Setenv(strings.TrimPrefix(strings.TrimSuffix(keyKey, "_"), "_"), key)
			os.Setenv(strings.TrimPrefix(strings.TrimSuffix(certKey, "_"), "_"), cert)

			return test{
				name: "Token updater works",
				fields: func() fields {
					token, err := createNtokend(cfg.Token)
					if err != nil {
						panic(err)
					}
					role := service.NewRoleService(cfg.Role, token.GetTokenProvider())
					h := handler.New(
						cfg.Proxy,
						infra.NewBuffer(cfg.Proxy.BufferSize),
						token.GetTokenProvider(),
						role.GetRoleProvider(),
					)

					var svccert service.SvcCertService
					if cfg.ServiceCert.Enable {
						svccert, _ := service.NewSvcCertService(cfg, token.GetTokenProvider())
						h.EnableSvcCert(svccert.GetSvcCertProvider())
					}

					serveMux := router.New(cfg, h)
					server := service.NewServer(
						service.WithServerConfig(cfg.Server),
						service.WithServerHandler(serveMux),
					)

					return fields{
						cfg:     cfg,
						token:   token,
						server:  server,
						role:    role,
						svccert: svccert,
					}
				}(),
				args: args{
					ctx: ctx,
				},
				checkFunc: func(got chan []error, want []error) error {
					time.Sleep(time.Millisecond * 200)
					cancelFunc()
					time.Sleep(time.Millisecond * 200)

					gotErr := <-got
					if !reflect.DeepEqual(gotErr, want) {
						return fmt.Errorf("Got: %v, want: %v", gotErr, want)
					}
					return nil
				},
				afterFunc: func() {
					os.Unsetenv(strings.TrimPrefix(strings.TrimSuffix(keyKey, "_"), "_"))
				},
				want: []error{context.Canceled},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.afterFunc != nil {
				defer tt.afterFunc()
			}
			if tt.beforeFunc != nil {
				if err := tt.beforeFunc(); err != nil {
					t.Errorf("Error : %v", err)
					return
				}
			}

			te := &clientd{
				cfg:     tt.fields.cfg,
				token:   tt.fields.token,
				server:  tt.fields.server,
				role:    tt.fields.role,
				svccert: tt.fields.svccert,
			}
			got := te.Start(tt.args.ctx)
			if err := tt.checkFunc(got, tt.want); err != nil {
				t.Errorf("Start function error: %v", err)
			}
		})
	}
}

func Test_createNtokend(t *testing.T) {
	type args struct {
		cfg config.Token
	}
	type test struct {
		name       string
		args       args
		beforeFunc func()
		checkFunc  func(got, want ntokend.TokenService) error
		afterFunc  func()
		want       ntokend.TokenService
		wantErr    error
	}
	tests := []test{
		{
			name: "refresh duration invalid",
			args: args{
				cfg: config.Token{
					RefreshDuration: "dummy",
				},
			},
			wantErr: fmt.Errorf("invalid token refresh duration %s, %v", "dummy", "time: invalid duration dummy"),
		},
		{
			name: "token expiration invalid",
			args: args{
				cfg: config.Token{
					RefreshDuration: "1s",
					Expiration:      "dummy",
				},
			},
			wantErr: fmt.Errorf("invalid token expiration %s, %v", "dummy", "time: invalid duration dummy"),
		},
		func() test {
			keyKey := "_dummyKey_"
			key := "notexists"

			return test{
				name: "Test error private key not exist",
				args: func() args {
					return args{
						cfg: config.Token{
							RefreshDuration: "1m",
							Expiration:      "1m",
							PrivateKeyPath:  keyKey,
						},
					}
				}(),
				beforeFunc: func() {
					os.Setenv(strings.TrimPrefix(strings.TrimSuffix(keyKey, "_"), "_"), key)
				},
				afterFunc: func() {
					os.Unsetenv(strings.TrimPrefix(strings.TrimSuffix(keyKey, "_"), "_"))
				},
				wantErr: fmt.Errorf("invalid token certificate open %v", "notexists: no such file or directory"),
			}
		}(),
		func() test {
			keyKey := "_dummyKey_"
			key := "./assets/invalid_dummyServer.key"

			return test{
				name: "Test error private key not valid",
				args: func() args {

					return args{
						cfg: config.Token{
							RefreshDuration: "1m",
							Expiration:      "1m",
							PrivateKeyPath:  keyKey,
							NTokenPath:      "",
						},
					}
				}(),
				beforeFunc: func() {
					os.Setenv(strings.TrimPrefix(strings.TrimSuffix(keyKey, "_"), "_"), key)
				},
				afterFunc: func() {
					os.Unsetenv(strings.TrimPrefix(strings.TrimSuffix(keyKey, "_"), "_"))
				},
				wantErr: fmt.Errorf("failed to create ZMS SVC Token Builder\nAthenzDomain:\t\nServiceName:\t\nKeyVersion:\t: Unable to create signer: Unable to load private key"),
			}
		}(),
		func() test {
			keyKey := "_dummyKey_"
			key := "./assets/dummyServer.key"
			cfg := config.Token{
				AthenzDomain:    strings.TrimPrefix(strings.TrimSuffix(keyKey, "_"), "_"),
				ServiceName:     strings.TrimPrefix(strings.TrimSuffix(keyKey, "_"), "_"),
				NTokenPath:      "",
				PrivateKeyPath:  keyKey,
				ValidateToken:   false,
				RefreshDuration: "1s",
				KeyVersion:      "1",
				Expiration:      "1s",
			}
			keyData, _ := ioutil.ReadFile(key)
			athenzDomain := config.GetActualValue(cfg.AthenzDomain)
			serviceName := config.GetActualValue(cfg.ServiceName)

			return test{
				name: "Check return value",
				args: args{
					cfg: cfg,
				},
				want: func() ntokend.TokenService {
					tok, err := ntokend.New(
						ntokend.RefreshDuration(time.Second), ntokend.TokenExpiration(time.Second), ntokend.KeyVersion(cfg.KeyVersion), ntokend.KeyData(keyData), ntokend.TokenFilePath(cfg.NTokenPath),
						ntokend.AthenzDomain(athenzDomain), ntokend.ServiceName(serviceName))

					if err != nil {
						panic(err)
					}

					return tok
				}(),
				beforeFunc: func() {
					os.Setenv(strings.TrimPrefix(strings.TrimSuffix(keyKey, "_"), "_"), key)
				},
				checkFunc: func(got, want ntokend.TokenService) error {
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					got.StartTokenUpdater(ctx)
					want.StartTokenUpdater(ctx)
					time.Sleep(time.Millisecond * 50)

					g, err := got.GetTokenProvider()()
					if err != nil {
						return fmt.Errorf("Got not found, err: %v", err)
					}
					w, err := want.GetTokenProvider()()
					if err != nil {
						return fmt.Errorf("Want not found, err: %v", err)
					}
					parse := func(str string) map[string]string {
						m := make(map[string]string)
						for _, pair := range strings.Split(str, ";") {
							kv := strings.SplitN(pair, "=", 2)
							if len(kv) < 2 {
								continue
							}
							m[kv[0]] = kv[1]
						}
						return m
					}

					gm := parse(g)
					wm := parse(w)

					check := func(key string) bool {
						return gm[key] != wm[key]
					}

					if check("v") || check("d") || check("n") || check("k") || check("h") || check("i") {
						return fmt.Errorf("invalid token, got: %s, want: %s", g, w)
					}

					return nil
				},
				afterFunc: func() {
					os.Unsetenv(strings.TrimPrefix(strings.TrimSuffix(keyKey, "_"), "_"))
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.beforeFunc != nil {
				tt.beforeFunc()
			}
			if tt.afterFunc != nil {
				defer tt.afterFunc()
			}

			got, err := createNtokend(tt.args.cfg)
			if err != nil && err.Error() != tt.wantErr.Error() {
				t.Errorf("createNtokend() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.checkFunc != nil {
				err = tt.checkFunc(got, tt.want)
				if tt.wantErr == nil && err != nil {
					t.Errorf("compare check failed, err: %v", err)
					return
				}
			}
		})
	}
}
