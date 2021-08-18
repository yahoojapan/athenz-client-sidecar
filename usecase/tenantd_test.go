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

	"github.com/kpango/ntokend"
	"github.com/yahoojapan/athenz-client-sidecar/v2/config"
	"github.com/yahoojapan/athenz-client-sidecar/v2/handler"
	"github.com/yahoojapan/athenz-client-sidecar/v2/infra"
	"github.com/yahoojapan/athenz-client-sidecar/v2/router"
	"github.com/yahoojapan/athenz-client-sidecar/v2/service"
)

func TestNew(t *testing.T) {
	type args struct {
		cfg config.Config
	}
	type test struct {
		name       string
		args       args
		beforeFunc func()
		checkFunc  func(Tenant) error
		afterFunc  func()
		wantErr    error
	}
	keyKey := "_dummyKey_"
	key := "../test/data/dummyServer.key"
	dummyNTokenConfig := config.NToken{
		Enable:            true,
		AthenzDomain:      strings.TrimPrefix(strings.TrimSuffix(keyKey, "_"), "_"),
		ServiceName:       strings.TrimPrefix(strings.TrimSuffix(keyKey, "_"), "_"),
		PrivateKeyPath:    key,
		Validate:          false,
		RefreshPeriod:     "1m",
		KeyVersion:        "1",
		Expiry:            "1m",
		ExistingTokenPath: "",
	}
	dummyServerConfig := config.Server{
		ShutdownTimeout: "10s",
		ShutdownDelay:   "10s",
	}
	tests := []test{
		{
			name: "Check error when new ntoken service",
			args: args{
				cfg: config.Config{
					NToken: config.NToken{
						Enable: true,
					},
				},
			},
			wantErr: fmt.Errorf("ntokend error: invalid token refresh period , time: invalid duration "),
		},
		{
			name: "Check error when new access token service",
			args: args{
				cfg: config.Config{
					NToken: dummyNTokenConfig,
					AccessToken: config.AccessToken{
						Enable: true,
						Expiry: "invalid_at_exp",
					},
				},
			},
			wantErr: fmt.Errorf("access token service error: Expiry: time: invalid duration invalid_at_exp: Invalid config"),
		},
		{
			name: "Check error when new role token service",
			args: args{
				cfg: config.Config{
					NToken: dummyNTokenConfig,
					RoleToken: config.RoleToken{
						Enable: true,
						Expiry: "invalid_rt_exp",
					},
				},
			},
			wantErr: fmt.Errorf("role token service error: Expiry: time: invalid duration invalid_rt_exp: Invalid config"),
		},
		func() test {
			cfg := config.Config{
				NToken: dummyNTokenConfig,
				Server: dummyServerConfig,
				AccessToken: config.AccessToken{
					Enable: true,
				},
			}

			return test{
				name: "Check success when access token is enabled",
				args: args{
					cfg: cfg,
				},
				checkFunc: func(got Tenant) error {
					if got.(*clientd).server == nil ||
						got.(*clientd).access == nil ||
						got.(*clientd).token == nil {

						return fmt.Errorf("Got: %v", got)
					}
					return nil
				},
			}
		}(),
		func() test {
			cfg := config.Config{
				NToken: dummyNTokenConfig,
				Server: dummyServerConfig,
				ServiceCert: config.ServiceCert{
					Enable:        true,
					AthenzCAPath:  "../test/data/non_exist.pem",
					RefreshPeriod: "1h",
					ExpiryMargin:  "1m",
					Expiry:        "24h",
				},
			}

			return test{
				name: "Check failure when svccert is enabled but AthenzCAPath file path is wrong",
				args: args{
					cfg: cfg,
				},
				wantErr: fmt.Errorf("service certificate service error: Failed to initialize a service"),
			}
		}(),
		func() test {
			cfg := config.Config{
				NToken: dummyNTokenConfig,
				Server: dummyServerConfig,
				ServiceCert: config.ServiceCert{
					Enable:        true,
					AthenzCAPath:  "../test/data/dummyCa.pem",
					RefreshPeriod: "1h",
					ExpiryMargin:  "1m",
					Expiry:        "24h",
				},
			}

			return test{
				name: "Check success when svccert is enabled",
				args: args{
					cfg: cfg,
				},
				checkFunc: func(got Tenant) error {
					if got.(*clientd).server == nil ||
						got.(*clientd).svccert == nil ||
						got.(*clientd).token == nil {

						return fmt.Errorf("Got: %v", got)
					}
					return nil
				},
			}
		}(),
		func() test {
			cfg := config.Config{
				NToken: dummyNTokenConfig,
				Server: dummyServerConfig,
				ServiceCert: config.ServiceCert{
					Enable: false,
				},
			}

			return test{
				name: "Check success when ServiceCert is disabled",
				args: args{
					cfg: cfg,
				},
				checkFunc: func(got Tenant) error {
					if got.(*clientd).server == nil ||
						got.(*clientd).token == nil {

						return fmt.Errorf("Got: %v", got)
					}
					return nil
				},
			}
		}(),
		func() test {
			cfg := config.Config{
				NToken: dummyNTokenConfig,
				Server: dummyServerConfig,
			}

			return test{
				name: "Check success without svccert settings",
				args: args{
					cfg: cfg,
				},
				checkFunc: func(got Tenant) error {
					if got.(*clientd).server == nil ||
						got.(*clientd).token == nil {

						return fmt.Errorf("Got: %v", got)
					}
					return nil
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

			got, err := New(tt.args.cfg)
			if err != nil {
				if tt.wantErr == nil {
					t.Errorf("failed to instantiate, err: %v", err)
					return
				}
				if tt.wantErr != nil && tt.wantErr.Error() != err.Error() {
					t.Errorf("error not the same, want: %v, got: %v", tt.wantErr, err)
					return
				}
			} else if tt.wantErr != nil {
				t.Errorf("error want: %v, got: nil", tt.wantErr)
				return
			}

			if tt.checkFunc != nil {
				err = tt.checkFunc(got)
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
		access  service.AccessService
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
			key := "../test/data/dummyServer.key"

			certKey := "_dummy_cert_"
			cert := "../test/data/dummyServer.crt"

			cfg := config.Config{
				NToken: config.NToken{
					Enable:            true,
					AthenzDomain:      strings.TrimPrefix(strings.TrimSuffix(keyKey, "_"), "_"),
					ServiceName:       strings.TrimPrefix(strings.TrimSuffix(keyKey, "_"), "_"),
					PrivateKeyPath:    key,
					Validate:          false,
					RefreshPeriod:     "1m",
					KeyVersion:        "1",
					Expiry:            "1m",
					ExistingTokenPath: "",
				},
				AccessToken: config.AccessToken{
					Enable: true,
				},
				RoleToken: config.RoleToken{
					Enable: true,
				},
				Server: config.Server{
					TLS: config.TLS{
						Enable:   true,
						CertPath: certKey,
						KeyPath:  keyKey,
					},
				},
				ServiceCert: config.ServiceCert{
					Enable:        true,
					AthenzCAPath:  "../test/data/dummyCa.pem",
					RefreshPeriod: "",
				},
			}

			ctx, cancelFunc := context.WithCancel(context.Background())

			os.Setenv(strings.TrimPrefix(strings.TrimSuffix(keyKey, "_"), "_"), key)
			os.Setenv(strings.TrimPrefix(strings.TrimSuffix(certKey, "_"), "_"), cert)

			return test{
				name: "Token updater works",
				fields: func() fields {
					token, err := createNtokend(cfg.NToken)
					if err != nil {
						panic(err)
					}
					access, err := service.NewAccessService(cfg.AccessToken, token.GetTokenProvider())
					if err != nil {
						panic(err)
					}
					role, err := service.NewRoleService(cfg.RoleToken, token.GetTokenProvider())
					if err != nil {
						panic(err)
					}

					h := handler.New(
						cfg.Proxy,
						infra.NewBuffer(cfg.Proxy.BufferSize),
						token.GetTokenProvider(),
						access.GetAccessProvider(),
						role.GetRoleProvider(),
						nil,
					)

					serveMux := router.New(cfg, h)
					server := service.NewServer(
						service.WithServerConfig(cfg.Server),
						service.WithServerHandler(serveMux),
					)

					return fields{
						cfg:     cfg,
						token:   token,
						server:  server,
						access:  access,
						role:    role,
						svccert: nil,
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
				access:  tt.fields.access,
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
		cfg config.NToken
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
			name: "refresh period invalid",
			args: args{
				cfg: config.NToken{
					RefreshPeriod: "dummy",
				},
			},
			wantErr: fmt.Errorf("invalid token refresh period %s, %v", "dummy", "time: invalid duration dummy"),
		},
		{
			name: "token expiry invalid",
			args: args{
				cfg: config.NToken{
					RefreshPeriod: "1s",
					Expiry:        "dummy",
				},
			},
			wantErr: fmt.Errorf("invalid token expiry %s, %v", "dummy", "time: invalid duration dummy"),
		},
		func() test {
			keyKey := "_dummyKey_"
			key := "../test/data/non_exist.key"

			return test{
				name: "Test error private key not exist",
				args: func() args {
					return args{
						cfg: config.NToken{
							RefreshPeriod:  "1m",
							Expiry:         "1m",
							PrivateKeyPath: keyKey,
						},
					}
				}(),
				beforeFunc: func() {
					os.Setenv(strings.TrimPrefix(strings.TrimSuffix(keyKey, "_"), "_"), key)
				},
				afterFunc: func() {
					os.Unsetenv(strings.TrimPrefix(strings.TrimSuffix(keyKey, "_"), "_"))
				},
				wantErr: fmt.Errorf("invalid token private key open %v", "../test/data/non_exist.key: no such file or directory"),
			}
		}(),
		func() test {
			keyKey := "_dummyKey_"
			key := "../test/data/invalid_dummyServer.key"

			return test{
				name: "Test error private key not valid",
				args: func() args {

					return args{
						cfg: config.NToken{
							RefreshPeriod:     "1m",
							Expiry:            "1m",
							PrivateKeyPath:    keyKey,
							ExistingTokenPath: "",
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
			key := "../test/data/dummyServer.key"
			cfg := config.NToken{
				AthenzDomain:      strings.TrimPrefix(strings.TrimSuffix(keyKey, "_"), "_"),
				ServiceName:       strings.TrimPrefix(strings.TrimSuffix(keyKey, "_"), "_"),
				ExistingTokenPath: "",
				PrivateKeyPath:    keyKey,
				Validate:          false,
				RefreshPeriod:     "1s",
				KeyVersion:        "1",
				Expiry:            "1s",
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
						ntokend.RefreshDuration(time.Second),
						ntokend.TokenExpiration(time.Second),
						ntokend.KeyVersion(cfg.KeyVersion),
						ntokend.KeyData(keyData),
						ntokend.TokenFilePath(cfg.ExistingTokenPath),
						ntokend.AthenzDomain(athenzDomain),
						ntokend.ServiceName(serviceName),
					)

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

func Test_requireNtokend(t *testing.T) {
	type args struct {
		cfg config.Config
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "ntoken enable",
			args: args{
				cfg: config.Config{
					NToken: config.NToken{
						Enable: true,
					},
				},
			},
			want: true,
		},
		{
			name: "access token enable with client cert not set",
			args: args{
				cfg: config.Config{
					AccessToken: config.AccessToken{
						Enable: true,
					},
				},
			},
			want: true,
		},
		{
			name: "role token enable with client cert not set",
			args: args{
				cfg: config.Config{
					RoleToken: config.RoleToken{
						Enable: true,
					},
				},
			},
			want: true,
		},
		{
			name: "service cert enable",
			args: args{
				cfg: config.Config{
					ServiceCert: config.ServiceCert{
						Enable: true,
					},
				},
			},
			want: true,
		},
		{
			name: "proxy enable",
			args: args{
				cfg: config.Config{
					Proxy: config.Proxy{
						Enable: true,
					},
				},
			},
			want: true,
		},
		{
			name: "all disable",
			args: args{
				cfg: config.Config{
					NToken: config.NToken{
						Enable: false,
					},
					AccessToken: config.AccessToken{
						Enable: false,
					},
					RoleToken: config.RoleToken{
						Enable: false,
					},
					ServiceCert: config.ServiceCert{
						Enable: false,
					},
					Proxy: config.Proxy{
						Enable: false,
					},
				},
			},
			want: false,
		},
		{
			name: "enable but using client cert",
			args: args{
				cfg: config.Config{
					NToken: config.NToken{
						Enable: false,
					},
					AccessToken: config.AccessToken{
						Enable:   true,
						CertPath: "any",
					},
					RoleToken: config.RoleToken{
						Enable:   true,
						CertPath: "any",
					},
					ServiceCert: config.ServiceCert{
						Enable: false,
					},
					Proxy: config.Proxy{
						Enable: false,
					},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := requireNtokend(tt.args.cfg); got != tt.want {
				t.Errorf("requireNtokend() = %v, want %v", got, tt.want)
			}
		})
	}
}
