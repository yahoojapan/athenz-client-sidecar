package usecase

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"ghe.corp.yahoo.co.jp/athenz/athenz-tenant-sidecar/config"
	"ghe.corp.yahoo.co.jp/athenz/athenz-tenant-sidecar/handler"
	"ghe.corp.yahoo.co.jp/athenz/athenz-tenant-sidecar/infra"
	"ghe.corp.yahoo.co.jp/athenz/athenz-tenant-sidecar/router"
	"ghe.corp.yahoo.co.jp/athenz/athenz-tenant-sidecar/service"
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
			keyKey := "dummyKey"
			key := "./assets/dummyServer.key"
			cfg := config.Config{
				Token: config.Token{
					AthenzDomain:    keyKey,
					ServiceName:     keyKey,
					PrivateKeyPath:  "_" + keyKey + "_",
					ValidateToken:   false,
					RefreshDuration: "1m",
					KeyVersion:      "1",
					Expiration:      "1m",
					NTokenPath:      "",
				},
				Server: config.Server{
					HealthzPath: "/dummyPath",
				},
			}

			return test{
				name: "Check success",
				args: args{
					cfg: cfg,
				},
				want: func() Tenant {
					os.Setenv(keyKey, key)
					defer os.Remove(keyKey)
					token, err := service.NewTokenService(cfg.Token, cfg.HC)
					if err != nil {
						panic(err)
					}
					hc, err := service.NewHC(cfg.HC, token.GetTokenProvider())
					if err != nil {
						panic(err)
					}
					udb := service.NewUDBClient(cfg.UDB, hc.GetCertProvider())
					role := service.NewRoleService(cfg.Role, token.GetTokenProvider())

					serveMux := router.New(cfg.Server, handler.New(cfg.Proxy, infra.NewBuffer(cfg.Proxy.BufferSize), udb, token.GetTokenProvider(), role.GetRoleProvider(), hc.GetCertProvider()))
					server := service.NewServer(cfg.Server, serveMux)

					return &tenantd{
						cfg:    cfg,
						token:  token,
						udb:    udb,
						hc:     hc,
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

func Test_tenantd_Start(t *testing.T) {
	type fields struct {
		cfg    config.Config
		token  service.TokenService
		udb    service.UDB
		hc     service.HC
		server service.Server
		role   service.RoleService
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
			keyKey := "dummyKey"
			key := "./assets/dummyServer.key"

			certKey := "dummy_cert"
			cert := "./assets/dummyServer.crt"

			cfg := config.Config{
				Token: config.Token{
					AthenzDomain:    keyKey,
					ServiceName:     keyKey,
					PrivateKeyPath:  "_" + keyKey + "_",
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
						CertKey: certKey,
						KeyKey:  keyKey,
					},
				},
			}

			ctx, cancelFunc := context.WithCancel(context.Background())

			os.Setenv(keyKey, key)
			os.Setenv(certKey, cert)

			return test{
				name: "Token updater works",
				fields: func() fields {
					token, err := service.NewTokenService(cfg.Token, cfg.HC)
					if err != nil {
						panic(err)
					}
					hc, err := service.NewHC(cfg.HC, token.GetTokenProvider())
					if err != nil {
						panic(err)
					}
					udb := service.NewUDBClient(cfg.UDB, hc.GetCertProvider())
					role := service.NewRoleService(cfg.Role, token.GetTokenProvider())

					serveMux := router.New(cfg.Server, handler.New(cfg.Proxy, infra.NewBuffer(cfg.Proxy.BufferSize), udb, token.GetTokenProvider(), role.GetRoleProvider(), hc.GetCertProvider()))
					server := service.NewServer(cfg.Server, serveMux)

					return fields{
						cfg:    cfg,
						token:  token,
						udb:    udb,
						hc:     hc,
						server: server,
						role:   role,
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
					os.Remove(keyKey)
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

			te := &tenantd{
				cfg:    tt.fields.cfg,
				token:  tt.fields.token,
				udb:    tt.fields.udb,
				hc:     tt.fields.hc,
				server: tt.fields.server,
				role:   tt.fields.role,
			}
			got := te.Start(tt.args.ctx)
			if err := tt.checkFunc(got, tt.want); err != nil {
				t.Errorf("Start function error: %v", err)
			}
		})
	}
}
