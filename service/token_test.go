package service

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ghe.corp.yahoo.co.jp/athenz/athenz-tenant-sidecar/config"
	"github.com/yahoo/athenz/libs/go/zmssvctoken"
)

func TestNewTokenService(t *testing.T) {
	type args struct {
		cfg   config.Token
		hcCfg config.HC
	}
	type test struct {
		name       string
		args       args
		want       TokenService
		beforeFunc func()
		checkFunc  func(TokenService, TokenService) error
		afterFunc  func()
		wantErr    error
	}
	tests := []test{
		{
			name: "Test error invalid refresh duration",
			args: args{
				cfg: config.Token{
					RefreshDuration: "test",
				},
			},
			wantErr: fmt.Errorf("invalid token refresh duration %s, %v", "test", "time: invalid duration test"),
		},
		{
			name: "Test error invalid expiration",
			args: args{
				cfg: config.Token{
					RefreshDuration: "1m",
					Expiration:      "test",
				},
			},
			wantErr: fmt.Errorf("invalid token expiration %s, %v", "test", "time: invalid duration test"),
		},
		func() test {
			keyKey := "dummyKey"
			key := "notexists"

			return test{
				name: "Test error private key not exist",
				args: func() args {
					return args{
						cfg: config.Token{
							RefreshDuration: "1m",
							Expiration:      "1m",
							PrivateKeyPath:  "_" + keyKey + "_",
						},
					}
				}(),
				beforeFunc: func() {
					os.Setenv(keyKey, key)
				},
				afterFunc: func() {
					os.Remove(keyKey)
				},
				wantErr: fmt.Errorf("invalid token certificate open %v", "notexists: no such file or directory"),
			}
		}(),
		func() test {
			keyKey := "dummyKey"
			key := "notexists"

			return test{
				name: "Test error private key not valid",
				args: func() args {

					return args{
						cfg: config.Token{
							RefreshDuration: "1m",
							Expiration:      "1m",
							PrivateKeyPath:  "_" + keyKey + "_",
							NTokenPath:      "",
						},
					}
				}(),
				beforeFunc: func() {
					os.Setenv(keyKey, key)
				},
				afterFunc: func() {
					os.Remove(keyKey)
				},
				wantErr: fmt.Errorf("invalid token certificate open %v", "notexists: no such file or directory"),
			}
		}(),
		func() test {
			keyKey := "dummyKey"
			key := "./assets/dummyServer.key"
			cfg := config.Token{
				AthenzDomain:    keyKey,
				ServiceName:     keyKey,
				NTokenPath:      "",
				PrivateKeyPath:  "_" + keyKey + "_",
				ValidateToken:   false,
				RefreshDuration: "1s",
				KeyVersion:      "1",
				Expiration:      "1s",
			}
			hcCfg := config.HC{
				Hostname: "",
				IP:       "",
			}
			keyData, _ := ioutil.ReadFile(key)
			athenzDomain := config.GetActualValue(cfg.AthenzDomain)
			serviceName := config.GetActualValue(cfg.ServiceName)
			hostname := os.Getenv(hcCfg.Hostname)
			ipAddr := os.Getenv(hcCfg.IP)

			return test{
				name: "Check return value",
				args: args{
					cfg:   cfg,
					hcCfg: hcCfg,
				},
				want: func() TokenService {
					tok, err := (&token{
						token:           new(atomic.Value),
						tokenFilePath:   cfg.NTokenPath,
						validateToken:   cfg.ValidateToken,
						tokenExpiration: time.Second,
						refreshDuration: time.Second,
					}).createTokenBuilder(athenzDomain, serviceName, cfg.KeyVersion, keyData, hostname, ipAddr)
					if err != nil {
						panic(err)
					}
					return tok
				}(),
				beforeFunc: func() {
					os.Setenv(keyKey, key)
				},
				checkFunc: func(got, want TokenService) error {
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					got.StartTokenUpdater(ctx)
					want.StartTokenUpdater(ctx)
					time.Sleep(time.Millisecond * 50)

					g, err := got.GetToken()
					if err != nil {
						return fmt.Errorf("Got not found, err: %v", err)
					}
					w, err := want.GetToken()
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

					if check("v") || check("d") || check("n") || check("k") || check("h") || check("i") || check("t") || check("e") {
						return fmt.Errorf("invalid token, got: %s, want: %s", g, w)
					}

					return nil
				},
				afterFunc: func() {
					os.Remove(keyKey)
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

			got, err := NewTokenService(tt.args.cfg, tt.args.hcCfg)
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

func Test_token_StartTokenUpdater(t *testing.T) {
	type fields struct {
		tokenFilePath   string
		token           *atomic.Value
		validateToken   bool
		tokenExpiration time.Duration
		refreshDuration time.Duration
		builder         zmssvctoken.TokenBuilder
	}
	type args struct {
		ctx context.Context
	}
	type test struct {
		name       string
		fields     fields
		args       args
		beforeFunc func()
		checkFunc  func(TokenService) error
		afterFunc  func()
		wantErr    error
	}
	tests := []test{
		func() test {
			keyKey := "dummyKey"
			key := "./assets/dummyServer.key"

			return test{
				name: "Check return value",
				args: args{
					ctx: context.Background(),
				},
				fields: fields{
					tokenFilePath:   "",
					token:           new(atomic.Value),
					validateToken:   false,
					tokenExpiration: time.Second,
					refreshDuration: time.Second,
					builder: func() zmssvctoken.TokenBuilder {
						tb := NewMockTokenBuilder()
						tb.(*mockTokenBuilder).valueFunc = func() (string, error) {
							return "dummyTok", nil
						}

						return tb
					}(),
				},
				beforeFunc: func() {
					os.Setenv(keyKey, key)
				},
				checkFunc: func(got TokenService) error {
					time.Sleep(time.Millisecond * 50)
					g, err := got.GetToken()
					if err != nil {
						return err
					}
					if len(g) == 0 {
						return fmt.Errorf("invalid token, got: %s", g)
					}

					return nil
				},
				afterFunc: func() {
					os.Remove(keyKey)
				},
			}
		}(),
		func() test {
			keyKey := "dummyKey"
			key := "./assets/dummyServer.key"

			ctx, cancel := context.WithCancel(context.Background())

			return test{
				name: "Check context canceled",
				args: args{
					ctx: ctx,
				},
				fields: fields{
					tokenFilePath:   "",
					token:           new(atomic.Value),
					validateToken:   false,
					tokenExpiration: time.Second,
					refreshDuration: time.Second,
					builder: func() zmssvctoken.TokenBuilder {
						tb := NewMockTokenBuilder()
						tb.(*mockTokenBuilder).valueFunc = func() (string, error) {
							return "dummyTok", nil
						}

						return tb
					}(),
				},
				beforeFunc: func() {
					os.Setenv(keyKey, key)
				},
				checkFunc: func(got TokenService) error {
					time.Sleep(time.Millisecond * 50)
					cancel()
					g, err := got.GetToken()
					if err != nil {
						return err
					}

					g2, err := got.GetToken()
					if err != nil {
						return err
					}

					if g != g2 {
						return fmt.Errorf("Context is canceled, but the token refreshed, g: %v\tg2: %v", g, g2)
					}
					return nil
				},
				afterFunc: func() {
					os.Remove(keyKey)
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

			tok := &token{
				tokenFilePath:   tt.fields.tokenFilePath,
				token:           tt.fields.token,
				validateToken:   tt.fields.validateToken,
				tokenExpiration: tt.fields.tokenExpiration,
				refreshDuration: tt.fields.refreshDuration,
				builder:         tt.fields.builder,
			}

			got := tok.StartTokenUpdater(tt.args.ctx)

			if tt.checkFunc != nil {
				err := tt.checkFunc(got)
				if tt.wantErr == nil && err != nil {
					t.Errorf("compare check failed, err: %v", err)
					return
				}
			}
		})
	}
}

func Test_token_GetTokenProvider(t *testing.T) {
	type fields struct {
		tokenFilePath   string
		token           *atomic.Value
		validateToken   bool
		tokenExpiration time.Duration
		refreshDuration time.Duration
		builder         zmssvctoken.TokenBuilder
	}
	tests := []struct {
		name   string
		fields fields
		want   TokenProvider
	}{
		{
			name: "provider exactly return",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := &token{
				tokenFilePath:   tt.fields.tokenFilePath,
				token:           tt.fields.token,
				validateToken:   tt.fields.validateToken,
				tokenExpiration: tt.fields.tokenExpiration,
				refreshDuration: tt.fields.refreshDuration,
				builder:         tt.fields.builder,
			}
			if got := tok.GetTokenProvider(); got == nil {
				t.Errorf("TokenProvider is empty")
			}
		})
	}
}

func Test_token_GetToken(t *testing.T) {
	type fields struct {
		tokenFilePath   string
		token           *atomic.Value
		validateToken   bool
		tokenExpiration time.Duration
		refreshDuration time.Duration
		builder         zmssvctoken.TokenBuilder
	}
	type test struct {
		name       string
		fields     fields
		beforeFunc func()
		checkFunc  func(TokenService) error
		afterFunc  func()
		wantErr    error
	}
	tests := []test{
		func() test {
			keyKey := "dummyKey"
			key := "./assets/dummyServer.key"

			return test{
				name: "Check return value",
				fields: fields{
					tokenFilePath:   "",
					token:           new(atomic.Value),
					validateToken:   false,
					tokenExpiration: time.Second,
					refreshDuration: time.Second,
					builder: func() zmssvctoken.TokenBuilder {
						tb := NewMockTokenBuilder()
						tb.(*mockTokenBuilder).valueFunc = func() (string, error) {
							return "dummyTok", nil
						}

						return tb
					}(),
				},
				beforeFunc: func() {
					os.Setenv(keyKey, key)
				},
				checkFunc: func(tok TokenService) error {
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					tok.StartTokenUpdater(ctx)
					time.Sleep(time.Millisecond * 50)

					got, err := tok.GetToken()
					if err != nil {
						return err
					}
					if len(got) == 0 {
						return fmt.Errorf("invalid token, got: %s", got)
					}

					return nil
				},
				afterFunc: func() {
					os.Remove(keyKey)
				},
			}
		}(),
		func() test {
			keyKey := "dummyKey"
			key := "./assets/dummyServer.key"

			return test{
				name: "Check error",
				fields: fields{
					tokenFilePath:   "",
					token:           new(atomic.Value),
					validateToken:   false,
					tokenExpiration: time.Second,
					refreshDuration: time.Second,
					builder: func() zmssvctoken.TokenBuilder {
						tb := NewMockTokenBuilder()
						tb.(*mockTokenBuilder).valueFunc = func() (string, error) {
							return "dummyTok", nil
						}

						return tb
					}(),
				},
				beforeFunc: func() {
					os.Setenv(keyKey, key)
				},
				checkFunc: func(tok TokenService) error {
					got, err := tok.GetToken()
					if got != "" || err == nil {
						return fmt.Errorf("Daemon is not started, but the GetToken didn't return error  got: %v", got)
					}
					return nil
				},
				afterFunc: func() {
					os.Remove(keyKey)
				},
				wantErr: ErrTokenNotFound,
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

			tok := &token{
				tokenFilePath:   tt.fields.tokenFilePath,
				token:           tt.fields.token,
				validateToken:   tt.fields.validateToken,
				tokenExpiration: tt.fields.tokenExpiration,
				refreshDuration: tt.fields.refreshDuration,
				builder:         tt.fields.builder,
			}
			if tt.checkFunc != nil {
				err := tt.checkFunc(tok)
				if tt.wantErr == nil && err != nil {
					t.Errorf("compare check failed, err: %v", err)
					return
				}
			}
		})
	}
}

func Test_token_createTokenBuilder(t *testing.T) {
	type fields struct {
		tokenFilePath   string
		token           *atomic.Value
		validateToken   bool
		tokenExpiration time.Duration
		refreshDuration time.Duration
		builder         zmssvctoken.TokenBuilder
	}
	type args struct {
		athenzDomain string
		serviceName  string
		keyVersion   string
		keyData      []byte
		hostname     string
		ipAddr       string
	}
	type test struct {
		name       string
		fields     fields
		args       args
		beforeFunc func() error
		checkFunc  func(TokenService) error
		afterFunc  func() error
		wantErr    error
	}
	tests := []test{
		func() test {
			keyData, err := ioutil.ReadFile("./assets/dummyServer.key")
			if err != nil {
				panic(err)
			}

			return test{
				name: "Check create token builder success",
				fields: fields{
					token:           new(atomic.Value),
					tokenFilePath:   "",
					validateToken:   false,
					tokenExpiration: time.Second,
					refreshDuration: time.Second,
				},
				args: args{
					athenzDomain: "athenz",
					serviceName:  "service",
					keyVersion:   "1",
					keyData:      keyData,
				},
				checkFunc: func(tv TokenService) error {
					if tv.(*token).builder == nil {
						return fmt.Errorf("Token builder is empty")
					}
					return nil
				},
			}
		}(),
		func() test {
			keyData, _ := ioutil.ReadFile("./assets/emptyfile")

			return test{
				name: "Check error create token builder",
				fields: fields{
					token:           new(atomic.Value),
					tokenFilePath:   "",
					validateToken:   false,
					tokenExpiration: time.Second,
					refreshDuration: time.Second,
				},
				args: args{
					athenzDomain: "athenz",
					serviceName:  "service",
					keyVersion:   "1",
					keyData:      keyData,
				},
				wantErr: fmt.Errorf(`failed to create ZMS SVC Token Builder
AthenzDomain:	athenz
ServiceName:	service
KeyVersion:	1
Error: Unable to create signer: Unable to load private key`),
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.afterFunc != nil {
				defer func() {
					if err := tt.afterFunc(); err != nil {
						t.Errorf("%v", err)
						return
					}
				}()
			}

			if tt.beforeFunc != nil {
				err := tt.beforeFunc()
				if err != nil {
					t.Errorf("beforeFunc error, error: %v", err)
					return
				}
			}

			tok := &token{
				tokenFilePath:   tt.fields.tokenFilePath,
				token:           tt.fields.token,
				validateToken:   tt.fields.validateToken,
				tokenExpiration: tt.fields.tokenExpiration,
				refreshDuration: tt.fields.refreshDuration,
				builder:         tt.fields.builder,
			}
			got, err := tok.createTokenBuilder(tt.args.athenzDomain, tt.args.serviceName, tt.args.keyVersion, tt.args.keyData, tt.args.hostname, tt.args.ipAddr)
			if tt.checkFunc != nil {
				if e := tt.checkFunc(got); e != nil {
					t.Errorf("createTokenBuilder error, error: %v", e)
					return
				}
			}

			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("expected error, but got nil")
					return
				} else if !reflect.DeepEqual(tt.wantErr.Error(), err.Error()) {
					t.Errorf("error not expected, want: %v, got: %v", tt.wantErr, err)
					return
				}
			}
		})
	}
}

func Test_token_loadToken(t *testing.T) {
	type fields struct {
		tokenFilePath   string
		token           *atomic.Value
		validateToken   bool
		tokenExpiration time.Duration
		refreshDuration time.Duration
		builder         zmssvctoken.TokenBuilder
	}
	type test struct {
		name       string
		fields     fields
		beforeFunc func() error
		checkFunc  func(got, want string) error
		afterFunc  func() error
		want       string
		wantErr    error
	}
	tests := []test{
		test{
			name: "Test error tokenFilePath is empty (k8s secret)",
			fields: fields{
				token:           new(atomic.Value),
				tokenFilePath:   "",
				validateToken:   false,
				tokenExpiration: time.Second,
				refreshDuration: time.Second,
				builder: func() zmssvctoken.TokenBuilder {
					tb := NewMockTokenBuilder()
					tb.(*mockTokenBuilder).valueFunc = func() (string, error) {
						return "", fmt.Errorf("Error")
					}

					return tb
				}(),
			},
			wantErr: fmt.Errorf("Error"),
		},
		test{
			name: "Test success tokenFilePath is empty (k8s secret)",
			fields: fields{
				token:           new(atomic.Value),
				tokenFilePath:   "",
				validateToken:   false,
				tokenExpiration: time.Second,
				refreshDuration: time.Second,
				builder: func() zmssvctoken.TokenBuilder {
					tb := NewMockTokenBuilder()
					tb.(*mockTokenBuilder).valueFunc = func() (string, error) {
						return "token", nil
					}

					return tb
				}(),
			},
			checkFunc: func(got, want string) error {
				if got != want {
					return fmt.Errorf("Token mismatch, got: %v, want: %v", got, want)
				}
				return nil
			},
			want: "token",
		},
		test{
			name: "Test tokenFilePath not exists error (Copper argos)",
			fields: fields{
				token:           new(atomic.Value),
				tokenFilePath:   "notexists",
				validateToken:   false,
				tokenExpiration: time.Second,
				refreshDuration: time.Second,
				builder:         NewMockTokenBuilder(),
			},
			wantErr: fmt.Errorf("open notexists: no such file or directory"),
		},
		test{
			name: "Test tokenFilePath exists (Copper argos)",
			fields: fields{
				token:           new(atomic.Value),
				tokenFilePath:   "./assets/dummyToken",
				validateToken:   false,
				tokenExpiration: time.Second,
				refreshDuration: time.Second,
				builder:         NewMockTokenBuilder(),
			},
			checkFunc: func(got, want string) error {
				if got != want {
					return fmt.Errorf("Token mismatch, got: %v, want: %v", got, want)
				}
				return nil
			},
			want: "dummy token",
		},
		test{
			name: "Test error validate token",
			fields: fields{
				token:           new(atomic.Value),
				tokenFilePath:   "./assets/dummyToken",
				validateToken:   true,
				tokenExpiration: time.Second,
				refreshDuration: time.Second,
				builder:         NewMockTokenBuilder(),
			},
			wantErr: fmt.Errorf("invalid server identity token:	no domain in token"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.afterFunc != nil {
				defer func() {
					if err := tt.afterFunc(); err != nil {
						t.Errorf("%v", err)
						return
					}
				}()
			}

			if tt.beforeFunc != nil {
				err := tt.beforeFunc()
				if err != nil {
					t.Errorf("beforeFunc error, error: %v", err)
					return
				}
			}

			tok := &token{
				tokenFilePath:   tt.fields.tokenFilePath,
				token:           tt.fields.token,
				validateToken:   tt.fields.validateToken,
				tokenExpiration: tt.fields.tokenExpiration,
				refreshDuration: tt.fields.refreshDuration,
				builder:         tt.fields.builder,
			}
			got, err := tok.loadToken()

			if tt.checkFunc != nil {
				if e := tt.checkFunc(got, tt.want); e != nil {
					t.Errorf("loadToken error, error: %v", e)
					return
				}
			}

			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("expected error, but got nil")
					return
				} else if !reflect.DeepEqual(tt.wantErr.Error(), err.Error()) {
					t.Errorf("error not expected, want: %v, got: %v", tt.wantErr, err)
					return
				}
			}
		})
	}
}

func Test_token_update(t *testing.T) {
	type fields struct {
		tokenFilePath   string
		token           *atomic.Value
		validateToken   bool
		tokenExpiration time.Duration
		refreshDuration time.Duration
		builder         zmssvctoken.TokenBuilder
	}
	tests := []struct {
		name      string
		fields    fields
		checkFunc func(TokenService) error
		wantErr   error
	}{
		{
			name: "Test update success",
			fields: fields{
				token:           new(atomic.Value),
				tokenFilePath:   "./assets/dummyToken",
				validateToken:   false,
				tokenExpiration: time.Second,
				refreshDuration: time.Second,
				builder:         NewMockTokenBuilder(),
			},
			checkFunc: func(tv TokenService) error {
				t, err := tv.GetToken()
				if err != nil {
					return fmt.Errorf("unexpected error when get token, err: %v", err)
				}
				if t == "" {
					return fmt.Errorf("token is empty")
				}
				return nil
			},
		},
		{
			name: "Test update fail",
			fields: fields{
				token:           new(atomic.Value),
				tokenFilePath:   "notexists",
				validateToken:   false,
				tokenExpiration: time.Second,
				refreshDuration: time.Second,
				builder:         NewMockTokenBuilder(),
			},
			wantErr: fmt.Errorf("open notexists: no such file or directory"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := &token{
				tokenFilePath:   tt.fields.tokenFilePath,
				token:           tt.fields.token,
				validateToken:   tt.fields.validateToken,
				tokenExpiration: tt.fields.tokenExpiration,
				refreshDuration: tt.fields.refreshDuration,
				builder:         tt.fields.builder,
			}
			err := tok.update()

			if tt.checkFunc != nil {
				if e := tt.checkFunc(tok); e != nil {
					t.Errorf("createTokenBuilder error, error: %v", e)
					return
				}
			}

			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("expected error, but got nil")
					return
				} else if !reflect.DeepEqual(tt.wantErr.Error(), err.Error()) {
					t.Errorf("error not expected, want: %v, got: %v", tt.wantErr, err)
					return
				}
			}
		})
	}
}

func Test_token_setToken(t *testing.T) {
	type fields struct {
		tokenFilePath   string
		token           *atomic.Value
		validateToken   bool
		tokenExpiration time.Duration
		refreshDuration time.Duration
		builder         zmssvctoken.TokenBuilder
	}
	type args struct {
		token string
	}
	tests := []struct {
		name      string
		fields    fields
		args      args
		checkFunc func(TokenService, string) error
		want      string
	}{
		{
			name: "Test set token correct",
			fields: fields{
				token: new(atomic.Value),
			},
			args: args{
				token: "token",
			},
			checkFunc: func(tv TokenService, want string) error {
				t, err := tv.GetToken()
				if err != nil {
					return fmt.Errorf("unexpected error when get token, err: %v", err)
				}
				if t != want {
					return fmt.Errorf("Token is not the same, got: %v, want: %v", t, want)
				}
				return nil
			},
			want: "token",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := &token{
				tokenFilePath:   tt.fields.tokenFilePath,
				token:           tt.fields.token,
				validateToken:   tt.fields.validateToken,
				tokenExpiration: tt.fields.tokenExpiration,
				refreshDuration: tt.fields.refreshDuration,
				builder:         tt.fields.builder,
			}
			tok.setToken(tt.args.token)

			if tt.checkFunc != nil {
				if err := tt.checkFunc(tok, tt.want); err != nil {
					t.Errorf("setToken error: %v", err)
					return
				}
			}
		})
	}
}

func Test_newRawToken(t *testing.T) {
	type args struct {
		token string
	}
	tests := []struct {
		name      string
		args      args
		checkFunc func(got, want *rawToken) error
		want      *rawToken
	}{
		{
			name: "newRawToken parse success",
			args: args{
				token: fmt.Sprintf("%v;%v;%v;%v", "d=dummyDomain", "n=dummyName", "s=dummySign", "e=50000"),
			},
			checkFunc: func(got, want *rawToken) error {
				if !reflect.DeepEqual(got, want) {
					return fmt.Errorf("got: %v, want: %v", got, want)
				}
				return nil
			},
			want: &rawToken{
				domain:     "dummyDomain",
				name:       "dummyName",
				signature:  "dummySign",
				expiration: time.Unix(50000, 0),
			},
		},
		{
			name: "newRawToken parse expiration failed",
			args: args{
				token: fmt.Sprintf("%v;%v;%v;%v", "d=dummyDomain", "n=dummyName", "s=dummySign", "e=dummy"),
			},
			checkFunc: func(got, want *rawToken) error {
				// because time difference of got and want time.Now() function call, we have to round the expiration before checking
				gotExp := got.expiration.Round(time.Second)
				wantExp := want.expiration.Round(time.Second)

				if !reflect.DeepEqual(gotExp, wantExp) {
					return fmt.Errorf("got: %v, want: %v", got, want)
				}
				return nil
			},
			want: &rawToken{
				domain:     "dummyDomain",
				name:       "dummyName",
				signature:  "dummySign",
				expiration: time.Now().Add(time.Second * 30),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := newRawToken(tt.args.token)
			if err := tt.checkFunc(got, tt.want); err != nil {
				t.Errorf("newRawToken() error: %v", err)
			}
		})
	}
}

func Test_rawToken_isValid(t *testing.T) {
	type fields struct {
		domain     string
		name       string
		signature  string
		expiration time.Time
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr error
	}{
		{
			name: "isValid return no error",
			fields: fields{
				domain:     "dummyDomain",
				name:       "dummyName",
				signature:  "dummySign",
				expiration: time.Now().AddDate(0, 0, 1),
			},
			wantErr: nil,
		},
		{
			name: "isValid token expired",
			fields: fields{
				domain:     "dummyDomain",
				name:       "dummyName",
				signature:  "dummySign",
				expiration: time.Unix(0, 0),
			},
			wantErr: fmt.Errorf("token has expired"),
		},
		{
			name: "isValid no domain",
			fields: fields{
				domain:     "",
				name:       "dummyName",
				signature:  "dummySign",
				expiration: time.Now().AddDate(0, 0, 1),
			},
			wantErr: fmt.Errorf("no domain in token"),
		},
		{
			name: "isValid no name",
			fields: fields{
				domain:     "dummyDomain",
				name:       "",
				signature:  "dummySign",
				expiration: time.Now().AddDate(0, 0, 1),
			},
			wantErr: fmt.Errorf("no name in token"),
		},
		{
			name: "isValid no signature",
			fields: fields{
				domain:     "dummyDomain",
				name:       "dummyName",
				signature:  "",
				expiration: time.Now().AddDate(0, 0, 1),
			},
			wantErr: fmt.Errorf("no signature in token"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &rawToken{
				domain:     tt.fields.domain,
				name:       tt.fields.name,
				signature:  tt.fields.signature,
				expiration: tt.fields.expiration,
			}
			err := r.isValid()
			if tt.wantErr == nil && err != nil {
				t.Errorf("failed to valid, err: %v", err)
				return
			} else if tt.wantErr != nil {
				if tt.wantErr.Error() != err.Error() {
					t.Errorf("error not the same, want: %v, got: %v", tt.wantErr, err)
				}
			}
		})
	}
}
