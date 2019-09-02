package service

import (
	"crypto/tls"
	"net/http"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kpango/glg"
	"github.com/kpango/ntokend"
	"github.com/yahoojapan/athenz-client-sidecar/config"
	"golang.org/x/sync/singleflight"
)

func init() {
	glg.Get().SetMode(glg.NONE)
}

func TestNewSvcCertService(t *testing.T) {
	type args struct {
		cfg   config.Config
		token ntokend.TokenProvider
	}
	type test struct {
		name string
		args args
		want SvcCertService
	}
	tests := []test{
		func() test {
			rootCA, _ := NewX509CertPool("./assets/dummyCa.pem")
			dur, _ := time.ParseDuration("30m")
			return test{
				name: "Success to initialize SvcCertService",
				args: args{
					cfg: config.Config{
						Token: config.Token{},
						ServiceCert: config.ServiceCert{
							AthenzRootCA:    "./assets/dummyCa.pem",
							RefreshDuration: "30m",
						},
					},
					token: func() (string, error) { return "", nil },
				},
				want: &svcCertService{
					cfg: config.ServiceCert{
						AthenzRootCA:    "./assets/dummyCa.pem",
						RefreshDuration: "30m",
					},
					tokenCfg:        config.Token{},
					token:           func() (string, error) { return "", nil },
					svcCert:         &atomic.Value{},
					group:           singleflight.Group{},
					refreshDuration: dur,
					httpClient: &http.Client{
						Transport: &http.Transport{
							TLSClientConfig: &tls.Config{
								RootCAs: rootCA,
							},
						},
					},
				},
			}
		}(),
		// func() test {
		// 	return test{
		// 		name: "Error create builder",
		// 		args: args{
		// 			Options: []Option{},
		// 		},
		// 		wantErr: ErrTokenBuilder("", "", "", errors.New("Unable to create signer: Unable to load private key")),
		// 	}
		// }(),
		// func() test {
		// 	tfp := ""
		// 	texp := time.Minute
		// 	rdur := time.Second
		//
		// 	d := "dummyDomain"
		// 	s := "dummyService"
		// 	kv := "dummyKeyVer"
		// 	kd, err := ioutil.ReadFile("./assets/dummyServer.key")
		// 	if err != nil {
		// 		panic(err)
		// 	}
		// 	h := "dummyHost"
		// 	i := "dummyIp"
		//
		// 	return test{
		// 		name: "return success",
		// 		args: args{
		// 			Options: []Option{
		// 				AthenzDomain(d), ServiceName(s), KeyVersion(kv), KeyData(kd), Hostname(h), IPAddr(i),
		// 				TokenFilePath(tfp), TokenExpiration(texp), RefreshDuration(rdur), DisableValidate(),
		// 			},
		// 		},
		// 		want: func() TokenService {
		// 			tb, err := zmssvctoken.NewTokenBuilder(d, s, kd, kv)
		// 			if err != nil {
		// 				panic(err)
		// 			}
		// 			tb.SetHostname(h)
		// 			tb.SetIPAddress(i)
		//
		// 			return &token{
		// 				token:           new(atomic.Value),
		// 				tokenFilePath:   tfp,
		// 				validateToken:   false,
		// 				tokenExpiration: texp,
		// 				refreshDuration: rdur,
		// 				builder:         tb,
		//
		// 				athenzDomain: d,
		// 				serviceName:  s,
		// 				keyVersion:   kv,
		// 				keyData:      kd,
		// 				hostname:     h,
		// 				ipAddr:       i,
		// 			}
		// 		}(),
		// 		checkFunc: func(got, want TokenService) error {
		// 			ctx, cancel := context.WithCancel(context.Background())
		// 			defer cancel()
		// 			got.StartTokenUpdater(ctx)
		// 			want.StartTokenUpdater(ctx)
		// 			time.Sleep(time.Millisecond * 50)
		//
		// 			g, err := got.GetTokenProvider()()
		// 			if err != nil {
		// 				return fmt.Errorf("Got not found, err: %v", err)
		// 			}
		// 			w, err := want.GetTokenProvider()()
		// 			if err != nil {
		// 				return fmt.Errorf("Want not found, err: %v", err)
		// 			}
		// 			parse := func(str string) map[string]string {
		// 				m := make(map[string]string)
		// 				for _, pair := range strings.Split(str, ";") {
		// 					kv := strings.SplitN(pair, "=", 2)
		// 					if len(kv) < 2 {
		// 						continue
		// 					}
		// 					m[kv[0]] = kv[1]
		// 				}
		// 				return m
		// 			}
		//
		// 			gm := parse(g)
		// 			wm := parse(w)
		//
		// 			check := func(key string) bool {
		// 				return gm[key] != wm[key]
		// 			}
		//
		// 			if check("v") || check("d") || check("n") || check("k") || check("h") || check("i") || check("t") || check("e") {
		// 				return fmt.Errorf("invalid token, got: %s, want: %s", g, w)
		// 			}
		//
		// 			return nil
		// 		},
		// 	}
		// }(),
		//
		// func() test {
		// 	tfp := ""
		// 	texp := time.Minute
		// 	rdur := time.Second
		//
		// 	d := "dummyDomain"
		// 	s := "dummyService"
		// 	kv := "dummyKeyVer"
		// 	kd, err := ioutil.ReadFile("./assets/dummyServer.key")
		// 	if err != nil {
		// 		panic(err)
		// 	}
		// 	h := "dummyHost"
		// 	i := "dummyIp"
		//
		// 	dummy := "dummy"
		//
		// 	return test{
		// 		name: "check token option order",
		// 		args: args{
		// 			Options: []Option{
		// 				// dummy value
		// 				AthenzDomain(dummy), ServiceName(dummy), KeyVersion(dummy), KeyData([]byte{}), Hostname(dummy), IPAddr(dummy),
		// 				TokenFilePath(dummy), TokenExpiration(time.Hour), RefreshDuration(time.Hour), EnableValidate(),
		// 				// actual value
		// 				AthenzDomain(d), ServiceName(s), KeyVersion(kv), KeyData(kd), Hostname(h), IPAddr(i),
		// 				TokenFilePath(tfp), TokenExpiration(texp), RefreshDuration(rdur), DisableValidate(),
		// 			},
		// 		},
		// 		want: func() TokenService {
		// 			tb, err := zmssvctoken.NewTokenBuilder(d, s, kd, kv)
		// 			if err != nil {
		// 				panic(err)
		// 			}
		// 			tb.SetHostname(h)
		// 			tb.SetIPAddress(i)
		//
		// 			return &token{
		// 				token:           new(atomic.Value),
		// 				tokenFilePath:   tfp,
		// 				validateToken:   false,
		// 				tokenExpiration: texp,
		// 				refreshDuration: rdur,
		// 				builder:         tb,
		//
		// 				athenzDomain: d,
		// 				serviceName:  s,
		// 				keyVersion:   kv,
		// 				keyData:      kd,
		// 				hostname:     h,
		// 				ipAddr:       i,
		// 			}
		// 		}(),
		// 		checkFunc: func(got, want TokenService) error {
		// 			ctx, cancel := context.WithCancel(context.Background())
		// 			defer cancel()
		// 			got.StartTokenUpdater(ctx)
		// 			want.StartTokenUpdater(ctx)
		// 			time.Sleep(time.Millisecond * 50)
		//
		// 			g, err := got.GetTokenProvider()()
		// 			if err != nil {
		// 				return fmt.Errorf("Got not found, err: %v", err)
		// 			}
		// 			w, err := want.GetTokenProvider()()
		// 			if err != nil {
		// 				return fmt.Errorf("Want not found, err: %v", err)
		// 			}
		// 			parse := func(str string) map[string]string {
		// 				m := make(map[string]string)
		// 				for _, pair := range strings.Split(str, ";") {
		// 					kv := strings.SplitN(pair, "=", 2)
		// 					if len(kv) < 2 {
		// 						continue
		// 					}
		// 					m[kv[0]] = kv[1]
		// 				}
		// 				return m
		// 			}
		//
		// 			gm := parse(g)
		// 			wm := parse(w)
		//
		// 			check := func(key string) bool {
		// 				return gm[key] != wm[key]
		// 			}
		//
		// 			if check("v") || check("d") || check("n") || check("k") || check("h") || check("i") || check("t") || check("e") {
		// 				return fmt.Errorf("invalid token, got: %s, want: %s", g, w)
		// 			}
		//
		// 			return nil
		// 		},
		// 	}
		// }(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svcCertService := NewSvcCertService(tt.args.cfg, tt.args.token)
			if !reflect.DeepEqual(svcCertService, tt.want) {
				t.Errorf("TestNewSvcCertService failed expected: %v, actual: %v", tt.want, svcCertService)
			}
		})
	}
}

/*
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
			dummyTok := "dummyTok"
			ctx, cancel := context.WithCancel(context.Background())

			return test{
				name: "Check return value",
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
							return dummyTok, nil
						}

						return tb
					}(),
				},
				checkFunc: func(got TokenService) error {
					time.Sleep(time.Millisecond * 50)
					g, err := got.GetTokenProvider()()
					if err != nil {
						return err
					}
					if g != dummyTok {
						return fmt.Errorf("invalid token, got: %s", g)
					}

					return nil
				},
				afterFunc: func() {
					cancel()
				},
			}
		}(),
		func() test {
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
					refreshDuration: time.Millisecond * 50,
					builder: func() zmssvctoken.TokenBuilder {
						tb := NewMockTokenBuilder()
						tb.(*mockTokenBuilder).valueFunc = func() (string, error) {
							return fmt.Sprintf("dummyTok, time: %v", time.Now()), nil
						}

						return tb
					}(),
				},
				checkFunc: func(got TokenService) error {
					time.Sleep(time.Millisecond * 60)

					g, err := got.GetTokenProvider()()
					if err != nil {
						return err
					}

					cancel()
					time.Sleep(time.Millisecond * 110)

					g2, err := got.GetTokenProvider()()
					if err != nil {
						return err
					}

					if g != g2 {
						return fmt.Errorf("Context is canceled, but the token refreshed, g: %v\tg2: %v", g, g2)
					}
					return nil
				},
				afterFunc: func() {
					cancel()
				},
			}
		}(),
		func() test {
			dummyErr := errors.New("dummy error")
			ctx, cancel := context.WithCancel(context.Background())

			return test{
				name: "Check token builder return error",
				args: args{
					ctx: ctx,
				},
				fields: fields{
					tokenFilePath:   "",
					token:           new(atomic.Value),
					validateToken:   false,
					tokenExpiration: time.Second,
					refreshDuration: time.Millisecond * 50,
					builder: func() zmssvctoken.TokenBuilder {
						tb := NewMockTokenBuilder()
						tb.(*mockTokenBuilder).valueFunc = func() (string, error) {
							return "", dummyErr
						}

						return tb
					}(),
				},
				checkFunc: func(got TokenService) error {
					time.Sleep(time.Millisecond * 100)
					g, err := got.GetTokenProvider()()
					if g != "" || err != ErrTokenNotFound {
						return fmt.Errorf("Got: %v, want: %v", err, dummyErr)
					}

					return nil
				},
				afterFunc: func() {
					cancel()
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
			dummyTok := "dummyTok"

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
							return dummyTok, nil
						}

						return tb
					}(),
				},
				checkFunc: func(tok TokenService) error {
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					tok.StartTokenUpdater(ctx)
					time.Sleep(time.Millisecond * 50)

					got, err := tok.GetTokenProvider()()
					if err != nil {
						return err
					}
					if got != dummyTok {
						return fmt.Errorf("invalid token, got: %s, want: %s", got, dummyTok)
					}

					return nil
				},
			}
		}(),
		func() test {
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
				checkFunc: func(tok TokenService) error {
					got, err := tok.GetTokenProvider()()
					if got != "" || err == nil {
						return fmt.Errorf("Daemon is not started, but the GetToken didn't return error  got: %v", got)
					}
					return nil
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
			wantErr: ErrInvalidToken(ErrDomainNotFound),
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
				t, err := tv.GetTokenProvider()()
				if err != nil {
					return fmt.Errorf("unexpected error when get token, err: %v", err)
				}
				if t != "dummy token" { // compare with file content
					return fmt.Errorf("token is not same, got: %s, want: %s", t, "dummy token")
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
				t, err := tv.GetTokenProvider()()
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
		{
			name: "newRawToken parse success with empty pair",
			args: args{
				token: fmt.Sprintf("%v;%v;%v;%v;%v", "d=dummyDomain", "n=dummyName", "s=dummySign", "e=50000", ""),
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
			name: "newRawToken parse success with empty value",
			args: args{
				token: fmt.Sprintf("%v;%v;%v;%v", "d=", "n=", "s=", "e=50000"),
			},
			checkFunc: func(got, want *rawToken) error {
				if !reflect.DeepEqual(got, want) {
					return fmt.Errorf("got: %v, want: %v", got, want)
				}
				return nil
			},
			want: &rawToken{
				domain:     "",
				name:       "",
				signature:  "",
				expiration: time.Unix(50000, 0),
			},
		},
		{
			name: "newRawToken parse success with extra pair",
			args: args{
				token: fmt.Sprintf("%v;%v;%v;%v;%v", "d=dummyDomain", "n=dummyName", "s=dummySign", "e=50000", "dummy=dummy"),
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
			name: "newRawToken parse success with extra field",
			args: args{
				token: fmt.Sprintf("%v;%v;%v;%v;%v", "d=dummyDomain", "n=dummyName", "s=dummySign", "e=50000", "dummydummy"),
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
			wantErr: ErrTokenExpired,
		},
		{
			name: "isValid no domain",
			fields: fields{
				domain:     "",
				name:       "dummyName",
				signature:  "dummySign",
				expiration: time.Now().AddDate(0, 0, 1),
			},
			wantErr: ErrDomainNotFound,
		},
		{
			name: "isValid no name",
			fields: fields{
				domain:     "dummyDomain",
				name:       "",
				signature:  "dummySign",
				expiration: time.Now().AddDate(0, 0, 1),
			},
			wantErr: ErrServiceNameNotFound,
		},
		{
			name: "isValid no signature",
			fields: fields{
				domain:     "dummyDomain",
				name:       "dummyName",
				signature:  "",
				expiration: time.Now().AddDate(0, 0, 1),
			},
			wantErr: ErrSignatureNotFound,
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
*/
