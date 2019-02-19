package service

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	ntokend "github.com/kpango/ntokend"
	"github.com/yahoojapan/athenz-client-sidecar/config"
	"github.com/kpango/gache"
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
	}
	tests := []test{
		func() test {
			args := args{
				cfg: config.Role{
					TokenExpiry:             "5s",
					AthenzURL:               "dummy",
					PrincipalAuthHeaderName: "dummyAuthHeader",
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
				name: "NewRoleService default expiry",
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
					expiry:                time.Minute * 120,
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewRoleService(tt.args.cfg, tt.args.token)

			if err := tt.checkFunc(got, tt.want); err != nil {
				t.Errorf("NewRoleService() err: %v", err)
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
	}
	type args struct {
		ctx context.Context
	}
	type test struct {
		name      string
		fields    fields
		args      args
		checkFunc func(RoleService) error
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

			domainRoleCache.SetWithExpire("dummyDomain-dummyRole", &cacheData{
				token: dummyRoleToken,
			}, time.Second)

			return test{
				name: "StartRoleUpdater",
				fields: fields{
					httpClient:            dummyServer.Client(),
					domainRoleCache:       domainRoleCache,
					expiry:                time.Second,
					athenzURL:             dummyServer.URL,
					athenzPrincipleHeader: "Athenz-Principal",
					token: func() (string, error) {
						return dummyToken2, nil
					},
				},
				args: args{
					ctx: context.Background(),
				},
				checkFunc: func(RoleService) error {

					roleTok1, ok := domainRoleCache.Get("dummyDomain-dummyRole")
					if !ok {
						return fmt.Errorf("cannot get first role token")
					}

					time.Sleep(time.Second * 2)

					roleTok2, ok := domainRoleCache.Get("dummyDomain-dummyRole")
					if !ok {
						return fmt.Errorf("cannot get second role token")
					}

					if reflect.DeepEqual(roleTok1, roleTok2) {
						return fmt.Errorf("Token did not updated, role token 1: %v, role token 2: %v", roleTok1, roleTok2)
					}

					return nil
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
			got := r.StartRoleUpdater(tt.args.ctx)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("roleService.StartRoleUpdater(), error: %v", err)
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
			if got := NewRoleService(config.Role{}, nil).GetRoleProvider(); got == nil {
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
			gac.Set("dummyDomain-dummyRole", &cacheData{
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
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "handleExpiredHook can run",
			fields: fields{
				httpClient:      httptest.NewTLSServer(nil).Client(),
				domainRoleCache: gache.New(),
				token: func() (string, error) {
					return "dummyToken", nil
				},
			},
			args: args{
				fctx: context.Background(),
				key:  "dummyKey",
			},
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
				httpClient:            tt.fields.httpClient,
			}
			r.handleExpiredHook(tt.args.fctx, tt.args.key)
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
				wantErr: fmt.Errorf("Get https://127.0.0.1:9876/domain/dummyDomain/token?role=dummyRole&minExpiryTime=1000000000&maxExpiryTime=1000000000&proxyForPrincipal=dummyProxy: dial tcp 127.0.0.1:9876: connect: connection refused"),
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
					_, ok := roleRoleCache.Get("dummyDomain-dummyRole")
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
			domainRoleCache.SetWithExpire("dummyDomain-dummyRole", &cacheData{
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
					tok, ok := domainRoleCache.Get("dummyDomain-dummyRole")
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

func Test_encode(t *testing.T) {
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
			name: "Encode correct",
			args: args{
				domain: "dummyDomain",
				role:   "dummyRole",
			},
			want: "dummyDomain-dummyRole",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := encode(tt.args.domain, tt.args.role); got != tt.want {
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
	}{
		{
			name: "decode correct",
			args: args{
				key: "dummyDomain-dummyRole",
			},
			want:  "dummyDomain",
			want1: "dummyRole",
		},
		{
			name: "decode correct no hyphen",
			args: args{
				key: "dummyDomain",
			},
			want:  "dummyDomain",
			want1: "",
		},
		{
			name: "decode correct 3 hyphen",
			args: args{
				key: "dummyDomain-domainRole-dummy1-dummy2",
			},
			want:  "dummyDomain",
			want1: "domainRole",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := decode(tt.args.key)
			if got != tt.want {
				t.Errorf("decode() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("decode() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func Test_getRoleTokenAthenzURL(t *testing.T) {
	type args struct {
		athenzURL         string
		domain            string
		role              string
		minExpiry         time.Duration
		maxExpiry         time.Duration
		proxyForPrincipal string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "getRoleTokenAthenzURL correct",
			args: args{
				athenzURL:         "dummyUURL",
				domain:            "dummyDomain",
				role:              "dummyRole",
				minExpiry:         time.Second,
				maxExpiry:         time.Second,
				proxyForPrincipal: "dummyProxyForPrincipal",
			},
			want: "https://dummyUURL/domain/dummyDomain/token?role=dummyRole&minExpiryTime=1000000000&maxExpiryTime=1000000000&proxyForPrincipal=dummyProxyForPrincipal",
		},
		{
			name: "getRoleTokenAthenzURL correct null minExpiry",
			args: args{
				athenzURL:         "dummyUURL",
				domain:            "dummyDomain",
				role:              "dummyRole",
				maxExpiry:         time.Second,
				proxyForPrincipal: "dummyProxyForPrincipal",
			},
			want: "https://dummyUURL/domain/dummyDomain/token?role=dummyRole&maxExpiryTime=1000000000&proxyForPrincipal=dummyProxyForPrincipal",
		},
		{
			name: "getRoleTokenAthenzURL correct null maxExpiry",
			args: args{
				athenzURL:         "dummyUURL",
				domain:            "dummyDomain",
				role:              "dummyRole",
				minExpiry:         time.Second,
				proxyForPrincipal: "dummyProxyForPrincipal",
			},
			want: "https://dummyUURL/domain/dummyDomain/token?role=dummyRole&minExpiryTime=1000000000&maxExpiryTime=0&proxyForPrincipal=dummyProxyForPrincipal",
		},
		{
			name: "getRoleTokenAthenzURL correct null proxyForPrincipal",
			args: args{
				athenzURL: "dummyUURL",
				domain:    "dummyDomain",
				role:      "dummyRole",
				minExpiry: time.Second,
				maxExpiry: time.Second,
			},
			want: "https://dummyUURL/domain/dummyDomain/token?role=dummyRole&minExpiryTime=1000000000&maxExpiryTime=1000000000&proxyForPrincipal=",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getRoleTokenAthenzURL(tt.args.athenzURL, tt.args.domain, tt.args.role, tt.args.minExpiry, tt.args.maxExpiry, tt.args.proxyForPrincipal); got != tt.want {
				t.Errorf("getRoleTokenAthenzURL() = %v, want %v", got, tt.want)
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
			domainRoleCache.Set("dummyDomain-dummyRole", &cacheData{
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
