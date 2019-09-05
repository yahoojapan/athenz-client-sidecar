package service

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/kpango/glg"
	"github.com/kpango/ntokend"
	"github.com/yahoojapan/athenz-client-sidecar/config"
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
		name      string
		args      args
		want      SvcCertService
		wantErr   error
		checkfunc func(*svcCertService, *svcCertService) bool
	}

	tests := []test{
		func() test {
			dur, _ := time.ParseDuration("30m")
			token := func() (string, error) { return "", nil }

			return test{
				name: "Success to initialize SvcCertService",
				args: args{
					cfg: config.Config{
						Token: config.Token{
							PrivateKeyPath: "./assets/dummyServer.key",
						},
						ServiceCert: config.ServiceCert{
							AthenzRootCA:    "./assets/dummyCa.pem",
							RefreshDuration: "30m",
						},
					},
					token: token,
				},
				want: &svcCertService{
					cfg: config.ServiceCert{
						AthenzRootCA:    "./assets/dummyCa.pem",
						RefreshDuration: "30m",
					},
					token:           token,
					refreshDuration: dur,
				},
				checkfunc: func(actual, expected *svcCertService) bool {
					return true
				},
				wantErr: nil,
			}
		}(),
		func() test {
			dur, _ := time.ParseDuration("30m")
			token := func() (string, error) { return "", nil }

			return test{
				name: "Success to initialize SvcCertService using EC PRIVATE KEY",
				args: args{
					cfg: config.Config{
						Token: config.Token{
							PrivateKeyPath: "./assets/dummyECServer.key",
						},
						ServiceCert: config.ServiceCert{
							AthenzRootCA:    "./assets/dummyCa.pem",
							RefreshDuration: "30m",
						},
					},
					token: token,
				},
				want: &svcCertService{
					cfg: config.ServiceCert{
						AthenzRootCA:    "./assets/dummyCa.pem",
						RefreshDuration: "30m",
					},
					token:           token,
					refreshDuration: dur,
				},
				checkfunc: func(actual, expected *svcCertService) bool {
					return true
				},
				wantErr: nil,
			}
		}(),

		func() test {
			token := func() (string, error) { return "", nil }

			return test{
				name: "Fail to parse RefreshDuration",
				args: args{
					cfg: config.Config{
						Token: config.Token{
							PrivateKeyPath: "./assets/dummyServer.key",
						},
						ServiceCert: config.ServiceCert{
							AthenzRootCA:    "./assets/dummyCa.pem",
							RefreshDuration: "",
						},
					},
					token: token,
				},
				want: &svcCertService{
					cfg: config.ServiceCert{
						AthenzRootCA:    "./assets/dummyCa.pem",
						RefreshDuration: "",
					},
					token:           token,
					refreshDuration: defaultSvcCertRefreshDuration,
				},
				checkfunc: func(actual, expected *svcCertService) bool {
					return true
				},
				wantErr: nil,
			}
		}(),
		func() test {
			token := func() (string, error) { return "", nil }

			return test{
				name: "Private key file does not exist",
				args: args{
					cfg: config.Config{
						Token: config.Token{
							PrivateKeyPath: "/not/exist.key",
						},
						ServiceCert: config.ServiceCert{
							AthenzRootCA:    "./assets/dummyCa.pem",
							RefreshDuration: "30m",
						},
					},
					token: token,
				},
				want:    &svcCertService{},
				wantErr: ErrLoadPrivateKey,
				checkfunc: func(actual, expected *svcCertService) bool {
					return true
				},
			}
		}(),
		func() test {
			token := func() (string, error) { return "", nil }

			return test{
				name: "Private key is invalid",
				args: args{
					cfg: config.Config{
						Token: config.Token{
							PrivateKeyPath: "./assets/invalid_dummyServer.key",
						},
						ServiceCert: config.ServiceCert{
							AthenzRootCA:    "./assets/dummyCa.pem",
							RefreshDuration: "30m",
						},
					},
					token: token,
				},
				want:    &svcCertService{},
				wantErr: ErrFailedToInitialize,
				checkfunc: func(actual, expected *svcCertService) bool {
					return true
				},
			}
		}(),
		func() test {
			token := func() (string, error) { return "", nil }

			return test{
				name: "AthenzRootCA file does not exist",
				args: args{
					cfg: config.Config{
						Token: config.Token{
							PrivateKeyPath: "./assets/dummyServer.key",
						},
						ServiceCert: config.ServiceCert{
							AthenzRootCA:    "/not/exist.pem",
							RefreshDuration: "30m",
						},
					},
					token: token,
				},
				want:    &svcCertService{},
				wantErr: ErrFailedToInitialize,
				checkfunc: func(actual, expected *svcCertService) bool {
					return true
				},
			}
		}(),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := NewSvcCertService(tt.args.cfg, tt.args.token)

			if err != tt.wantErr {
				t.Errorf("TestNewSvcCertService failed. expected error: %v, actual error: %v", tt.wantErr, err)
			}
			if err != nil {
				return
			}

			actualSvcCertService := actual.(*svcCertService)
			expectedSvcCertService := tt.want.(*svcCertService)

			if (actualSvcCertService.cfg != expectedSvcCertService.cfg) ||
				(actualSvcCertService.refreshDuration != expectedSvcCertService.refreshDuration) ||
				!tt.checkfunc(actualSvcCertService, expectedSvcCertService) {
				t.Errorf("TestNewSvcCertService failed expected: %+v, actual: %+v", expectedSvcCertService, actualSvcCertService)
			}
		})
	}
}

func Test_svccertService_refreshSvcCert(t *testing.T) {
	// type fields struct {
	// 	cfg                   config.Role
	// 	token                 ntokend.TokenProvider
	// 	athenzURL             string
	// 	athenzPrincipleHeader string
	// 	domainRoleCache       gache.Gache
	// 	group                 singleflight.Group
	// 	expiry                time.Duration
	// 	httpClient            *http.Client
	// }
	// type test struct {
	// 	name       string
	// 	fields     fields
	// 	args       args
	// 	beforeFunc func() error
	// 	checkFunc  func(got, want *RoleToken) error
	// 	afterFunc  func() error
	// 	want       *RoleToken
	// 	wantErr    error
	// }

	type args struct {
		cfg   config.Config
		token ntokend.TokenProvider
	}
	type test struct {
		name      string
		args      args
		want      SvcCertService
		wantErr   error
		checkFunc func(*svcCertService, *svcCertService) bool
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
				name: "refreshSvcCert returns correct",
				// fields: fields{
				// 	httpClient:      dummyServer.Client(),
				// 	domainRoleCache: gache.New(),
				// 	token: func() (string, error) {
				// 		return dummyToken, nil
				// 	},
				// 	athenzURL:             dummyServer.URL,
				// 	athenzPrincipleHeader: "Athenz-Principal",
				// },
				args: args{
					token: dummyToken,
				},
				afterFunc: func() error {
					dummyServer.Close()
					return nil
				},
				want: &svcCertService{
					cfg: config.ServiceCert{
						AthenzRootCA:    "./assets/dummyCa.pem",
						RefreshDuration: "30m",
					},
					token:           dummyToken,
					refreshDuration: dur,
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dur, _ := time.ParseDuration("30m")
			token := func() (string, error) { return "", nil }

			s := &svcCertService{
				cfg: config.ServiceCert{
					AthenzRootCA:    "./assets/dummyCa.pem",
					RefreshDuration: "30m",
				},
				token:           token,
				refreshDuration: dur,
			}

			actual, err := s.refreshSvcCert()

			if tt.wantErr == nil && err != nil {
				t.Errorf("failed to instantiate, err: %v", err)
				return
			} else if tt.wantErr != nil {
				if tt.wantErr.Error() != err.Error() {
					t.Errorf("error not the same, want: %v, got: %v", tt.wantErr, err)
				}
			}

			if tt.checkFunc != nil {
				if err := tt.checkFunc(actual, tt.want); err != nil {
					t.Errorf("svcCertService.refreshSvcCert() = %v", err)
				}
			} else {
				if !reflect.DeepEqual(actual, tt.want) {
					t.Errorf("svcCertService.refreshSvcCert() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}
