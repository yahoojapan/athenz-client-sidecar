package service

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kpango/glg"
	"github.com/kpango/ntokend"
	"github.com/yahoojapan/athenz-client-sidecar/config"
)

// mockTransporter is the mock of RoundTripper
type mockTransporter struct {
	StatusCode int
	Body       []byte
	Method     string
	URL        *url.URL
	Error      error
}

// RoundTrip is used to crate a mock http response
func (m *mockTransporter) RoundTrip(req *http.Request) (*http.Response, error) {
	readcloser := ioutil.NopCloser(bytes.NewBuffer(m.Body))
	return &http.Response{
		Status:     fmt.Sprintf("%d %s", m.StatusCode, http.StatusText(m.StatusCode)),
		StatusCode: m.StatusCode,
		Body:       readcloser,
		Request: &http.Request{
			URL:    m.URL,
			Method: m.Method,
		},
	}, m.Error
}

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
			dur, _ := time.ParseDuration("30m")
			token := func() (string, error) { return "", nil }

			return test{
				name: "Success to initialize SvcCertService when spiffe is true",
				args: args{
					cfg: config.Config{
						Token: config.Token{
							PrivateKeyPath: "./assets/dummyServer.key",
						},
						ServiceCert: config.ServiceCert{
							AthenzRootCA:    "./assets/dummyCa.pem",
							RefreshDuration: "30m",
							Spiffe:          true,
						},
					},
					token: token,
				},
				want: &svcCertService{
					cfg: config.ServiceCert{
						AthenzRootCA:    "./assets/dummyCa.pem",
						RefreshDuration: "30m",
						Spiffe:          true,
					},
					token:           token,
					refreshDuration: dur,
				},
				checkfunc: func(actual, expected *svcCertService) bool {
					return actual.cfg.Spiffe == expected.cfg.Spiffe
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
	type test struct {
		name           string
		svcCertService SvcCertService
		want           string
		wantErr        error
	}

	tests := []test{
		func() test {
			dummyCertBytes, _ := ioutil.ReadFile("./assets/dummyServer.crt")
			dummyCaCertBytes, _ := ioutil.ReadFile("./assets/dummyCa.crt")
			dummyCert := strings.ReplaceAll(string(dummyCertBytes), "\n", "\\n")
			dummyCaCert := strings.ReplaceAll(string(dummyCaCertBytes), "\n", "\\n")

			dummyResponce := fmt.Sprintf(
				`{"name": "dummy", "certificate":"%s", "caCertBundle": "%s"}`, dummyCert, dummyCaCert,
			)
			token := func() (string, error) { return "dummyToken", nil }

			transpoter := &mockTransporter{
				StatusCode: 200,
				Body:       []byte(dummyResponce),
				Method:     "GET",
				Error:      nil,
			}

			cfg := config.Config{
				Token: config.Token{
					PrivateKeyPath: "./assets/dummyServer.key",
					AthenzDomain:   "dummyDomain",
					ServiceName:    "dummyService",
				},
				ServiceCert: config.ServiceCert{
					AthenzRootCA:            "./assets/dummyCa.pem",
					AthenzURL:               "http://dummy",
					RefreshDuration:         "30m",
					PrincipalAuthHeaderName: "Athenz-Principal",
					IntermediateCert:        true,
				},
			}

			s, _ := NewSvcCertService(cfg, token)
			svcCertService := s.(*svcCertService)

			svcCertService.client.Transport = transpoter

			return test{
				name:           "refreshSvcCert returns correct when IntermediateCert is true",
				svcCertService: svcCertService,
				want:           string(dummyCertBytes) + string(dummyCaCertBytes),
				wantErr:        nil,
			}
		}(),
		func() test {
			dummyCertBytes, _ := ioutil.ReadFile("./assets/dummyServer.crt")
			dummyCaCertBytes, _ := ioutil.ReadFile("./assets/dummyCa.crt")
			dummyCert := strings.ReplaceAll(string(dummyCertBytes), "\n", "\\n")
			dummyCaCert := strings.ReplaceAll(string(dummyCaCertBytes), "\n", "\\n")

			dummyResponce := fmt.Sprintf(
				`{"name": "dummy", "certificate":"%s", "caCertBundle": "%s"}`, dummyCert, dummyCaCert,
			)
			token := func() (string, error) { return "dummyToken", nil }

			transpoter := &mockTransporter{
				StatusCode: 200,
				Body:       []byte(dummyResponce),
				Method:     "GET",
				Error:      nil,
			}

			cfg := config.Config{
				Token: config.Token{
					PrivateKeyPath: "./assets/dummyServer.key",
					AthenzDomain:   "dummyDomain",
					ServiceName:    "dummyService",
				},
				ServiceCert: config.ServiceCert{
					AthenzRootCA:            "./assets/dummyCa.pem",
					AthenzURL:               "http://dummy",
					RefreshDuration:         "30m",
					PrincipalAuthHeaderName: "Athenz-Principal",
					IntermediateCert:        false,
				},
			}

			s, _ := NewSvcCertService(cfg, token)
			svcCertService := s.(*svcCertService)

			svcCertService.client.Transport = transpoter

			return test{
				name:           "refreshSvcCert returns correct when IntermediateCert is false",
				svcCertService: svcCertService,
				want:           string(dummyCertBytes),
				wantErr:        nil,
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.svcCertService.(*svcCertService)
			cert, err := s.refreshSvcCert()

			if tt.wantErr == nil && err != nil {
				t.Errorf("failed to instantiate, err: %v", err)
			} else if tt.wantErr != nil {
				if tt.wantErr.Error() != err.Error() {
					t.Errorf("error not the same, want: %v, got: %v", tt.wantErr, err)
				}
			} else if tt.want != string(cert) {
				t.Errorf("refreshSvcCert got: %v, want: %v", string(cert), tt.want)
			}
		})
	}
}
