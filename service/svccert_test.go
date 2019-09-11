package service

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kpango/fastime"
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
			beforeDur, _ := time.ParseDuration("-1h")
			token := func() (string, error) { return "", nil }

			return test{
				name: "Success to initialize SvcCertService with before_expiration",
				args: args{
					cfg: config.Config{
						Token: config.Token{
							PrivateKeyPath: "./assets/dummyServer.key",
						},
						ServiceCert: config.ServiceCert{
							AthenzRootCA:     "./assets/dummyCa.pem",
							RefreshDuration:  "30m",
							BeforeExpiration: "1h",
						},
					},
					token: token,
				},
				want: &svcCertService{
					cfg: config.ServiceCert{
						AthenzRootCA:     "./assets/dummyCa.pem",
						RefreshDuration:  "30m",
						BeforeExpiration: "1h",
					},
					token:            token,
					refreshDuration:  dur,
					beforeExpiration: beforeDur,
				},
				checkfunc: func(actual, expected *svcCertService) bool {
					return actual.beforeExpiration == expected.beforeExpiration
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
			dur, _ := time.ParseDuration("30m")
			token := func() (string, error) { return "", nil }

			return test{
				name: "Fail to parse before_expiration",
				args: args{
					cfg: config.Config{
						Token: config.Token{
							PrivateKeyPath: "./assets/dummyServer.key",
						},
						ServiceCert: config.ServiceCert{
							AthenzRootCA:     "./assets/dummyCa.pem",
							RefreshDuration:  "30m",
							BeforeExpiration: "error",
						},
					},
					token: token,
				},
				want: &svcCertService{
					cfg: config.ServiceCert{
						AthenzRootCA:     "./assets/dummyCa.pem",
						RefreshDuration:  "30m",
						BeforeExpiration: "error",
					},
					token:            token,
					refreshDuration:  dur,
					beforeExpiration: defaultSvcCertBeforeExpiration,
				},
				checkfunc: func(actual, expected *svcCertService) bool {
					return actual.beforeExpiration == expected.beforeExpiration
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

func Test_svccertService_GetSvcCertProvider(t *testing.T) {
	svcCertService, _ := NewSvcCertService(
		config.Config{
			Token: config.Token{
				PrivateKeyPath: "./assets/dummyServer.key",
			},
			ServiceCert: config.ServiceCert{
				AthenzRootCA:    "./assets/dummyCa.pem",
				RefreshDuration: "30m",
			},
		},
		func() (string, error) { return "ntoken", nil },
	)

	if svcCertService.GetSvcCertProvider() == nil {
		t.Error("GetSvcCertProvider is nil")
	}
}

// mockTransporter is the mock of RoundTripper
type mockTransporter struct {
	StatusCode int
	Body       [][]byte
	Method     string
	URL        *url.URL
	Error      error
	Counter    int
}

// RoundTrip is used to create a mock http response
func (m *mockTransporter) RoundTrip(req *http.Request) (*http.Response, error) {
	m.Counter = m.Counter + 1
	return &http.Response{
		Status:     fmt.Sprintf("%d %s", m.StatusCode, http.StatusText(m.StatusCode)),
		StatusCode: m.StatusCode,
		Body:       ioutil.NopCloser(bytes.NewBuffer(m.Body[m.Counter-1])),
		Request: &http.Request{
			URL:    m.URL,
			Method: m.Method,
		},
	}, m.Error
}

func Test_svccertService_getSvcCert(t *testing.T) {
	type test struct {
		name           string
		svcCertService SvcCertService
		want           []byte
		wantErr        error
	}

	tests := []test{
		func() test {
			dummyCertBytes, _ := ioutil.ReadFile("./assets/dummyServer.crt")
			dummyCaCertBytes, _ := ioutil.ReadFile("./assets/dummyCa.pem")
			dummyCert := strings.ReplaceAll(string(dummyCertBytes), "\n", "\\n")
			dummyCaCert := strings.ReplaceAll(string(dummyCaCertBytes), "\n", "\\n")

			dummyResponce := fmt.Sprintf(
				`{"name": "dummy", "certificate":"%s", "caCertBundle": "%s"}`, dummyCert, dummyCaCert,
			)
			token := func() (string, error) { return "dummyToken", nil }

			transpoter := &mockTransporter{
				StatusCode: 200,
				Body:       [][]byte{[]byte(dummyResponce)},
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
			svcCertService.svcCert.Store(dummyCertBytes)
			svcCertService.expiration.Store(fastime.Now().Add(time.Hour))

			return test{
				name:           "getSvcCert returns stored value.",
				svcCertService: svcCertService,
				want:           dummyCertBytes,
				wantErr:        nil,
			}
		}(),
		func() test {
			dummyCertBytes, _ := ioutil.ReadFile("./assets/dummyServer.crt")
			dummyCaCertBytes, _ := ioutil.ReadFile("./assets/dummyCa.pem")
			dummyCert := strings.ReplaceAll(string(dummyCertBytes), "\n", "\\n")
			dummyCaCert := strings.ReplaceAll(string(dummyCaCertBytes), "\n", "\\n")

			dummyResponce := fmt.Sprintf(
				`{"name": "dummy", "certificate":"%s", "caCertBundle": "%s"}`, dummyCert, dummyCaCert,
			)
			token := func() (string, error) { return "dummyToken", nil }

			transpoter := &mockTransporter{
				StatusCode: 200,
				Body:       [][]byte{[]byte(dummyResponce)},
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
				name:           "getSvcCert returns value from refreshSvcCert",
				svcCertService: svcCertService,
				want:           append(dummyCertBytes, dummyCaCertBytes...),
				wantErr:        nil,
			}
		}(),
		func() test {
			dummyCertBytes, _ := ioutil.ReadFile("./assets/dummyServer.crt")
			dummyCaCertBytes, _ := ioutil.ReadFile("./assets/dummyCa.pem")
			dummyCert := strings.ReplaceAll(string(dummyCertBytes), "\n", "\\n")
			dummyCaCert := strings.ReplaceAll(string(dummyCaCertBytes), "\n", "\\n")

			dummyResponce := fmt.Sprintf(
				`{"name": "dummy", "certificate":"%s", "caCertBundle": "%s"}`, dummyCert, dummyCaCert,
			)
			token := func() (string, error) { return "dummyToken", nil }

			transpoter := &mockTransporter{
				StatusCode: 200,
				Body:       [][]byte{[]byte(dummyResponce)},
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
					BeforeExpiration:        "1000h",
				},
			}

			s, _ := NewSvcCertService(cfg, token)
			svcCertService := s.(*svcCertService)
			svcCertService.svcCert.Store(dummyCertBytes)

			svcCertService.client.Transport = transpoter

			return test{
				name:           "getSvcCert returns value from refreshSvcCert when expiration is before now.",
				svcCertService: svcCertService,
				want:           append(dummyCertBytes, dummyCaCertBytes...),
				wantErr:        nil,
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.svcCertService.(*svcCertService)
			cert, err := s.getSvcCert()

			if tt.wantErr == nil && err != nil {
				t.Errorf("failed to instantiate, err: %v", err)
			} else if tt.wantErr != nil {
				if tt.wantErr.Error() != err.Error() {
					t.Errorf("error not the same, want: %v, got: %v", tt.wantErr, err)
				}
			} else if string(tt.want) != string(cert) {
				t.Errorf("refreshSvcCert got: %v, want: %v", string(cert), string(tt.want))
			}
		})
	}
}

func Test_svccertService_StartSvcCertUpdater(t *testing.T) {
	type test struct {
		name           string
		svcCertService SvcCertService
		checkFunc      func(*svcCertService, *testing.T)
		afterFunc      func()
	}

	tests := []test{
		func() test {
			ctx, cancel := context.WithCancel(context.Background())

			dummyCertBytes, _ := ioutil.ReadFile("./assets/dummyServer.crt")
			dummyCaCertBytes, _ := ioutil.ReadFile("./assets/dummyCa.pem")
			dummyCert := strings.ReplaceAll(string(dummyCertBytes), "\n", "\\n")
			dummyCaCert := strings.ReplaceAll(string(dummyCaCertBytes), "\n", "\\n")

			dummyResponce := [][]byte{
				[]byte(fmt.Sprintf(`{"name": "dummy", "certificate":"%s", "caCertBundle": "%s"}`, dummyCert, dummyCaCert)),
				[]byte(fmt.Sprintf(`{"name": "dummy", "certificate":"%s", "caCertBundle": "%s"}`, dummyCaCert, dummyCaCert)),
			}

			token := func() (string, error) { return "dummyToken", nil }

			transpoter := &mockTransporter{
				StatusCode: 200,
				Body:       dummyResponce,
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
					RefreshDuration:         "100ms",
					PrincipalAuthHeaderName: "Athenz-Principal",
					IntermediateCert:        true,
				},
			}

			checkFunc := func(s *svcCertService, t *testing.T) {
				s.StartSvcCertUpdater(ctx)
				cert1, _ := s.GetSvcCertProvider()()
				time.Sleep(time.Millisecond * 120)
				cert2, _ := s.GetSvcCertProvider()()
				if string(cert1) == string(cert2) {
					t.Errorf("cert did not refreshed")
				}
			}

			s, _ := NewSvcCertService(cfg, token)
			svcCertService := s.(*svcCertService)

			svcCertService.client.Transport = transpoter

			return test{
				name:           "cert is refreshed successfully",
				svcCertService: svcCertService,
				checkFunc:      checkFunc,
				afterFunc:      cancel,
			}
		}(),
		func() test {
			ctx, cancel := context.WithCancel(context.Background())

			dummyCertBytes, _ := ioutil.ReadFile("./assets/dummyServer.crt")
			dummyCaCertBytes, _ := ioutil.ReadFile("./assets/dummyCa.pem")
			dummyCert := strings.ReplaceAll(string(dummyCertBytes), "\n", "\\n")
			dummyCaCert := strings.ReplaceAll(string(dummyCaCertBytes), "\n", "\\n")

			dummyResponce := [][]byte{
				[]byte(fmt.Sprintf(`{"name": "dummy", "certificate":"%s", "caCertBundle": "%s"}`, dummyCert, dummyCaCert)),
				[]byte(fmt.Sprintf(`{"name": "dummy", "certificate":"%s", "caCertBundle": "%s"}`, dummyCaCert, dummyCaCert)),
			}

			token := func() (string, error) { return "", fmt.Errorf("error") }

			transpoter := &mockTransporter{
				StatusCode: 200,
				Body:       dummyResponce,
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
					RefreshDuration:         "100ms",
					PrincipalAuthHeaderName: "Athenz-Principal",
					IntermediateCert:        true,
				},
			}

			checkFunc := func(s *svcCertService, t *testing.T) {
				s.StartSvcCertUpdater(ctx)
				cert1, _ := s.GetSvcCertProvider()()
				time.Sleep(time.Millisecond * 250)
				cert2, _ := s.GetSvcCertProvider()()
				if string(cert1) != string(cert2) {
					t.Errorf("cert refreshed")
				}
			}

			s, _ := NewSvcCertService(cfg, token)
			svcCertService := s.(*svcCertService)

			svcCertService.client.Transport = transpoter

			return test{
				name:           "fail to refresh cert when refreshSvcCert returns error",
				svcCertService: svcCertService,
				checkFunc:      checkFunc,
				afterFunc:      cancel,
			}
		}(),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.svcCertService.(*svcCertService)

			defer tt.afterFunc()

			if tt.checkFunc == nil {
				t.Errorf("checkfunc is nil")
			} else {
				tt.checkFunc(s, t)
			}
		})
	}

}

func Test_svccertService_refreshSvcCert(t *testing.T) {
	type test struct {
		name           string
		svcCertService SvcCertService
		want           []byte
		wantErr        error
	}

	tests := []test{
		func() test {
			dummyCertBytes, _ := ioutil.ReadFile("./assets/dummyServer.crt")
			dummyCaCertBytes, _ := ioutil.ReadFile("./assets/dummyCa.pem")
			dummyCert := strings.ReplaceAll(string(dummyCertBytes), "\n", "\\n")
			dummyCaCert := strings.ReplaceAll(string(dummyCaCertBytes), "\n", "\\n")

			dummyResponce := fmt.Sprintf(
				`{"name": "dummy", "certificate":"%s", "caCertBundle": "%s"}`, dummyCert, dummyCaCert,
			)
			token := func() (string, error) { return "dummyToken", nil }

			transpoter := &mockTransporter{
				StatusCode: 200,
				Body:       [][]byte{[]byte(dummyResponce)},
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
				want:           append(dummyCertBytes, dummyCaCertBytes...),
				wantErr:        nil,
			}
		}(),
		func() test {
			dummyCertBytes, _ := ioutil.ReadFile("./assets/dummyServer.crt")
			dummyCaCertBytes, _ := ioutil.ReadFile("./assets/dummyCa.pem")
			dummyCert := strings.ReplaceAll(string(dummyCertBytes), "\n", "\\n")
			dummyCaCert := strings.ReplaceAll(string(dummyCaCertBytes), "\n", "\\n")

			dummyResponce := fmt.Sprintf(
				`{"name": "dummy", "certificate":"%s", "caCertBundle": "%s"}`, dummyCert, dummyCaCert,
			)
			token := func() (string, error) { return "dummyToken", nil }

			transpoter := &mockTransporter{
				StatusCode: 200,
				Body:       [][]byte{[]byte(dummyResponce)},
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
				want:           dummyCertBytes,
				wantErr:        nil,
			}
		}(),
		func() test {
			dummyCertBytes, _ := ioutil.ReadFile("./assets/dummyServer.crt")
			dummyCaCertBytes, _ := ioutil.ReadFile("./assets/dummyCa.pem")
			dummyCert := strings.ReplaceAll(string(dummyCertBytes), "\n", "\\n")
			dummyCaCert := strings.ReplaceAll(string(dummyCaCertBytes), "\n", "\\n")

			dummyResponce := fmt.Sprintf(
				`{"name": "dummy", "certificate":"%s", "caCertBundle": "%s"}`, dummyCert, dummyCaCert,
			)
			token := func() (string, error) { return "", fmt.Errorf("ntoken error") }

			transpoter := &mockTransporter{
				StatusCode: 200,
				Body:       [][]byte{[]byte(dummyResponce)},
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
				name:           "refreshSvcCert fail when ntokend returns error",
				svcCertService: svcCertService,
				want:           nil,
				wantErr:        fmt.Errorf("ntoken error"),
			}
		}(),
		func() test {
			token := func() (string, error) { return "dummyToken", nil }

			transpoter := &mockTransporter{
				StatusCode: 200,
				Body:       [][]byte{[]byte("{}")},
				Method:     "GET",
				Error:      fmt.Errorf("request error"),
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

			wantErr := fmt.Errorf(
				"Post %s/instance/%s/%s/refresh: request error",
				cfg.ServiceCert.AthenzURL,
				cfg.Token.AthenzDomain,
				cfg.Token.ServiceName,
			)

			return test{
				name:           "refreshSvcCert fail when request failed",
				svcCertService: svcCertService,
				want:           nil,
				wantErr:        wantErr,
			}
		}(),
		func() test {
			dummyCertBytes, _ := ioutil.ReadFile("./assets/invalid_dummyServer.crt")
			dummyCaCertBytes, _ := ioutil.ReadFile("./assets/dummyCa.pem")
			dummyCert := strings.ReplaceAll(string(dummyCertBytes), "\n", "\\n")
			dummyCaCert := strings.ReplaceAll(string(dummyCaCertBytes), "\n", "\\n")

			dummyResponce := fmt.Sprintf(
				`{"name": "dummy", "certificate":"%s", "caCertBundle": "%s"}`, dummyCert, dummyCaCert,
			)
			token := func() (string, error) { return "dummyToken", nil }

			transpoter := &mockTransporter{
				StatusCode: 200,
				Body:       [][]byte{[]byte(dummyResponce)},
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
				name:           "refreshSvcCert fail when recieved cert is invalid",
				svcCertService: svcCertService,
				want:           nil,
				wantErr:        ErrInvalidCert,
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
			} else if string(tt.want) != string(cert) {
				t.Errorf("refreshSvcCert got: %v, want: %v", string(cert), tt.want)
			}
		})
	}
}
