package service

import (
	"net/http"
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
		checkfunc func(*svcCertService, *svcCertService) bool
	}

	tests := []test{
		func() test {
			dur, _ := time.ParseDuration("30m")
			token := func() (string, error) { return "", nil }
			tokenCfg := config.Token{}

			return test{
				name: "Success to initialize SvcCertService",
				args: args{
					cfg: config.Config{
						Token: tokenCfg,
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
					tokenCfg:        tokenCfg,
					token:           token,
					refreshDuration: dur,
				},
				checkfunc: func(actual, expected *svcCertService) bool {
					return (actual.cfg == expected.cfg) &&
						(actual.tokenCfg == expected.tokenCfg) &&
						(actual.refreshDuration == expected.refreshDuration)
				},
			}
		}(),
		func() test {
			dur := defaultRefreshDuration
			token := func() (string, error) { return "", nil }
			tokenCfg := config.Token{}

			return test{
				name: "Fail to parse RefreshDuration",
				args: args{
					cfg: config.Config{
						Token: tokenCfg,
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
					tokenCfg:        tokenCfg,
					token:           token,
					refreshDuration: dur,
				},
				checkfunc: func(actual, expected *svcCertService) bool {
					return true
				},
			}
		}(),
		func() test {
			dur, _ := time.ParseDuration("30m")
			token := func() (string, error) { return "", nil }
			tokenCfg := config.Token{}

			return test{
				name: "AthenzRootCA file dose not exist",
				args: args{
					cfg: config.Config{
						Token: tokenCfg,
						ServiceCert: config.ServiceCert{
							AthenzRootCA:    "/not/exist.pem",
							RefreshDuration: "30m",
						},
					},
					token: token,
				},
				want: &svcCertService{
					cfg: config.ServiceCert{
						AthenzRootCA:    "/not/exist.pem",
						RefreshDuration: "30m",
					},
					tokenCfg:        tokenCfg,
					token:           token,
					refreshDuration: dur,
				},
				checkfunc: func(actual, expected *svcCertService) bool {
					return actual.httpClient == http.DefaultClient
				},
			}
		}(),
		func() test {
			dur, _ := time.ParseDuration("30m")
			token := func() (string, error) { return "", nil }
			tokenCfg := config.Token{}

			return test{
				name: "AthenzRootCA dose not match x509",
				args: args{
					cfg: config.Config{
						Token: tokenCfg,
						ServiceCert: config.ServiceCert{
							AthenzRootCA:    "./assets/invalid_dummyCa.pem",
							RefreshDuration: "30m",
						},
					},
					token: token,
				},
				want: &svcCertService{
					cfg: config.ServiceCert{
						AthenzRootCA:    "./assets/invalid_dummyCa.pem",
						RefreshDuration: "30m",
					},
					tokenCfg:        tokenCfg,
					token:           token,
					refreshDuration: dur,
				},
				checkfunc: func(actual, expected *svcCertService) bool {
					return actual.httpClient == http.DefaultClient
				},
			}
		}(),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := NewSvcCertService(tt.args.cfg, tt.args.token)
			if actual == nil {
				t.Errorf("TestNewSvcCertService failed expected: %v, actual: %v", tt.want, actual)
			}

			actualSvcCertService := actual.(*svcCertService)
			expectedSvcCertService := tt.want.(*svcCertService)

			if (actualSvcCertService.cfg != expectedSvcCertService.cfg) ||
				(actualSvcCertService.tokenCfg != expectedSvcCertService.tokenCfg) ||
				(actualSvcCertService.refreshDuration != expectedSvcCertService.refreshDuration) ||
				!tt.checkfunc(actualSvcCertService, expectedSvcCertService) {
				t.Errorf("TestNewSvcCertService failed expected: %+v, actual: %+v", expectedSvcCertService, actualSvcCertService)
			}
		})
	}
}
