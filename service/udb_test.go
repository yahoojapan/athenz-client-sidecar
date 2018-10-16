package service

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"ghe.corp.yahoo.co.jp/athenz/athenz-tenant-sidecar/config"
)

func TestNewUDBClient(t *testing.T) {
	type args struct {
		cfg config.UDB
		hc  CertProvider
	}
	type test struct {
		name string
		args args
		want UDB
	}
	tests := []test{
		func() test {
			cfg := config.UDB{
				URL: "dummyURL",
			}
			var hc CertProvider = nil

			return test{
				name: "NewUDBClient returns correct",
				args: args{
					cfg: cfg,
					hc:  hc,
				},
				want: &udb{
					hc:         hc,
					host:       cfg.URL,
					httpClient: http.DefaultClient,
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewUDBClient(tt.args.cfg, tt.args.hc)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewUDBClient() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_udb_GetByGUID(t *testing.T) {
	type fields struct {
		hc         CertProvider
		host       string
		httpClient *http.Client
	}
	type args struct {
		appID string
		guid  string
		keys  []string
	}
	type test struct {
		name      string
		fields    fields
		args      args
		checkFunc func(map[string]string, map[string]string) error
		afterFunc func() error
		want      map[string]string
		wantErr   bool
	}
	tests := []test{
		func() test {
			dummyContentA := base64.StdEncoding.EncodeToString([]byte("dummy"))
			dummyResult := fmt.Sprintf(`{"a": "%v"}`, dummyContentA)

			var url, method string
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				url = fmt.Sprintf("http://%s%s", r.Host, r.URL.RequestURI())
				method = r.Method
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, dummyResult)

			})
			dummyServer := httptest.NewServer(handler)

			dummyHost := dummyServer.URL
			dummyGUID := "dummyGuid"
			dummyKeys := []string{
				"a", "f",
			}

			return test{
				name: "GetByGUID request URL correct",

				fields: fields{
					hc: func(string) (string, error) {
						return "", nil
					},
					host:       dummyHost,
					httpClient: dummyServer.Client(),
				},
				args: args{
					appID: "",
					guid:  dummyGUID,
					keys:  dummyKeys,
				},
				checkFunc: func(got, want map[string]string) error {
					expectURL := fmt.Sprintf("%s/%s?fields=%s", dummyHost, dummyGUID, strings.Join(dummyKeys, ","))
					if url != expectURL {
						return fmt.Errorf("URL not expected, got: %v, want: %v", url, expectURL)
					}
					if method != http.MethodGet {
						return fmt.Errorf("HTTP method not match")
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
		t.Run(tt.name, func(t *testing.T) {
			u := &udb{
				hc:         tt.fields.hc,
				host:       tt.fields.host,
				httpClient: tt.fields.httpClient,
			}
			got, err := u.GetByGUID(tt.args.appID, tt.args.guid, tt.args.keys)
			if (err != nil) != tt.wantErr {
				t.Errorf("udb.GetByGUID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err := tt.checkFunc(got, tt.want); err != nil {
				t.Errorf("GetByGUID() err: %v", err)
			}
		})
	}
}

func Test_udb_doRequest(t *testing.T) {
	type fields struct {
		hc         CertProvider
		host       string
		httpClient *http.Client
	}
	type args struct {
		appID  string
		method string
		url    string
		cookie string
		body   io.Reader
	}
	type test struct {
		name      string
		fields    fields
		args      args
		want      map[string]string
		afterFunc func() error
		wantErr   error
	}
	tests := []test{
		test{
			name: "doRequest hc return error",
			args: args{
				method: "dummyMethod",
				url:    "dummyUrl",
			},
			fields: fields{
				hc: func(string) (string, error) {
					return "", fmt.Errorf("dummyError")
				},
			},
			wantErr: fmt.Errorf("dummyError"),
		},
		func() test {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			})
			dummyServer := httptest.NewServer(handler)

			return test{
				name: "doRequest httpclient response server error",
				args: args{
					method: "dummyMethod",
					url:    dummyServer.URL,
				},
				fields: fields{
					hc: func(string) (string, error) {
						return "", nil
					},
					httpClient: dummyServer.Client(),
				},
				afterFunc: func() error {
					dummyServer.Close()
					return nil
				},
				wantErr: fmt.Errorf("Error: response status 500"),
			}
		}(),
		func() test {
			dummyResult := `"a":"dummy"`
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, dummyResult)
			})
			dummyServer := httptest.NewServer(handler)

			return test{
				name: "doRequest httpclient invalid response json",
				args: args{
					method: "dummyMethod",
					url:    dummyServer.URL,
				},
				fields: fields{
					hc: func(string) (string, error) {
						return "", nil
					},
					httpClient: dummyServer.Client(),
				},
				afterFunc: func() error {
					dummyServer.Close()
					return nil
				},
				wantErr: fmt.Errorf("json: cannot unmarshal string into Go value of type map[string]string"),
			}
		}(),
		func() test {
			dummyResult := fmt.Sprintf(`{"a": "%v"}`, "dummy")
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, dummyResult)
			})
			dummyServer := httptest.NewServer(handler)

			return test{
				name: "doRequest httpclient invalid response base64 content",
				args: args{
					method: "dummyMethod",
					url:    dummyServer.URL,
				},
				fields: fields{
					hc: func(string) (string, error) {
						return "", nil
					},
					httpClient: dummyServer.Client(),
				},
				afterFunc: func() error {
					dummyServer.Close()
					return nil
				},
				wantErr: fmt.Errorf("illegal base64 data at input byte 4"),
			}
		}(),
		func() test {
			dummyResult := fmt.Sprintf(`{}`)
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, dummyResult)
			})
			dummyServer := httptest.NewServer(handler)

			return test{
				name: "doRequest httpclient return empty",
				args: args{
					method: "dummyMethod",
					url:    dummyServer.URL,
				},
				fields: fields{
					hc: func(string) (string, error) {
						return "", nil
					},
					httpClient: dummyServer.Client(),
				},
				afterFunc: func() error {
					dummyServer.Close()
					return nil
				},
				want: map[string]string{},
			}
		}(),
		func() test {
			dummyContentA := base64.StdEncoding.EncodeToString([]byte("dummy"))
			dummyResult := fmt.Sprintf(`{"a": "%v"}`, dummyContentA)
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, dummyResult)
			})
			dummyServer := httptest.NewServer(handler)

			return test{
				name: "doRequest httpclient return success",
				args: args{
					method: "dummyMethod",
					url:    dummyServer.URL,
				},
				fields: fields{
					hc: func(string) (string, error) {
						return "", nil
					},
					httpClient: dummyServer.Client(),
				},
				afterFunc: func() error {
					dummyServer.Close()
					return nil
				},
				want: map[string]string{
					"a": "dummy",
				},
			}
		}(),
		func() test {
			dummyContentA := base64.StdEncoding.EncodeToString([]byte("dummyA"))
			dummyContentB := base64.StdEncoding.EncodeToString([]byte("dummyB"))
			dummyContentC := base64.StdEncoding.EncodeToString([]byte("dummyC"))

			dummyResult := fmt.Sprintf(`{"a": "%v"
			, "b":"%v"
			,"c":"%v"}`, dummyContentA, dummyContentB, dummyContentC)
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, dummyResult)
			})
			dummyServer := httptest.NewServer(handler)

			return test{
				name: "doRequest httpclient return multiple values",
				args: args{
					method: "dummyMethod",
					url:    dummyServer.URL,
				},
				fields: fields{
					hc: func(string) (string, error) {
						return "", nil
					},
					httpClient: dummyServer.Client(),
				},
				afterFunc: func() error {
					dummyServer.Close()
					return nil
				},
				want: map[string]string{
					"a": "dummyA",
					"b": "dummyB",
					"c": "dummyC",
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.afterFunc != nil {
				defer tt.afterFunc()
			}

			u := &udb{
				hc:         tt.fields.hc,
				host:       tt.fields.host,
				httpClient: tt.fields.httpClient,
			}
			got, err := u.doRequest(tt.args.appID, tt.args.method, tt.args.url, tt.args.cookie, tt.args.body)
			if tt.wantErr == nil && err != nil {
				t.Errorf("failed to instantiate, err: %v", err)
				return
			} else if tt.wantErr != nil {
				if !strings.HasPrefix(tt.wantErr.Error(), err.Error()) {
					t.Errorf("error not the same, want: %v, got: %v", tt.wantErr, err)
				}
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("udb.doRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}
