package handler

import (
	"testing"

	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"reflect"
	"strings"
	"time"

	ntokend "ghe.corp.yahoo.co.jp/athenz/athenz-ntokend"
	"ghe.corp.yahoo.co.jp/athenz/athenz-tenant-sidecar/config"
	"ghe.corp.yahoo.co.jp/athenz/athenz-tenant-sidecar/infra"
	"ghe.corp.yahoo.co.jp/athenz/athenz-tenant-sidecar/service"
)

// NotEqualError reports the name of the field having different value and their values.
type NotEqualError struct {
	Field string
	Got   interface{}
	Want  interface{}
}

// Error formats NotEqualError.
func (e *NotEqualError) Error() string {
	return fmt.Sprintf("%s got = %v, want %v", e.Field, e.Got, e.Want)
}

// EqualResponse checks whether the ResponseRecorder contains the expected content passed in.
func EqualResponse(writer http.ResponseWriter, code int, header map[string]string, body []byte) error {
	recorder, ok := writer.(*httptest.ResponseRecorder)
	if !ok {
		return fmt.Errorf("expect type: *httptest.ResponseRecorder")
	}

	// check code
	if recorder.Code != code {
		return &NotEqualError{"code", recorder.Code, code}
	}

	// check header
	for k, v := range header {
		if recorder.HeaderMap.Get(k) != v {
			return &NotEqualError{"header", recorder.HeaderMap.Get(k), v}
		}
	}

	// check body
	if !bytes.Equal(recorder.Body.Bytes(), body) {
		return &NotEqualError{"body", string(recorder.Body.Bytes()), string(body)}
	}

	return nil
}

func TestNew(t *testing.T) {
	type args struct {
		cfg   config.Proxy
		bp    httputil.BufferPool
		token ntokend.TokenProvider
		role  service.RoleProvider
	}
	type testcase struct {
		name      string
		args      args
		want      *handler
		checkFunc func(got, want *handler) error
	}
	tests := []testcase{
		testcase{
			name: "Check New, works normally",
			args: args{
				cfg: config.Proxy{
					BufferSize: 72,
					AuthHeader: "auth-header-73",
				},
				bp: infra.NewBuffer(uint64(75)),
				token: func() (string, error) {
					return "token-85", fmt.Errorf("get-token-error-85")
				},
				role: func(ctx context.Context, domain string, role string, proxyForPrincipal string, minExpiry time.Duration, maxExpiry time.Duration) (*service.RoleToken, error) {
					return &service.RoleToken{
						Token:      "role-token-89",
						ExpiryTime: 90,
					}, fmt.Errorf("get-role-token-error-91")
				},
			},
			want: &handler{
				cfg: config.Proxy{
					BufferSize: 72,
					AuthHeader: "auth-header-73",
				},
			},
			checkFunc: func(got, want *handler) error {

				// cfg
				if !reflect.DeepEqual(got.cfg, want.cfg) {
					return &NotEqualError{"cfg", got.cfg, want.cfg}
				}

				// token
				gotToken, gotError := got.token()
				wantToken, wantError := "token-85", fmt.Errorf("get-token-error-85")
				if !reflect.DeepEqual(gotToken, wantToken) {
					return &NotEqualError{"token()", gotToken, wantToken}
				}
				if !reflect.DeepEqual(gotError, wantError) {
					return &NotEqualError{"token() err", gotError, wantError}
				}

				// role
				gotRoleToken, gotError := got.role(nil, "", "", "", 0, 0)
				wantRoleToken, wantError := &service.RoleToken{
					Token:      "role-token-89",
					ExpiryTime: 90,
				}, fmt.Errorf("get-role-token-error-91")
				if !reflect.DeepEqual(gotRoleToken, wantRoleToken) {
					return &NotEqualError{"role()", gotRoleToken, wantRoleToken}
				}
				if !reflect.DeepEqual(gotError, wantError) {
					return &NotEqualError{"role() err", gotError, wantError}
				}

				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := New(tt.args.cfg, tt.args.bp, tt.args.token, tt.args.role)
			if err := tt.checkFunc(got.(*handler), tt.want); err != nil {
				t.Errorf("New() %v", err)
				return
			}
		})
	}
}

func Test_handler_NToken(t *testing.T) {
	type fields struct {
		token ntokend.TokenProvider
	}
	type args struct {
		w http.ResponseWriter
		r *http.Request
	}
	type want struct {
		code   int
		header map[string]string
		body   []byte
	}
	type testcase struct {
		name      string
		fields    fields
		args      args
		want      want
		wantError error
	}
	tests := []testcase{
		testcase{
			name: "Check handler NToken, on token error",
			fields: fields{
				token: func() (string, error) {
					return "token-207", fmt.Errorf("get-token-error-207")
				},
			},
			args: args{
				w: httptest.NewRecorder(),
				r: httptest.NewRequest(http.MethodGet, "http://url-212", nil),
			},
			want: want{
				code:   http.StatusOK,
				header: map[string]string{},
				body:   []byte{},
			},
			wantError: fmt.Errorf("get-token-error-207"),
		},
		testcase{
			name: "Check handler NToken, response token as json",
			fields: fields{
				token: func() (string, error) {
					return "token-230", nil
				},
			},
			args: args{
				w: httptest.NewRecorder(),
				r: httptest.NewRequest(http.MethodGet, "http://url-235", nil),
			},
			want: want{
				code:   http.StatusOK,
				header: map[string]string{},
				body:   []byte(`{"n_token":"token-230"}` + "\n"),
			},
		},
		testcase{
			name: "Check handler NToken, request body closed",
			fields: fields{
				token: func() (string, error) {
					return "token-247", nil
				},
			},
			args: args{
				w: httptest.NewRecorder(),
				r: httptest.NewRequest(http.MethodPost, "http://url-252", strings.NewReader("body-252")),
			},
			want: want{
				code:   http.StatusOK,
				header: map[string]string{},
				body:   []byte(`{"n_token":"token-247"}` + "\n"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			var err error
			h := &handler{
				token: tt.fields.token,
			}

			gotError := h.NToken(tt.args.w, tt.args.r)
			if !reflect.DeepEqual(gotError, tt.wantError) {
				err = &NotEqualError{"error", gotError, tt.wantError}
			}
			if err != nil {
				t.Errorf("handler.NToken() %v", err)
				return
			}

			err = EqualResponse(tt.args.w, tt.want.code, tt.want.header, tt.want.body)
			if err != nil {
				t.Errorf("handler.NToken() %v", err)
				return
			}

			// check if the response's body is closed
			if tt.args.r.Body != nil {
				byteRead, err := tt.args.r.Body.Read(make([]byte, 64))
				if byteRead != 0 || err != io.EOF {
					t.Errorf("handler.NToken() request not closed, %v bytes read, err %v", byteRead, err)
					return
				}
			}
		})
	}
}

// roundTripperMock is the adapter implementation of http.RoundTripper interface for mocking.
type roundTripperMock struct {
	roundTripMock func(*http.Request) (*http.Response, error)
}

// RoundTrip is just an adapter.
func (roundTripper *roundTripperMock) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTripper.roundTripMock(request)
}

func Test_handler_NTokenProxy(t *testing.T) {
	type fields struct {
		proxy *httputil.ReverseProxy
		token ntokend.TokenProvider
		cfg   config.Proxy
	}
	type args struct {
		w http.ResponseWriter
		r *http.Request
	}
	type want struct {
		code   int
		header map[string]string
		body   []byte
	}
	type testcase struct {
		name      string
		fields    fields
		args      args
		want      want
		wantError error
	}
	tests := []testcase{
		testcase{
			name: "Check handler NTokenProxy, on token error",
			fields: fields{
				token: func() (string, error) {
					return "token-319", fmt.Errorf("get-token-error-331")
				},
			},
			args: args{
				w: httptest.NewRecorder(),
				r: httptest.NewRequest(http.MethodGet, "http://url-336", nil),
			},
			want: want{
				code:   http.StatusOK,
				header: map[string]string{},
				body:   []byte{},
			},
			wantError: fmt.Errorf("get-token-error-331"),
		},
		testcase{
			name: "Check handler NTokenProxy, request got auth-token and proxied (GET)",
			fields: fields{
				// mock proxy, mirror header, prepends prefix to response
				proxy: &httputil.ReverseProxy{
					Director: func(*http.Request) {},
					Transport: &roundTripperMock{
						roundTripMock: func(request *http.Request) (response *http.Response, err error) {
							var reqBody []byte
							if request.Body != nil {
								reqBody, err = ioutil.ReadAll(request.Body)
							}
							if err != nil {
								return nil, err
							}
							return &http.Response{
								StatusCode: http.StatusOK,
								Header:     request.Header,
								Body:       ioutil.NopCloser(strings.NewReader("proxied-359" + "-" + string(reqBody))),
							}, nil
						},
					},
				},
				token: func() (string, error) {
					return "token-365", nil
				},
				cfg: config.Proxy{
					AuthHeader: "auth-header-368",
				},
			},
			args: args{
				w: httptest.NewRecorder(),
				r: httptest.NewRequest(http.MethodGet, "http://url-373", nil),
			},
			want: want{
				code: http.StatusOK,
				header: map[string]string{
					"auth-header-368": "token-365",
				},
				body: []byte(`proxied-359-`),
			},
		},
		testcase{
			name: "Check handler NTokenProxy, request got auth-token and proxied (POST)",
			fields: fields{
				// mock proxy, mirror header, prepends prefix to response
				proxy: &httputil.ReverseProxy{
					Director: func(*http.Request) {},
					Transport: &roundTripperMock{
						roundTripMock: func(request *http.Request) (response *http.Response, err error) {
							reqBody, err := ioutil.ReadAll(request.Body)
							if err != nil {
								return nil, err
							}
							return &http.Response{
								StatusCode: http.StatusOK,
								Header:     request.Header,
								Body:       ioutil.NopCloser(strings.NewReader("proxied-399" + "-" + string(reqBody))),
							}, nil
						},
					},
				},
				token: func() (string, error) {
					return "token-405", nil
				},
				cfg: config.Proxy{
					AuthHeader: "auth-header-408",
				},
			},
			args: args{
				w: httptest.NewRecorder(),
				r: httptest.NewRequest(http.MethodPost, "http://url-413", strings.NewReader("body-413")),
			},
			want: want{
				code: http.StatusOK,
				header: map[string]string{
					"auth-header-408": "token-405",
				},
				body: []byte(`proxied-399-body-413`),
			},
		},
		testcase{
			name: "Check handler NTokenProxy, request body closed",
			fields: fields{
				// mock proxy, mirror header, prepends prefix to response
				proxy: &httputil.ReverseProxy{
					Director: func(*http.Request) {},
					Transport: &roundTripperMock{
						roundTripMock: func(request *http.Request) (response *http.Response, err error) {
							reqBody := ""
							return &http.Response{
								StatusCode: http.StatusOK,
								Header:     request.Header,
								Body:       ioutil.NopCloser(strings.NewReader("proxied-439" + "-" + string(reqBody))),
							}, nil
						},
					},
				},
				token: func() (string, error) {
					return "token-445", nil
				},
				cfg: config.Proxy{
					AuthHeader: "auth-header-448",
				},
			},
			args: args{
				w: httptest.NewRecorder(),
				r: httptest.NewRequest(http.MethodPost, "http://url-453", strings.NewReader("body-453")),
			},
			want: want{
				code: http.StatusOK,
				header: map[string]string{
					"auth-header-448": "token-445",
				},
				body: []byte(`proxied-439-`),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			var err error
			h := &handler{
				proxy: tt.fields.proxy,
				token: tt.fields.token,
				cfg:   tt.fields.cfg,
			}

			gotError := h.NTokenProxy(tt.args.w, tt.args.r)
			if !reflect.DeepEqual(gotError, tt.wantError) {
				err = &NotEqualError{"error", gotError, tt.wantError}
			}
			if err != nil {
				t.Errorf("handler.RoleToken() %v", err)
				return
			}

			err = EqualResponse(tt.args.w, tt.want.code, tt.want.header, tt.want.body)
			if err != nil {
				t.Errorf("handler.NTokenProxy() %v", err)
				return
			}

			// check if the response's body is closed
			if tt.args.r.Body != nil {
				byteRead, err := tt.args.r.Body.Read(make([]byte, 64))
				if byteRead != 0 || err != io.EOF {
					t.Errorf("handler.NTokenProxy() request not closed, %v bytes read, err %v", byteRead, err)
				}
			}
		})
	}
}

// readCloserMock is the adapter implementation of io.ReadCloser interface for mocking.
type readCloserMock struct {
	readMock  func(p []byte) (n int, err error)
	closeMock func() error
}

// Read is just an adapter.
func (r *readCloserMock) Read(p []byte) (n int, err error) {
	return r.readMock(p)
}

// Close is just an adapter.
func (r *readCloserMock) Close() error {
	return r.closeMock()
}

func Test_handler_RoleToken(t *testing.T) {
	type fields struct {
		role service.RoleProvider
	}
	type args struct {
		w http.ResponseWriter
		r *http.Request
	}
	type want struct {
		code   int
		header map[string]string
		body   []byte
	}
	type testcase struct {
		name      string
		fields    fields
		args      args
		want      want
		wantError error
	}
	tests := []testcase{
		testcase{
			name:   "Check handler RoleToken, on decode request body error",
			fields: fields{},
			args: args{
				w: httptest.NewRecorder(),
				r: httptest.NewRequest(http.MethodGet, "http://url-555", strings.NewReader("body-555")),
			},
			want: want{
				code:   http.StatusOK,
				header: map[string]string{},
				body:   []byte{},
			},
			wantError: fmt.Errorf("invalid character 'b' looking for beginning of value"),
		},
		testcase{
			name: "Check handler RoleToken, on role error",
			fields: fields{
				role: func(ctx context.Context, domain string, role string, proxyForPrincipal string, minExpiry time.Duration, maxExpiry time.Duration) (*service.RoleToken, error) {
					return &service.RoleToken{
						Token:      "role-token-569",
						ExpiryTime: 570,
					}, fmt.Errorf("get-role-token-error-571")
				},
			},
			args: args{
				w: httptest.NewRecorder(),
				r: httptest.NewRequest(http.MethodGet, "http://url-576", strings.NewReader(`{}`)),
			},
			want: want{
				code:   http.StatusOK,
				header: map[string]string{},
				body:   []byte{},
			},
			wantError: fmt.Errorf("get-role-token-error-571"),
		},
		testcase{
			name: "Check handler RoleToken, on context cancel",
			fields: fields{
				role: func(ctx context.Context, domain string, role string, proxyForPrincipal string, minExpiry time.Duration, maxExpiry time.Duration) (roleToken *service.RoleToken, err error) {

					roleToken = &service.RoleToken{
						Token:      "role-token-591",
						ExpiryTime: 592,
					}
					ticker := time.NewTicker(time.Millisecond)
					defer ticker.Stop()

					select {
					case <-ctx.Done():
						err = ctx.Err()
					case <-ticker.C:
						err = fmt.Errorf("get-role-token-timeout-error-601")
					}
					return
				},
			},
			args: args{
				w: httptest.NewRecorder(),
				r: func() *http.Request {
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()

					request := httptest.NewRequest(http.MethodGet, "http://url-612", strings.NewReader(`{}`))
					return request.WithContext(ctx)
				}(),
			},
			want: want{
				code:   http.StatusOK,
				header: map[string]string{},
				body:   []byte{},
			},
			wantError: context.Canceled,
		},
		testcase{
			name: "Check handler RoleToken, request got role token",
			fields: fields{
				role: func(ctx context.Context, domain string, role string, proxyForPrincipal string, minExpiry time.Duration, maxExpiry time.Duration) (roleToken *service.RoleToken, err error) {
					return &service.RoleToken{
						Token:      "role-token-629",
						ExpiryTime: 630,
					}, nil
				},
			},
			args: args{
				w: httptest.NewRecorder(),
				r: httptest.NewRequest(http.MethodGet, "http://url-636", strings.NewReader(`{
					"domain":"domain-637",
					"role":"role-638",
					"proxy_for_principal":"proxy_for_principal-639",
					"min_expiry": 640,
					"max_expiry": 641
				}`)),
			},
			want: want{
				code:   http.StatusOK,
				header: map[string]string{},
				body:   []byte(`{"token":"role-token-629","expiryTime":630}` + "\n"),
			},
		},
		func() testcase {
			requestClosed := false
			return testcase{
				name:   "Check handler RoleToken, request body closed",
				fields: fields{},
				args: args{
					w: httptest.NewRecorder(),
					r: httptest.NewRequest(http.MethodGet, "http://url-657", &readCloserMock{
						readMock: func(p []byte) (n int, err error) {
							if !requestClosed {
								n = copy(p, []byte("body-660"))
							} else {
								n = 0
							}
							return n, io.EOF
						},
						closeMock: func() error {
							requestClosed = true
							return nil
						},
					}),
				},
				want: want{
					code:   http.StatusOK,
					header: map[string]string{},
					body:   []byte{},
				},
				wantError: fmt.Errorf("invalid character 'b' looking for beginning of value"),
			}
		}(),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			var err error
			h := &handler{
				role: tt.fields.role,
			}

			gotError := h.RoleToken(tt.args.w, tt.args.r)
			if !reflect.DeepEqual(gotError, tt.wantError) {
				if gotError == nil || tt.wantError == nil || gotError.Error() != tt.wantError.Error() {
					err = &NotEqualError{"error", gotError, tt.wantError}
				}
			}
			if err != nil {
				t.Errorf("handler.RoleToken() %v", err)
				return
			}

			err = EqualResponse(tt.args.w, tt.want.code, tt.want.header, tt.want.body)
			if err != nil {
				t.Errorf("handler.RoleToken() %v", err)
				return
			}

			// check if the response's body is closed
			if tt.args.r.Body != nil {
				byteRead, err := tt.args.r.Body.Read(make([]byte, 64))
				if byteRead != 0 || err != io.EOF {
					t.Errorf("handler.RoleToken() request not closed, %v bytes read, err %v", byteRead, err)
					return
				}
			}
		})
	}
}

func Test_handler_RoleTokenProxy(t *testing.T) {
	type fields struct {
		proxy *httputil.ReverseProxy
		role  service.RoleProvider
		cfg   config.Proxy
	}
	type args struct {
		w http.ResponseWriter
		r *http.Request
	}
	type want struct {
		code   int
		header map[string]string
		body   []byte
	}
	type testcase struct {
		name      string
		fields    fields
		args      args
		want      want
		wantError error
	}
	tests := []testcase{
		testcase{
			name: "Check handler RoleTokenProxy, on role error",
			fields: fields{
				role: func(ctx context.Context, domain string, role string, proxyForPrincipal string, minExpiry time.Duration, maxExpiry time.Duration) (roleToken *service.RoleToken, err error) {
					return &service.RoleToken{
						Token:      "role-token-747",
						ExpiryTime: 748,
					}, fmt.Errorf("get-role-token-error-749")
				},
			},
			args: args{
				w: httptest.NewRecorder(),
				r: httptest.NewRequest(http.MethodGet, "http://url-754", nil),
			},
			want: want{
				code:   http.StatusOK,
				header: map[string]string{},
				body:   []byte{},
			},
			wantError: fmt.Errorf("get-role-token-error-749"),
		},
		testcase{
			name: "Check handler RoleTokenProxy, on context cancel",
			fields: fields{
				role: func(ctx context.Context, domain string, role string, proxyForPrincipal string, minExpiry time.Duration, maxExpiry time.Duration) (roleToken *service.RoleToken, err error) {

					roleToken = &service.RoleToken{
						Token:      "role-token-769",
						ExpiryTime: 770,
					}
					ticker := time.NewTicker(time.Millisecond)
					defer ticker.Stop()

					select {
					case <-ctx.Done():
						err = ctx.Err()
					case <-ticker.C:
						err = fmt.Errorf("get-role-token-timeout-error-779")
					}
					return
				},
			},
			args: args{
				w: httptest.NewRecorder(),
				r: func() *http.Request {
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()

					request := httptest.NewRequest(http.MethodGet, "http://url-790", strings.NewReader(`{}`))
					return request.WithContext(ctx)
				}(),
			},
			want: want{
				code:   http.StatusOK,
				header: map[string]string{},
				body:   []byte{},
			},
			wantError: context.Canceled,
		},
		testcase{
			name: "Check handler RoleTokenProxy, request got role-token and proxied (GET)",
			fields: fields{
				// mock proxy, mirror header, prepends prefix to response
				proxy: &httputil.ReverseProxy{
					Director: func(*http.Request) {},
					Transport: &roundTripperMock{
						roundTripMock: func(request *http.Request) (response *http.Response, err error) {
							var reqBody []byte
							if request.Body != nil {
								reqBody, err = ioutil.ReadAll(request.Body)
							}
							if err != nil {
								return nil, err
							}
							return &http.Response{
								StatusCode: http.StatusOK,
								Header:     request.Header,
								Body:       ioutil.NopCloser(strings.NewReader("proxied-819" + "-" + string(reqBody))),
							}, nil
						},
					},
				},
				role: func(ctx context.Context, domain string, role string, proxyForPrincipal string, minExpiry time.Duration, maxExpiry time.Duration) (roleToken *service.RoleToken, err error) {
					return &service.RoleToken{
						Token: strings.Join([]string{
							"role-token-827",
							domain,
							role,
							proxyForPrincipal,
						}, "-"),
						ExpiryTime: 832,
					}, nil
				},
				cfg: config.Proxy{
					RoleHeader: "role-header-836",
				},
			},
			args: args{
				w: httptest.NewRecorder(),
				r: func() *http.Request {
					request := httptest.NewRequest(http.MethodGet, "http://url-842", nil)
					request.Header.Set("Athenz-Role-Auth", "athenz-role-auth-843")
					request.Header.Set("Athenz-Domain-Auth", "athenz-domain-auth-844")
					request.Header.Set("Athenz-Proxy-Principal-Auth", "athenz-proxy-principal-auth-845")
					return request
				}(),
			},
			want: want{
				code: http.StatusOK,
				header: map[string]string{
					"role-header-836": strings.Join([]string{
						"role-token-827",
						"athenz-domain-auth-844",
						"athenz-role-auth-843",
						"athenz-proxy-principal-auth-845",
					}, "-"),
				},
				body: []byte(`proxied-819-`),
			},
		},
		testcase{
			name: "Check handler RoleTokenProxy, request got auth-token and proxied (POST)",
			fields: fields{
				// mock proxy, mirror header, prepends prefix to response
				proxy: &httputil.ReverseProxy{
					Director: func(*http.Request) {},
					Transport: &roundTripperMock{
						roundTripMock: func(request *http.Request) (response *http.Response, err error) {
							reqBody, err := ioutil.ReadAll(request.Body)
							if err != nil {
								return nil, err
							}
							return &http.Response{
								StatusCode: http.StatusOK,
								Header:     request.Header,
								Body:       ioutil.NopCloser(strings.NewReader("proxied-877" + "-" + string(reqBody))),
							}, nil
						},
					},
				},
				role: func(ctx context.Context, domain string, role string, proxyForPrincipal string, minExpiry time.Duration, maxExpiry time.Duration) (roleToken *service.RoleToken, err error) {
					return &service.RoleToken{
						Token: strings.Join([]string{
							"role-token-885",
							domain,
							role,
							proxyForPrincipal,
						}, "-"),
						ExpiryTime: 890,
					}, nil
				},
				cfg: config.Proxy{
					RoleHeader: "role-header-894",
				},
			},
			args: args{
				w: httptest.NewRecorder(),
				r: func() *http.Request {
					request := httptest.NewRequest(http.MethodGet, "http://url-900", strings.NewReader("body-900"))
					request.Header.Set("Athenz-Role-Auth", "athenz-role-auth-901")
					request.Header.Set("Athenz-Domain-Auth", "athenz-domain-auth-902")
					request.Header.Set("Athenz-Proxy-Principal-Auth", "athenz-proxy-principal-auth-903")
					return request
				}(),
			},
			want: want{
				code: http.StatusOK,
				header: map[string]string{
					"role-header-894": strings.Join([]string{
						"role-token-885",
						"athenz-domain-auth-902",
						"athenz-role-auth-901",
						"athenz-proxy-principal-auth-903",
					}, "-"),
				},
				body: []byte(`proxied-877-body-900`),
			},
		},
		testcase{
			name: "Check handler RoleTokenProxy, request body closed",
			fields: fields{
				// mock proxy, mirror header, prepends prefix to response
				proxy: &httputil.ReverseProxy{
					Director: func(*http.Request) {},
					Transport: &roundTripperMock{
						roundTripMock: func(request *http.Request) (response *http.Response, err error) {
							reqBody := ""
							return &http.Response{
								StatusCode: http.StatusOK,
								Header:     request.Header,
								Body:       ioutil.NopCloser(bytes.NewReader([]byte("proxied-932" + "-" + string(reqBody)))),
							}, nil
						},
					},
				},
				role: func(ctx context.Context, domain string, role string, proxyForPrincipal string, minExpiry time.Duration, maxExpiry time.Duration) (roleToken *service.RoleToken, err error) {
					return &service.RoleToken{
						Token:      "role-token-939",
						ExpiryTime: 940,
					}, nil
				},
				cfg: config.Proxy{
					RoleHeader: "role-header-944",
				},
			},
			args: args{
				w: httptest.NewRecorder(),
				r: httptest.NewRequest(http.MethodPost, "http://url-949", bytes.NewReader([]byte("body-949"))),
			},
			want: want{
				code: http.StatusOK,
				header: map[string]string{
					"role-header-944": "role-token-939",
				},
				body: []byte(`proxied-932-`),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			var err error
			h := &handler{
				proxy: tt.fields.proxy,
				role:  tt.fields.role,
				cfg:   tt.fields.cfg,
			}

			gotError := h.RoleTokenProxy(tt.args.w, tt.args.r)
			if !reflect.DeepEqual(gotError, tt.wantError) {
				err = &NotEqualError{"error", gotError, tt.wantError}
			}
			if err != nil {
				t.Errorf("handler.RoleTokenProxy() %v", err)
				return
			}

			err = EqualResponse(tt.args.w, tt.want.code, tt.want.header, tt.want.body)
			if err != nil {
				t.Errorf("handler.RoleTokenProxy() %v", err)
				return
			}

			// check if the response's body is closed
			if tt.args.r.Body != nil {
				byteRead, err := tt.args.r.Body.Read(make([]byte, 64))
				if byteRead != 0 || err != io.EOF {
					t.Errorf("handler.RoleTokenProxy() request not closed, %v bytes read, err %v", byteRead, err)
				}
			}
		})
	}
}

func Test_flushAndClose(t *testing.T) {
	type args struct {
		readCloser io.ReadCloser
	}
	type testcase struct {
		name      string
		args      args
		wantError error
	}
	tests := []testcase{
		{
			name: "Check flushAndClose, readCloser is nil",
			args: args{
				readCloser: nil,
			},
			wantError: nil,
		},
		{
			name: "Check flushAndClose, flush & close success",
			args: args{
				readCloser: &readCloserMock{
					readMock: func(p []byte) (n int, err error) {
						return 0, io.EOF
					},
					closeMock: func() error {
						return nil
					},
				},
			},
			wantError: nil,
		},
		{
			name: "Check flushAndClose, flush fail",
			args: args{
				readCloser: &readCloserMock{
					readMock: func(p []byte) (n int, err error) {
						return 0, fmt.Errorf("read-error-1332")
					},
					closeMock: func() error {
						return nil
					},
				},
			},
			wantError: fmt.Errorf("read-error-1332"),
		},
		{
			name: "Check flushAndClose, close fail",
			args: args{
				readCloser: &readCloserMock{
					readMock: func(p []byte) (n int, err error) {
						return 0, io.EOF
					},
					closeMock: func() error {
						return fmt.Errorf("close-error-1349")
					},
				},
			},
			wantError: fmt.Errorf("close-error-1349"),
		},
		{
			name: "Check flushAndClose, flush & close fail",
			args: args{
				readCloser: &readCloserMock{
					readMock: func(p []byte) (n int, err error) {
						return 0, fmt.Errorf("read-error-1360")
					},
					closeMock: func() error {
						return fmt.Errorf("close-error-1363")
					},
				},
			},
			wantError: fmt.Errorf("read-error-1360"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotError := flushAndClose(tt.args.readCloser)
			if !reflect.DeepEqual(gotError, tt.wantError) {
				t.Errorf("flushAndClose() error = %v, want %v", gotError, tt.wantError)
			}
		})
	}
}
