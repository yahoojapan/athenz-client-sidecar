package service

import (
	"testing"

	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"ghe.corp.yahoo.co.jp/athenz/athenz-tenant-sidecar/config"
	"github.com/kpango/gache"
	"github.com/kpango/glg"
)

// updaterMock is the adapter implementation of updater interface for mocking.
type updaterMock struct {
	updateMock func() error
}

// update is just an adapter.
func (updater *updaterMock) update() error {
	return updater.updateMock()
}

// dummyReadCloser is the adapter implementation of io.ReadCloser interface for mocking.
type dummyReadCloser struct {
	closed    bool
	closeMock func() error
	readMock  func(p []byte) (n int, err error)
}

// Close is just an adapter.
func (rc *dummyReadCloser) Close() error {
	return rc.closeMock()
}

// Read is just an adapter.
func (rc *dummyReadCloser) Read(p []byte) (n int, err error) {
	return rc.readMock(p)
}

func TestNewHC(t *testing.T) {
	type args struct {
		cfg  config.HC
		prov TokenProvider
	}
	type testcase struct {
		name       string
		args       args
		want       *hc
		checkFunc  func(got, want *hc) error
		beforeFunc func() error
		afterFunc  func() error
	}
	tests := []testcase{
		{
			name: "Check NewHC, use configuration correctly",
			args: args{
				cfg: config.HC{
					AuthHeader:       "auth-header-66",
					AthenzURL:        "athenz-url-67",
					Hostname:         "hostname-68",
					IP:               "ip-69",
					CertExpire:       "70s",
					CertExpireMargin: "71s",
				},
				prov: func() (string, error) {
					return "token-74", nil
				},
			},
			want: func() *hc {
				wantH := &hc{
					certs:    gache.New(),
					ip:       "ip-69",
					hostname: "hostname-68",
					token: func() (string, error) {
						return "token-74", nil
					},
					athenzURL:             "athenz-url-67",
					athenzPrincipleHeader: "auth-header-66",
					lastRefreshed:         time.Now(),
					certExpire:            70 * time.Second,
					certExpireMargin:      71 * time.Second,
					httpClient:            http.DefaultClient,
				}
				wantH.updater = wantH
				return wantH
			}(),
			checkFunc: func(got, want *hc) error {
				errFunc := func(field string) error {
					return fmt.Errorf("NewHC() %s = %v, want %v", field, got, want)
				}

				// only works for empty Map
				if reflect.TypeOf(got.certs) != reflect.TypeOf(want.certs) {
					return errFunc("certs")
				}
				if got.ip != want.ip {
					return errFunc("ip")
				}
				if got.hostname != want.hostname {
					return errFunc("hostname")
				}
				if func() bool {
					gotT, gotE := got.token()
					wantT, wantE := want.token()
					return gotT != wantT || gotE != wantE
				}() {
					return errFunc("token")
				}
				if got.athenzURL != want.athenzURL {
					return errFunc("athenzURL")
				}
				if got.athenzPrincipleHeader != want.athenzPrincipleHeader {
					return errFunc("athenzPrincipleHeader")
				}
				if target := got.lastRefreshed; !(target.After(want.lastRefreshed) && target.Before(time.Now())) {
					return errFunc("lastRefreshed")
				}
				if got.certExpire != want.certExpire {
					return errFunc("certExpire")
				}
				if got.certExpireMargin != want.certExpireMargin {
					return errFunc("certExpireMargin")
				}
				if got.httpClient != want.httpClient {
					return errFunc("httpClient")
				}
				if got.updater != got {
					return errFunc("updater")
				}

				return nil
			},
		},
		func() testcase {
			env := map[string]string{
				"ip-135":       "ip-v-135",
				"hostname-136": "hostname-v-136",
			}
			return testcase{
				name: "Check NewHC, use env. variable correctly",
				args: args{
					cfg: config.HC{
						IP:       "_ip-135_",
						Hostname: "_hostname-136_",
					},
				},
				want: &hc{
					ip:       "ip-v-135",
					hostname: "hostname-v-136",
				},
				beforeFunc: func() error {
					for k, v := range env {
						err := os.Setenv(k, v)
						if err != nil {
							return err
						}
					}
					return nil
				},
				afterFunc: func() error {
					for k, _ := range env {
						err := os.Unsetenv(k)
						if err != nil {
							return err
						}
					}
					return nil
				},
				checkFunc: func(got, want *hc) error {
					errFunc := func(field string) error {
						return fmt.Errorf("NewHC() %s = %v, want %v", field, got, want)
					}

					if got.ip != want.ip {
						return errFunc("ip")
					}
					if got.hostname != want.hostname {
						return errFunc("hostname")
					}

					return nil
				},
			}
		}(),
		{
			name: "Check NewHC, on error, on invalid duration string, use default value",
			args: args{
				cfg: config.HC{
					CertExpire:       "invalid-cert-expire-188",
					CertExpireMargin: "invalid-cert-expire-margin-189",
				},
			},
			want: &hc{
				certExpire:       30 * time.Minute,
				certExpireMargin: time.Minute,
			},
			checkFunc: func(got, want *hc) error {
				errFunc := func(field string) error {
					return fmt.Errorf("NewHC() %s = %v, want %v", field, got, want)
				}

				if got.certExpire != want.certExpire {
					return errFunc("certExpire")
				}
				if got.certExpireMargin != want.certExpireMargin {
					return errFunc("certExpireMargin")
				}

				return nil
			},
		},
		{
			name: "Check NewHC, on error, on invalid duration range, use default value",
			args: args{
				cfg: config.HC{
					CertExpire: fmt.Sprintf("%dh", 365*24+224),
				},
			},
			want: &hc{
				certExpire: 365 * 24 * time.Hour,
			},
			checkFunc: func(got, want *hc) error {
				errFunc := func(field string) error {
					return fmt.Errorf("NewHC() %s = %v, want %v", field, got, want)
				}

				if got.certExpire != want.certExpire {
					return errFunc("certExpire")
				}

				return nil
			},
		},
	}

	glg.Get().SetMode(glg.NONE) // disable logger
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// before
			if tt.beforeFunc != nil {
				if err := tt.beforeFunc(); err != nil {
					t.Error(err)
					return
				}
			}

			// check
			got, _ := NewHC(tt.args.cfg, tt.args.prov)
			if err := tt.checkFunc(got.(*hc), tt.want); err != nil {
				t.Error(err)
				return
			}

			// after
			if tt.afterFunc != nil {
				if err := tt.afterFunc(); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
}

func Test_hc_GetCertProvider(t *testing.T) {
	type fields struct {
		certs gache.Gache
	}
	type providerArgs struct {
		appID string
	}
	type testcase struct {
		name         string
		fields       fields
		providerArgs providerArgs
		want         string
		wantError    error
	}
	tests := []testcase{
		{
			name: "Check hc GetCertProvider, default provider function returns error",
			fields: fields{
				certs: func() gache.Gache {
					m := gache.New()
					m.Set("app-id-63", "cert-63")
					return m
				}(),
			},
			providerArgs: providerArgs{
				appID: "not-found-app-id-68",
			},
			want:      "",
			wantError: ErrCertNotFound,
		},
		{
			name: "Check hc GetCertProvider, default provider function returns correct result",
			fields: fields{
				certs: func() gache.Gache {
					m := gache.New()
					m.Set("app-id-78", "cert-78")
					return m
				}(),
			},
			providerArgs: providerArgs{
				appID: "app-id-78",
			},
			want:      "cert-78",
			wantError: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &hc{
				certs: tt.fields.certs,
			}
			provider := h.GetCertProvider()
			got, gotError := provider(tt.providerArgs.appID)

			if !reflect.DeepEqual(gotError, tt.wantError) {
				t.Errorf("hc.GetCertProvider() got error = %v, want %v", gotError, tt.wantError)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("hc.GetCertProvider() got = %v, want %v", got, tt.want)
				return
			}
		})
	}
}

func Test_hc_getCertificate(t *testing.T) {
	type fields struct {
		certs gache.Gache
	}
	type args struct {
		appID string
	}
	type testcase struct {
		name      string
		fields    fields
		args      args
		want      string
		wantError error
	}
	tests := []testcase{
		{
			name: "Check hc getCertificate, empty list, not found",
			fields: fields{
				certs: gache.New(),
			},
			args: args{
				appID: "any-app-id-68",
			},
			want:      "",
			wantError: ErrCertNotFound,
		},
		{
			name: "Check hc getCertificate, cert not found",
			fields: fields{
				certs: func() gache.Gache {
					m := gache.New()
					m.Set("app-id-155", "cert-155")
					m.Set("app-id-156", "cert-156")
					return m
				}(),
			},
			args: args{
				appID: "not-found-app-id-161",
			},
			want:      "",
			wantError: ErrCertNotFound,
		},
		{
			name: "Check hc getCertificate, cert found",
			fields: fields{
				certs: func() gache.Gache {
					m := gache.New()
					m.Set("app-id-171", "cert-171")
					m.Set("app-id-172", "cert-172")
					return m
				}(),
			},
			args: args{
				appID: "app-id-172",
			},
			want:      "cert-172",
			wantError: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &hc{
				certs: tt.fields.certs,
			}
			got, gotError := h.getCertificate(tt.args.appID)

			if !reflect.DeepEqual(gotError, tt.wantError) {
				t.Errorf("hc.getCertificate() got error = %v, want %v", gotError, tt.wantError)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("hc.getCertificate() got = %v, want %v", got, tt.want)
				return
			}
		})
	}
}

func Test_hc_update(t *testing.T) {
	type fields struct {
		certs                 gache.Gache
		ip                    string
		hostname              string
		token                 TokenProvider
		athenzURL             string
		athenzPrincipleHeader string
		nextExpire            time.Duration
		lastRefreshed         time.Time
		certExpire            time.Duration
		certExpireMargin      time.Duration
		httpClient            *http.Client
		updater               updater
	}
	type testcase struct {
		name       string
		fields     fields
		want       fields
		wantError  error
		checkFunc  func(got, want *hc, start, end time.Time) error
		beforeFunc func(testcase *testcase) error
		afterFunc  func() error
	}

	// isBetweenTimes returns true when target is inside (start, end)
	isBetweenTimes := func(target, start, end time.Time) bool {
		return target.After(start) && target.Before(end)
	}
	// createBeforeFunc helps create the beforeFunc for start mock server and test parameters binding
	createBeforeFunc := func(serverMock **httptest.Server, handler http.HandlerFunc) func(testcase *testcase) error {
		return func(testcase *testcase) error {
			s := httptest.NewTLSServer(handler)

			*serverMock = s
			testcase.fields.athenzURL = strings.TrimPrefix(s.URL, "https://")
			testcase.fields.httpClient = s.Client()

			return nil
		}
	}
	// createAfterFunc helps create the afterFunc to stop the server
	createAfterFunc := func(serverMock **httptest.Server) func() error {
		return func() error {
			(*serverMock).Close()
			return nil
		}
	}
	// dummyTokenProvider is a token provider returns an empty token
	dummyTokenProvider := func() (string, error) {
		return "", nil
	}

	tests := []testcase{
		{
			name: "Check hc update, token generation error",
			fields: fields{
				token: func() (string, error) {
					return "token-448", fmt.Errorf("token-generation-error-448")
				},
			},
			wantError: fmt.Errorf("token-generation-error-448"),
		},
		{
			name: "Check hc update, error on getting certificates by HTTP",
			fields: fields{
				athenzURL: "invalid-athenz-url-%^&-455",
				token: func() (string, error) {
					return "token-457", nil
				},
			},
			wantError: &url.Error{"parse", "https://invalid-athenz-url-%^&-455/containercerts/mh/?d=3600&ip=", url.EscapeError("%^&")},
		},
		func() testcase {
			var serverMock *httptest.Server
			return testcase{
				name: "Check hc update, empty certificate list, update internal status correctly",
				fields: fields{
					athenzPrincipleHeader: "Yahoo-Principal-Auth",
					certExpire:            474 * time.Second,
					token:                 dummyTokenProvider,
				},
				want: fields{
					nextExpire: 474 * time.Second,
				},
				checkFunc: func(got, want *hc, start, end time.Time) error {
					if got.nextExpire != want.nextExpire {
						return fmt.Errorf("hc.update() got nextExpire = %v, want %v", got.nextExpire, want.nextExpire)

					}
					if !isBetweenTimes(got.lastRefreshed, start, end) {
						return fmt.Errorf("hc.update() got lastRefreshed = %v, want between %v and %v", got.lastRefreshed, start, end)
					}
					return nil
				},
				beforeFunc: createBeforeFunc(&serverMock, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					fmt.Fprintln(w, `<certificates xmlns="urn:yahoo:auth:yca" hostname="" exhaustive="true"></certificates>`)
				})),
				afterFunc: createAfterFunc(&serverMock),
			}
		}(),
		func() testcase {
			wantedNextExpire := 500 * time.Second
			initTime := time.Now()
			earliestExpiry := initTime.Add(wantedNextExpire).Truncate(time.Second)
			truncatedTime := initTime.Add(wantedNextExpire).Sub(earliestExpiry)

			var serverMock *httptest.Server
			return testcase{
				name: "Check hc update, certificate list with expiry, set nextExpire correctly",
				fields: fields{
					athenzPrincipleHeader: "Yahoo-Principal-Auth",
					token: dummyTokenProvider,
				},
				want: fields{
					nextExpire: 500 * time.Second,
				},
				checkFunc: func(got, want *hc, start, end time.Time) error {
					longestWaitingTime := end.Sub(initTime)
					shortestExpiryDuration := want.nextExpire - longestWaitingTime - truncatedTime

					if !(shortestExpiryDuration <= got.nextExpire && got.nextExpire <= want.nextExpire) {
						return fmt.Errorf("hc.update() got nextExpire = %v, want %v-%v", got.nextExpire, shortestExpiryDuration, want.nextExpire)
					}
					return nil
				},
				beforeFunc: createBeforeFunc(&serverMock, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					fmt.Fprintln(w, fmt.Sprintf(
						`<certificates xmlns="urn:yahoo:auth:yca" hostname="" exhaustive="true">
							<certificate xmlns="urn:yahoo:auth:yca">%s</certificate>
							<certificate xmlns="urn:yahoo:auth:yca">%s</certificate>
							<certificate xmlns="urn:yahoo:auth:yca">%s</certificate>
							<certificate xmlns="urn:yahoo:auth:yca">%s</certificate>
						</certificates>`,
						"c=1;t="+strconv.FormatInt(initTime.Add(519*time.Minute).Unix(), 10)+";end=0;",
						"c=2;t="+strconv.FormatInt(earliestExpiry.Unix(), 10)+";end=0;",
						"c=3;t="+strconv.FormatInt(initTime.Add(525*time.Minute).Unix(), 10)+";end=0;",
						"c=4;t="+"invalid-timestamp-should-skip"+";end=0;",
					))
				})),
				afterFunc: createAfterFunc(&serverMock),
			}
		}(),
		func() testcase {
			certExpiryTimeString := strconv.FormatInt(time.Now().Add(553*time.Second).Unix(), 10)

			var serverMock *httptest.Server
			return testcase{
				name: "Check hc update, certificate list stored correctly",
				fields: fields{
					athenzPrincipleHeader: "Yahoo-Principal-Auth",
					token: dummyTokenProvider,
				},
				want: fields{
					certs: func() gache.Gache {
						wantedCerts := gache.New()

						wantedCerts.Set("app-id-565", "cert=566")
						wantedCerts.Set("app-id-577", "cert=578;t="+certExpiryTimeString)

						return wantedCerts
					}(),
				},
				checkFunc: func(got, want *hc, start, end time.Time) (err error) {
					// prevent type assertion panic
					defer func() {
						panicError, ok := recover().(error)
						if panicError != nil {
							if ok {
								err = panicError
							} else {
								err = fmt.Errorf("%v", panicError)
							}
						}
					}()

					getCertificate := got.GetCertProvider()
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()

					// check exits
					want.certs.Foreach(ctx, func(key string, value interface{}, expire int64) bool {
						wantCert := value.(string)

						gotCert, innerErr := getCertificate(key)
						if innerErr != nil {
							err = innerErr
							return false
						}
						if gotCert != wantCert {
							err = fmt.Errorf("hc.update() got cert = %v, want %v", gotCert, wantCert)
							return false
						}

						return true
					})
					if err != nil {
						return err
					}

					// check non-exists
					want.certs.Foreach(ctx, func(key string, value interface{}, expire int64) bool {
						got.certs.Delete(key)
						return true
					})
					count := 0
					got.certs.Foreach(ctx, func(key string, value interface{}, expire int64) bool {
						count++
						return true
					})
					if count != 0 {
						return fmt.Errorf("hc.update() got unexpected cert (count) = %v", count)
					}

					return nil
				},
				beforeFunc: createBeforeFunc(&serverMock, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					fmt.Fprintln(w, fmt.Sprintf(
						`<certificates xmlns="urn:yahoo:auth:yca" hostname="" exhaustive="true">
							<certificate xmlns="urn:yahoo:auth:yca" appid="%s">%s</certificate>
							<certificate xmlns="urn:yahoo:auth:yca" appid="%s">%s</certificate>
							<certificate xmlns="urn:yahoo:auth:yca" appid="%s">%s</certificate>
							<certificate xmlns="urn:yahoo:auth:yca" appid="%s">%s</certificate>
						</certificates>`,
						"app-id-565", "cert=566",
						"empty expiry time skipped", "cert=570;t=",
						"invalid expiry time skipped", "cert=574;t=invalid",
						"app-id-577", "cert=578;t="+certExpiryTimeString,
					))
				})),
				afterFunc: createAfterFunc(&serverMock),
			}
		}(),
		func() testcase {
			var serverMock *httptest.Server
			return testcase{
				name: "Check hc update, create correct request for getting athenz",
				fields: fields{
					athenzPrincipleHeader: "athenz-principle-header-610",
					token: func() (string, error) {
						return "token-612", nil
					},
					hostname: "hostname-614",
					ip:       "6.15.6.15",
				},
				want: fields{
					certs: func() gache.Gache {
						wantedCerts := gache.New()

						wantedCerts.Set("app-id-651", "cert-651")
						wantedCerts.Set("app-id-652", "cert-652;")

						return wantedCerts
					}(),
				},
				checkFunc: func(got, want *hc, start, end time.Time) (err error) {
					// prevent type assertion panic
					defer func() {
						panicError, ok := recover().(error)
						if panicError != nil {
							if ok {
								err = panicError
							} else {
								err = fmt.Errorf("%v", panicError)
							}
						}
					}()

					getCertificate := got.GetCertProvider()
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()

					// check exits
					want.certs.Foreach(ctx, func(key string, value interface{}, expire int64) bool {
						wantCert := value.(string)

						gotCert, innerErr := getCertificate(key)
						if innerErr != nil {
							err = innerErr
							return false
						}
						if gotCert != wantCert {
							err = fmt.Errorf("hc.update() got cert = %v, want %v", gotCert, wantCert)
							return false
						}

						return true
					})
					if err != nil {
						return err
					}

					// check non-exists
					want.certs.Foreach(ctx, func(key string, value interface{}, expire int64) bool {
						got.certs.Delete(key)
						return true
					})
					count := 0
					got.certs.Foreach(ctx, func(key string, value interface{}, expire int64) bool {
						count++
						return true
					})
					if count != 0 {
						return fmt.Errorf("hc.update() got unexpected cert (count) = %v", count)
					}

					return nil
				},
				beforeFunc: createBeforeFunc(&serverMock, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

					writeErrResponse := func(err error) {
						w.WriteHeader(http.StatusInternalServerError)
						fmt.Fprintln(w, err.Error())
					}

					// check url
					gotURL := r.URL
					wantURL, err := url.Parse("/containercerts/mh/hostname-614?d=3600&ip=6.15.6.15")
					if err != nil {
						writeErrResponse(err)
						return
					}
					if !reflect.DeepEqual(gotURL, wantURL) {
						writeErrResponse(fmt.Errorf("getCertificatesByHttp() request got URL = %v, want %v", gotURL, wantURL))
						return
					}

					// check header
					gotToken := r.Header.Get("athenz-principle-header-610")
					wantToken := "token-612"
					if gotToken != wantToken {
						writeErrResponse(fmt.Errorf("getCertificatesByHttp() request got token = %v, want %v", gotToken, wantToken))
						return
					}

					// return valid certs
					w.WriteHeader(http.StatusOK)
					fmt.Fprintln(
						w,
						`<?xml version="1.0" encoding="utf-8"?>
						<certificates xmlns="urn:yahoo:auth:yca" hostname="hostname-614" exhaustive="true">
						  <certificate xmlns="urn:yahoo:auth:yca" appid="app-id-651">cert-651</certificate>
						  <certificate xmlns="urn:yahoo:auth:yca" appid="app-id-652">cert-652;</certificate>
						</certificates>

						<!-- ca1.yca.kks.yahoo.co.jp Wed Sep 19 13:12:06 JST 2018 -->`,
					)
				})),
				afterFunc: createAfterFunc(&serverMock),
			}
		}(),
	}

	glg.Get().SetMode(glg.NONE) // disable logger
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// before
			if tt.beforeFunc != nil {
				if err := tt.beforeFunc(&tt); err != nil {
					t.Error(err)
					return
				}
			}

			// run
			h := &hc{
				certs:                 tt.fields.certs,
				ip:                    tt.fields.ip,
				hostname:              tt.fields.hostname,
				token:                 tt.fields.token,
				athenzURL:             tt.fields.athenzURL,
				athenzPrincipleHeader: tt.fields.athenzPrincipleHeader,
				nextExpire:            tt.fields.nextExpire,
				lastRefreshed:         tt.fields.lastRefreshed,
				certExpire:            tt.fields.certExpire,
				certExpireMargin:      tt.fields.certExpireMargin,
				httpClient:            tt.fields.httpClient,
			}
			if h.certs == nil {
				h.certs = gache.New()
			}
			start := time.Now()
			gotError := h.update()
			end := time.Now()

			// check
			if !reflect.DeepEqual(gotError, tt.wantError) {
				t.Errorf("hc.update() got error = %v, want %v", gotError, tt.wantError)
				return
			}
			if tt.checkFunc != nil {
				err := tt.checkFunc(h, (*hc)(&tt.want), start, end)
				if err != nil {
					t.Error(err)
					return
				}
			}

			// after
			if tt.afterFunc != nil {
				if err := tt.afterFunc(); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
}

// roundTripperMock is the adapter implementation of http.RoundTripper interface for mocking.
type roundTripperMock struct {
	RoundTripMock func(*http.Request) (*http.Response, error)
}

// RoundTrip is just an adapter.
func (rtMock *roundTripperMock) RoundTrip(r *http.Request) (*http.Response, error) {
	return rtMock.RoundTripMock(r)
}

func Test_getCertificatesByHttp(t *testing.T) {
	type args struct {
		client      *http.Client
		targetUrl   string
		tokenHeader string
		token       string
	}
	type testcase struct {
		name       string
		args       args
		want       *certificates
		wantError  error
		beforeFunc func(testcase *testcase) error
		afterFunc  func() error
	}

	// createBeforeFunc helps create the beforeFunc for start mock server and test parameters binding
	createBeforeFunc := func(serverMock **httptest.Server, handler http.HandlerFunc) func(testcase *testcase) error {
		return func(testcase *testcase) error {
			s := httptest.NewTLSServer(handler)

			*serverMock = s
			testcase.args.client = s.Client()
			testcase.args.targetUrl = s.URL

			return nil
		}
	}
	// createAfterFunc helps create the afterFunc to stop the server
	createAfterFunc := func(serverMock **httptest.Server) func() error {
		return func() error {
			(*serverMock).Close()
			return nil
		}
	}

	tests := []testcase{
		func() testcase {
			return testcase{
				name: "Check getCertificatesByHttp, error on creating request ",
				args: args{
					targetUrl: "https://invalid-target-url-%^&-731/",
				},
				want:      nil,
				wantError: &url.Error{"parse", "https://invalid-target-url-%^&-731/", url.EscapeError("%^&")},
			}
		}(),
		func() testcase {
			serverMock := httptest.NewTLSServer(nil)

			// disable default server logger
			serverMock.Config.ErrorLog = log.New(ioutil.Discard, "", 0)

			return testcase{
				name: "Check getCertificatesByHttp, error on sending request",
				args: args{
					client:      http.DefaultClient,
					targetUrl:   serverMock.URL,
					tokenHeader: "token-header-742",
					token:       "token-743",
				},
				want: nil,
				wantError: &url.Error{
					"Get",
					serverMock.URL,
					fmt.Errorf("x509: certificate signed by unknown authority"),
				},
			}
		}(),
		func() testcase {
			var serverMock *httptest.Server
			return testcase{
				name: "Check getCertificatesByHttp, error on response status",
				args: args{
					client:      nil,
					targetUrl:   "",
					tokenHeader: "token-header-776",
					token:       "token-777",
				},
				want:      nil,
				wantError: nil,
				beforeFunc: func(testcase *testcase) error {
					serverMock = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						w.WriteHeader(http.StatusInternalServerError)
						fmt.Fprintln(w, "")
					}))

					testcase.args.client = serverMock.Client()
					testcase.args.targetUrl = serverMock.URL

					testcase.wantError = fmt.Errorf("GET %s returned status code 500", serverMock.URL)

					return nil
				},
				afterFunc: createAfterFunc(&serverMock),
			}
		}(),
		func() testcase {
			var serverMock *httptest.Server
			return testcase{
				name: "Check getCertificatesByHttp, error on parsing XML",
				args: args{
					client:      nil,
					targetUrl:   "",
					tokenHeader: "token-header-806",
					token:       "token-807",
				},
				want:      nil,
				wantError: io.EOF,
				beforeFunc: createBeforeFunc(&serverMock, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					fmt.Fprintln(w, "invalid-xml-815")
				})),
				afterFunc: createAfterFunc(&serverMock),
			}
		}(),
		func() testcase {
			var serverMock *httptest.Server
			return testcase{
				name: "Check getCertificatesByHttp, create request and parse response correctly",
				args: args{
					client:      nil,
					targetUrl:   "",
					tokenHeader: "token-header-838",
					token:       "token-839",
				},
				want: &certificates{
					Hostname: "tester02.paranoids.ssk.ynwm.yahoo.co.jp",
					Certificates: []certificate{
						certificate{
							AppID: "yahoo.ykeykey_ckms_alpha_jp.paranoids.tester.test",
							Cert:  "v=1;a=yahoo.ykeykey_ckms_alpha_jp.paranoids.tester.test;h=172.16.164.215;t=1539922326;d=yby;n=tester;s=[signature]",
						},
						certificate{
							AppID: "yahoo.paranoids_jp.yca_test.tester",
							Cert:  "v=1;a=yahoo.paranoids_jp.yca_test.tester;h=172.16.164.215;t=1539922326;d=yby;n=tester;s=[signature]",
						},
						certificate{
							AppID: "yahoo.ykeykey_ckms_alpha_jp.paranoids.tester.test2",
							Cert:  "v=1;a=yahoo.ykeykey_ckms_alpha_jp.paranoids.tester.test2;h=172.16.164.215;t=1539922326;d=yby;n=tester;s=[signature]",
						},
					},
				},
				wantError: nil,
				beforeFunc: createBeforeFunc(&serverMock, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

					// check header
					gotToken := r.Header.Get("token-header-838")
					wantToken := "token-839"
					if gotToken != wantToken {
						w.WriteHeader(http.StatusInternalServerError)
						fmt.Fprintln(w, fmt.Errorf("getCertificatesByHttp() request got token = %v, want %v", gotToken, wantToken))
						return
					}

					// return valid certs
					w.WriteHeader(http.StatusOK)
					fmt.Fprintln(w, `
						<?xml version="1.0" encoding="utf-8"?>
						<certificates xmlns="urn:yahoo:auth:yca" hostname="tester02.paranoids.ssk.ynwm.yahoo.co.jp" exhaustive="true">
							<certificate
								xmlns="urn:yahoo:auth:yca"
								appid="yahoo.ykeykey_ckms_alpha_jp.paranoids.tester.test"
							>v=1;a=yahoo.ykeykey_ckms_alpha_jp.paranoids.tester.test;h=172.16.164.215;t=1539922326;d=yby;n=tester;s=[signature]</certificate>
							<certificate
								xmlns="urn:yahoo:auth:yca"
								appid="yahoo.paranoids_jp.yca_test.tester"
							>v=1;a=yahoo.paranoids_jp.yca_test.tester;h=172.16.164.215;t=1539922326;d=yby;n=tester;s=[signature]</certificate>
							<certificate
								xmlns="urn:yahoo:auth:yca"
								appid="yahoo.ykeykey_ckms_alpha_jp.paranoids.tester.test2"
							>v=1;a=yahoo.ykeykey_ckms_alpha_jp.paranoids.tester.test2;h=172.16.164.215;t=1539922326;d=yby;n=tester;s=[signature]</certificate>
						</certificates>

						<!-- ca1.yca.kks.yahoo.co.jp Wed Sep 19 13:12:06 JST 2018 -->
					`)
				})),
				afterFunc: createAfterFunc(&serverMock),
			}
		}(),
		{
			name: "Check getCertificatesByHttp, error on closing response, ignore error",
			args: args{
				client: func() *http.Client {
					return &http.Client{
						Transport: &roundTripperMock{
							RoundTripMock: func(*http.Request) (*http.Response, error) {
								responseBuffer := bytes.NewBufferString(`
									<?xml version="1.0" encoding="utf-8"?>
									<certificates xmlns="urn:yahoo:auth:yca" hostname="tester02.paranoids.ssk.ynwm.yahoo.co.jp" exhaustive="true">
										<certificate
											xmlns="urn:yahoo:auth:yca"
											appid="yahoo.ykeykey_ckms_alpha_jp.paranoids.tester.test"
										>v=1;a=yahoo.ykeykey_ckms_alpha_jp.paranoids.tester.test;h=172.16.164.215;t=1539922326;d=yby;n=tester;s=[signature]</certificate>
										<certificate
											xmlns="urn:yahoo:auth:yca"
											appid="yahoo.paranoids_jp.yca_test.tester"
										>v=1;a=yahoo.paranoids_jp.yca_test.tester;h=172.16.164.215;t=1539922326;d=yby;n=tester;s=[signature]</certificate>
										<certificate
											xmlns="urn:yahoo:auth:yca"
											appid="yahoo.ykeykey_ckms_alpha_jp.paranoids.tester.test2"
										>v=1;a=yahoo.ykeykey_ckms_alpha_jp.paranoids.tester.test2;h=172.16.164.215;t=1539922326;d=yby;n=tester;s=[signature]</certificate>
									</certificates>

									<!-- ca1.yca.kks.yahoo.co.jp Wed Sep 19 13:12:06 JST 2018 -->
								`)

								return &http.Response{
									StatusCode: http.StatusOK,
									Body: &dummyReadCloser{
										closeMock: func() error {
											return fmt.Errorf("close-error-907")
										},
										readMock: func(p []byte) (n int, err error) {
											return responseBuffer.Read(p)
										},
									},
								}, nil
							},
						},
					}
				}(),
				targetUrl:   "",
				tokenHeader: "token-header-918",
				token:       "token-919",
			},
			want: &certificates{
				Hostname: "tester02.paranoids.ssk.ynwm.yahoo.co.jp",
				Certificates: []certificate{
					certificate{
						AppID: "yahoo.ykeykey_ckms_alpha_jp.paranoids.tester.test",
						Cert:  "v=1;a=yahoo.ykeykey_ckms_alpha_jp.paranoids.tester.test;h=172.16.164.215;t=1539922326;d=yby;n=tester;s=[signature]",
					},
					certificate{
						AppID: "yahoo.paranoids_jp.yca_test.tester",
						Cert:  "v=1;a=yahoo.paranoids_jp.yca_test.tester;h=172.16.164.215;t=1539922326;d=yby;n=tester;s=[signature]",
					},
					certificate{
						AppID: "yahoo.ykeykey_ckms_alpha_jp.paranoids.tester.test2",
						Cert:  "v=1;a=yahoo.ykeykey_ckms_alpha_jp.paranoids.tester.test2;h=172.16.164.215;t=1539922326;d=yby;n=tester;s=[signature]",
					},
				},
			},
			wantError: nil,
		},
	}

	glg.Get().SetMode(glg.NONE) // disable logger
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// before
			if tt.beforeFunc != nil {
				if err := tt.beforeFunc(&tt); err != nil {
					t.Error(err)
					return
				}
			}

			// run
			got, gotError := getCertificatesByHttp(tt.args.client, tt.args.targetUrl, tt.args.tokenHeader, tt.args.token)
			if !reflect.DeepEqual(gotError, tt.wantError) {
				if gotError == nil || tt.wantError == nil || gotError.Error() != tt.wantError.Error() {
					t.Errorf("getCertificatesByHttp() got error = %v, want %v", gotError, tt.wantError)
					return
				}
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getCertificatesByHttp() got = %v, want %v", got, tt.want)
				return
			}

			// after
			if tt.afterFunc != nil {
				if err := tt.afterFunc(); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
}

func Test_flushAndClose(t *testing.T) {
	type args struct {
		rc io.ReadCloser
	}
	type testcase struct {
		name      string
		args      args
		wantError error
		checkFunc func(rc io.ReadCloser) error
	}
	tests := []testcase{
		{
			name: "Check flushAndClose, error on flush",
			args: args{
				rc: &dummyReadCloser{
					closeMock: nil,
					readMock: func(p []byte) (n int, err error) {
						return 0, fmt.Errorf("read error")
					},
				},
			},
			wantError: fmt.Errorf("read error"),
		},
		{
			name: "Check flushAndClose, error on close",
			args: args{
				rc: &dummyReadCloser{
					closeMock: func() error {
						return fmt.Errorf("close error")
					},
					readMock: func(p []byte) (n int, err error) {
						return 0, io.EOF
					},
				},
			},
			wantError: fmt.Errorf("close error"),
		},
		{
			name: "Check flushAndClose, flush and close success",
			args: args{
				rc: func() io.ReadCloser {
					var drc *dummyReadCloser
					drc = &dummyReadCloser{
						closeMock: func() error {
							drc.closed = true
							return nil
						},
						readMock: func(p []byte) (n int, err error) {
							return 0, io.EOF
						},
					}
					return drc
				}(),
			},
			wantError: nil,
			checkFunc: func(rc io.ReadCloser) error {
				gotClosed := rc.(*dummyReadCloser).closed
				wantClosed := true
				if gotClosed != wantClosed {
					t.Errorf("flushAndClose() closed = %v, want %v", gotClosed, wantClosed)
				}
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			gotError := flushAndClose(tt.args.rc)

			if !reflect.DeepEqual(gotError, tt.wantError) {
				t.Errorf("flushAndClose() got error = %v, want %v", gotError, tt.wantError)
				return
			}
			if tt.checkFunc != nil {
				err := tt.checkFunc(tt.args.rc)
				if err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
}

func Test_checkExpire(t *testing.T) {
	type args struct {
		cert string
	}
	type testcase struct {
		name      string
		args      args
		want      time.Time
		wantError error
	}
	tests := []testcase{
		{
			name: "Check checkExpire, no splitting",
			args: args{
				cert: "t=1530001139",
			},
			want: time.Unix(1530001139, 0),
		},
		{
			name: "Check checkExpire, with empty string part",
			args: args{
				cert: ";t=1530001146;;",
			},
			want: time.Unix(1530001146, 0),
		},
		{
			name: "Check checkExpire, no expiry time",
			args: args{
				cert: ";;",
			},
			// want: [zero value],
		},
		{
			name: "Check checkExpire, error on parse",
			args: args{
				cert: "v=1;t=invalid-timestamp-1161",
			},
			// want: [zero value],
			wantError: &strconv.NumError{"ParseInt", "invalid-timestamp-1161", strconv.ErrSyntax},
		},
		{
			name: "Check checkExpire, normal case",
			args: args{
				cert: "v=1;a=yahoo.ykeykey_ckms_alpha_jp.paranoids.tester.test2;h=172.16.164.215;t=1530001168;d=yby;n=tester;s=[signature]",
			},
			want: time.Unix(1530001168, 0),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotError := checkExpire(tt.args.cert)

			if !reflect.DeepEqual(gotError, tt.wantError) {
				t.Errorf("checkExpire() got error = %v, want %v", gotError, tt.wantError)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("checkExpire() got = %v, want %v", got, tt.want)
				return
			}
		})
	}
}

func Test_hc_StartCertUpdater(t *testing.T) {
	type fields struct {
		nextExpire       time.Duration
		certExpireMargin time.Duration
		updater          updater
	}
	type args struct {
		ctx context.Context
	}
	type testcase struct {
		name       string
		fields     fields
		args       args
		checkFunc  func(h *hc) error
		beforeFunc func() error
		afterFunc  func() error
	}
	tests := []testcase{
		func() testcase {
			ctx, cancel := context.WithCancel(context.Background())
			isUpdateRun := int32(0)

			return testcase{
				name: "Check hc StartCertUpdater, can use context to stop updater",
				fields: fields{
					updater: &updaterMock{
						updateMock: func() error {
							atomic.SwapInt32(&isUpdateRun, 1304)
							return fmt.Errorf("update-error-1271")
						},
					},
				},
				args: args{
					ctx: ctx,
				},
				checkFunc: func(h *hc) error {
					time.Sleep(100 * time.Millisecond)

					// do checking after context done
					<-ctx.Done()

					if atomic.LoadInt32(&isUpdateRun) != 1304 {
						return fmt.Errorf("StartCertUpdater() update should run")
					}
					return nil
				},
				beforeFunc: func() error {
					cancel()
					return nil
				},
			}
		}(),
		func() testcase {
			ctx, cancel := context.WithCancel(context.Background())
			updateTimeChan := make(chan time.Time, 3)
			updateCounter := 0

			return testcase{
				name: "Check hc StartCertUpdater, on error, retry after 1s",
				fields: fields{
					updater: &updaterMock{
						updateMock: func() error {
							if updateCounter < 3 {
								updateTimeChan <- time.Now()
							}

							updateCounter++
							return fmt.Errorf("update-error-1312")
						},
					},
				},
				args: args{
					ctx: ctx,
				},
				checkFunc: func(h *hc) (err error) {
					defer cancel()

					var gotTimeDiff time.Duration
					startTime := time.Now()
					updateTime := [3]time.Time{}

					// check 1st run
					updateTime[0] = <-updateTimeChan
					if (updateTime[0] == time.Time{}) {
						return fmt.Errorf("StartCertUpdater() update did not run")
					}
					gotTimeDiff = updateTime[0].Sub(startTime).Round(time.Second)
					if gotTimeDiff != 0*time.Second {
						return fmt.Errorf("StartCertUpdater() update is supposed to start after 0s, got %v", gotTimeDiff)
					}

					// check 2nd run
					updateTime[1] = <-updateTimeChan
					if (updateTime[1] == time.Time{}) {
						return fmt.Errorf("StartCertUpdater() update did not run on error")
					}
					gotTimeDiff = updateTime[1].Sub(updateTime[0]).Round(time.Second)
					if gotTimeDiff != time.Second {
						return fmt.Errorf("StartCertUpdater() update did not run after 1s on error, got %v", gotTimeDiff)
					}

					// check 3rd run
					updateTime[2] = <-updateTimeChan
					if (updateTime[2] == time.Time{}) {
						return fmt.Errorf("StartCertUpdater() update did not run on error")
					}
					gotTimeDiff = updateTime[2].Sub(updateTime[1]).Round(time.Second)
					if gotTimeDiff != time.Second {
						return fmt.Errorf("StartCertUpdater() update did not run after 1s on error, got %v", gotTimeDiff)
					}

					return nil
				},
				afterFunc: func() error {
					go func() {
						<-ctx.Done()
						close(updateTimeChan)
					}()
					return nil
				},
			}
		}(),
		func() testcase {
			ctx, cancel := context.WithCancel(context.Background())
			updateTimeChan := make(chan time.Time, 3)
			updateCounter := 0

			return testcase{
				name: "Check hc StartCertUpdater, update runs based on internal state",
				fields: fields{
					nextExpire:       time.Second + time.Second,
					certExpireMargin: time.Second,
					updater: &updaterMock{
						updateMock: func() error {
							if updateCounter < 3 {
								updateTimeChan <- time.Now()
							}

							updateCounter++
							return nil
						},
					},
				},
				args: args{
					ctx: ctx,
				},
				checkFunc: func(h *hc) (err error) {
					defer cancel()

					var gotTimeDiff time.Duration
					startTime := time.Now()
					updateTime := [3]time.Time{}

					// check 1st run
					updateTime[0] = <-updateTimeChan
					if (updateTime[0] == time.Time{}) {
						return fmt.Errorf("StartCertUpdater() update did not run")
					}
					gotTimeDiff = updateTime[0].Sub(startTime).Round(time.Second)
					if gotTimeDiff != 0*time.Second {
						return fmt.Errorf("StartCertUpdater() update is supposed to start after 0s, got %v", gotTimeDiff)
					}

					// check 2nd run
					updateTime[1] = <-updateTimeChan
					if (updateTime[1] == time.Time{}) {
						return fmt.Errorf("StartCertUpdater() 2nd update did not run")
					}
					gotTimeDiff = updateTime[1].Sub(updateTime[0]).Round(time.Second)
					if gotTimeDiff != time.Second {
						return fmt.Errorf("StartCertUpdater() 2nd update did not run after 1s, got %v", gotTimeDiff)
					}

					// check 2nd run
					updateTime[2] = <-updateTimeChan
					if (updateTime[2] == time.Time{}) {
						return fmt.Errorf("StartCertUpdater() 3rd update did not run")
					}
					gotTimeDiff = updateTime[2].Sub(updateTime[1]).Round(time.Second)
					if gotTimeDiff != time.Second {
						return fmt.Errorf("StartCertUpdater() 3rd update did not run after 1s, got %v", gotTimeDiff)
					}

					return nil
				},
				afterFunc: func() error {
					go func() {
						<-ctx.Done()
						close(updateTimeChan)
					}()
					return nil
				},
			}
		}(),
	}

	glg.Get().SetMode(glg.NONE) // disable logger
	for _, tt := range tests {
		t.Run(tt.name, func(tt testcase) func(t *testing.T) {
			// cannot use closure, need to prevent tt from changing before run
			return func(t *testing.T) {
				t.Parallel()

				// before
				if tt.beforeFunc != nil {
					if err := tt.beforeFunc(); err != nil {
						t.Error(err)
						return
					}
				}

				// run
				h := &hc{
					nextExpire:       tt.fields.nextExpire,
					certExpireMargin: tt.fields.certExpireMargin,
					updater:          tt.fields.updater,
				}
				h.certs = gache.New()
				h.StartCertUpdater(tt.args.ctx)

				// check
				if tt.checkFunc != nil {
					err := tt.checkFunc(h)
					if err != nil {
						t.Error(err)
						return
					}
				}

				// after
				if tt.afterFunc != nil {
					if err := tt.afterFunc(); err != nil {
						t.Error(err)
						return
					}
				}
			}
		}(tt))
	}
}
