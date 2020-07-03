/*
Copyright (C)  2018 Yahoo Japan Corporation Athenz team.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package router

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/yahoojapan/athenz-client-sidecar/v2/config"
	"github.com/yahoojapan/athenz-client-sidecar/v2/handler"
)

func TestNewRoutes(t *testing.T) {
	type args struct {
		cfg config.Config
		h   handler.Handler
	}
	type test struct {
		name string
		args args
		want []Route
	}

	tests := []test{
		func() test {
			// prepare handler.Handler for calling NewRoutes()
			proxyConfig := config.Proxy{
				PrincipalAuthHeader: "X-test-auth-header",
				RoleAuthHeader:      "X-test-role-header",
				BufferSize:          1024,
			}
			h := handler.New(proxyConfig, nil, nil, nil, nil, nil)

			return test{
				name: "Run NewRoutes successfully",
				args: args{
					cfg: config.Config{
						ServiceCert: config.ServiceCert{
							Enable: true,
						},
						AccessToken: config.AccessToken{
							Enable: true,
						},
					},
					h: h,
				},
				want: []Route{
					{
						"NToken Handler",
						[]string{
							http.MethodGet,
						},
						"/ntoken",
						h.NToken,
					},
					{
						"RoleToken Handler",
						[]string{
							http.MethodPost,
						},
						"/roletoken",
						h.RoleToken,
					},
					{
						"RoleToken proxy Handler",
						[]string{
							"*",
						},
						"/proxy/roletoken",
						h.RoleTokenProxy,
					},
					{
						"NToken proxy Handler",
						[]string{
							"*",
						},
						"/proxy/ntoken",
						h.NTokenProxy,
					},
					{
						"Access Token Handler",
						[]string{
							http.MethodPost,
						},
						"/accesstoken",
						h.AccessToken,
					},
					{
						"Service Cert Handler",
						[]string{
							http.MethodGet,
						},
						"/svccert",
						h.ServiceCert,
					},
				},
			}
		}(),
		func() test {
			// prepare handler.Handler for calling NewRoutes()
			proxyConfig := config.Proxy{
				PrincipalAuthHeader: "X-test-auth-header",
				RoleAuthHeader:      "X-test-role-header",
				BufferSize:          1024,
			}
			h := handler.New(proxyConfig, nil, nil, nil, nil, nil)

			return test{
				name: "Run NewRoutes successfully without ServiceCert and AccessToken",
				args: args{
					cfg: config.Config{
						ServiceCert: config.ServiceCert{
							Enable: false,
						},
						AccessToken: config.AccessToken{
							Enable: false,
						},
					},
					h: h,
				},
				want: []Route{
					{
						"NToken Handler",
						[]string{
							http.MethodGet,
						},
						"/ntoken",
						h.NToken,
					},
					{
						"RoleToken Handler",
						[]string{
							http.MethodPost,
						},
						"/roletoken",
						h.RoleToken,
					},
					{
						"RoleToken proxy Handler",
						[]string{
							"*",
						},
						"/proxy/roletoken",
						h.RoleTokenProxy,
					},
					{
						"NToken proxy Handler",
						[]string{
							"*",
						},
						"/proxy/ntoken",
						h.NTokenProxy,
					},
				},
			}
		}(),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewRoutes(tt.args.cfg, tt.args.h)
			if got == nil {
				t.Errorf("NewRoutes() = %v, want %v", got, tt.want)
				return
			}

			for i, gotValue := range got {
				wantValue := tt.want[i]
				if gotValue.Name != wantValue.Name ||
					!reflect.DeepEqual(gotValue.Methods, wantValue.Methods) ||
					gotValue.Pattern != wantValue.Pattern ||
					reflect.ValueOf(gotValue.HandlerFunc).Pointer() != reflect.ValueOf(wantValue.HandlerFunc).Pointer() {
					t.Errorf("got and want unmatched: got: %v  want: %v", gotValue, wantValue)
					return
				}
			}
		})
	}
}
