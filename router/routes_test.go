package router

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/yahoojapan/athenz-client-sidecar/config"
	"github.com/yahoojapan/athenz-client-sidecar/handler"
)

func TestNewRoutes(t *testing.T) {
	type args struct {
		h handler.Handler
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
				PrincipalAuthHeaderName: "X-test-auth-header",
				RoleAuthHeaderName: "X-test-role-header",
				BufferSize: 1024,
			}
			h := handler.New(proxyConfig, nil, nil, nil)

			return test{
				name: "Run NewRoutes successfully",
				args: args{
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
			got := NewRoutes(tt.args.h)
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
