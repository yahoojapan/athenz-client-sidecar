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
package service

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pkg/errors"
	"github.com/yahoojapan/athenz-client-sidecar/config"
)

func TestWithServerConfig(t *testing.T) {
	type args struct {
		cfg config.Server
	}
	tests := []struct {
		name      string
		args      args
		checkFunc func(Option) error
	}{
		{
			name: "set succes",
			args: args{
				cfg: config.Server{
					Port: 10000,
				},
			},
			checkFunc: func(o Option) error {
				srv := &server{}
				o(srv)
				if srv.cfg.Port != 10000 {
					return errors.New("value cannot set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithServerConfig(tt.args.cfg)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithServiceConfig() error = %v", err)
			}
		})
	}
}

func TestWithServerHandler(t *testing.T) {
	type args struct {
		h http.Handler
	}
	type test struct {
		name      string
		args      args
		checkFunc func(Option) error
	}
	tests := []test{
		func() test {
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(999)
			})
			return test{
				name: "set success",
				args: args{
					h: h,
				},
				checkFunc: func(o Option) error {
					srv := &server{}
					o(srv)
					r := &httptest.ResponseRecorder{}
					srv.srvHandler.ServeHTTP(r, nil)
					if r.Code != 999 {
						return errors.New("value cannot set")
					}
					return nil
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithServerHandler(tt.args.h)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithServerHandler() error = %v", err)
			}
		})
	}
}
