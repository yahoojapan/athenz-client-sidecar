package main

import (
	"os"
	"reflect"
	"testing"

	"github.com/kpango/glg"
	"github.com/pkg/errors"
	"github.com/yahoojapan/athenz-client-sidecar/v2/config"
)

func TestParseParams(t *testing.T) {
	type test struct {
		name       string
		beforeFunc func()
		checkFunc  func(*params) error
		checkErr   bool
	}
	tests := []test{
		func() test {
			return test{
				name: "check parseParams set default value",
				beforeFunc: func() {
					os.Args = []string{""}
				},
				checkFunc: func(p *params) error {
					if p.configFilePath != "/etc/athenz/client/config.yaml" {
						return errors.Errorf("unexpected file path. got: %s, want: /etc/athenz/client/config.yaml", p.configFilePath)
					}
					if p.showVersion != false {
						return errors.Errorf("unexpected showVersion flag. got: %v, want : false", p.showVersion)
					}
					return nil
				},
				checkErr: false,
			}
		}(),
		func() test {
			return test{
				name: "check parse error",
				checkFunc: func(p *params) error {
					return nil
				},
				beforeFunc: func() {
					os.Args = []string{"", "-="}
				},
				checkErr: true,
			}
		}(),
		func() test {
			return test{
				name: "check parseParams set user flags",
				beforeFunc: func() {
					os.Args = []string{"", "-f", "/dummy/path", "-version", "true"}
				},
				checkFunc: func(p *params) error {
					if p.configFilePath != "/dummy/path" {
						return errors.Errorf("unexpected file path. got: %s, want: /dummy/path", p.configFilePath)
					}
					if p.showVersion != true {
						return errors.Errorf("unexpected showVersion flag. got: %v, want: true", p.showVersion)
					}

					return nil
				},
				checkErr: false,
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.beforeFunc != nil {
				tt.beforeFunc()
			}

			got, err := parseParams()
			if err != nil && !tt.checkErr {
				t.Errorf("unexpected error: %v", err)
			}
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("checkFunc() error: %v", err)
			}
		})
	}
}

// invalid values are added to Config{} in each test case so that the test case can end with server error instead of running indefinitely
func Test_run(t *testing.T) {
	type args struct {
		cfg config.Config
	}
	type test struct {
		name      string
		args      args
		checkFunc func([]error) error
	}
	tests := []test{
		{
			name: "run with log level, default",
			args: args{
				cfg: config.Config{
					NToken: config.NToken{
						Enable:        true,
						RefreshPeriod: "invalid",
					},
					Log: config.Log{
						Level: "",
					},
				},
			},
			checkFunc: func(gotErrs []error) error {
				wantExitingErr := "tenant error: ntokend error: invalid token refresh period invalid, time: invalid duration invalid"
				if gotErrs == nil || gotErrs[0].Error() != wantExitingErr {
					return errors.Errorf("Unexpected exit: %v", gotErrs)
				}

				g := glg.Get()
				got := []glg.MODE{
					g.GetCurrentMode(glg.FATAL),
					g.GetCurrentMode(glg.ERR),
					g.GetCurrentMode(glg.WARN),
					g.GetCurrentMode(glg.INFO),
					g.GetCurrentMode(glg.DEBG),
				}
				want := []glg.MODE{
					glg.NONE,
					glg.NONE,
					glg.NONE,
					glg.NONE,
					glg.NONE,
				}
				if !reflect.DeepEqual(got, want) {
					return errors.Errorf("got: %v, want: %v", got, want)
				}
				return nil
			},
		},
		{
			name: "run with log level, fatal",
			args: args{
				cfg: config.Config{
					NToken: config.NToken{
						Enable:        true,
						RefreshPeriod: "invalid",
					},
					Log: config.Log{
						Level: "fatal",
					},
				},
			},
			checkFunc: func(gotErrs []error) error {
				wantExitingErr := "tenant error: ntokend error: invalid token refresh period invalid, time: invalid duration invalid"
				if gotErrs == nil || gotErrs[0].Error() != wantExitingErr {
					return errors.Errorf("Unexpected exit: %v", gotErrs)
				}

				g := glg.Get()
				got := []glg.MODE{
					g.GetCurrentMode(glg.FATAL),
					g.GetCurrentMode(glg.ERR),
					g.GetCurrentMode(glg.WARN),
					g.GetCurrentMode(glg.INFO),
					g.GetCurrentMode(glg.DEBG),
				}
				want := []glg.MODE{
					glg.STD,
					glg.NONE,
					glg.NONE,
					glg.NONE,
					glg.NONE,
				}
				if !reflect.DeepEqual(got, want) {
					return errors.Errorf("got: %v, want: %v", got, want)
				}
				return nil
			},
		},
		{
			name: "run with log level, error",
			args: args{
				cfg: config.Config{
					NToken: config.NToken{
						Enable:        true,
						RefreshPeriod: "invalid",
					},
					Log: config.Log{
						Level: "error",
					},
				},
			},
			checkFunc: func(gotErrs []error) error {
				wantExitingErr := "tenant error: ntokend error: invalid token refresh period invalid, time: invalid duration invalid"
				if gotErrs == nil || gotErrs[0].Error() != wantExitingErr {
					return errors.Errorf("Unexpected exit: %v", gotErrs)
				}

				g := glg.Get()
				got := []glg.MODE{
					g.GetCurrentMode(glg.FATAL),
					g.GetCurrentMode(glg.ERR),
					g.GetCurrentMode(glg.WARN),
					g.GetCurrentMode(glg.INFO),
					g.GetCurrentMode(glg.DEBG),
				}
				want := []glg.MODE{
					glg.STD,
					glg.STD,
					glg.NONE,
					glg.NONE,
					glg.NONE,
				}
				if !reflect.DeepEqual(got, want) {
					return errors.Errorf("got: %v, want: %v", got, want)
				}
				return nil
			},
		},
		{
			name: "run with log level, warn",
			args: args{
				cfg: config.Config{
					NToken: config.NToken{
						Enable:        true,
						RefreshPeriod: "invalid",
					},
					Log: config.Log{
						Level: "warn",
					},
				},
			},
			checkFunc: func(gotErrs []error) error {
				wantExitingErr := "tenant error: ntokend error: invalid token refresh period invalid, time: invalid duration invalid"
				if gotErrs == nil || gotErrs[0].Error() != wantExitingErr {
					return errors.Errorf("Unexpected exit: %v", gotErrs)
				}

				g := glg.Get()
				got := []glg.MODE{
					g.GetCurrentMode(glg.FATAL),
					g.GetCurrentMode(glg.ERR),
					g.GetCurrentMode(glg.WARN),
					g.GetCurrentMode(glg.INFO),
					g.GetCurrentMode(glg.DEBG),
				}
				want := []glg.MODE{
					glg.STD,
					glg.STD,
					glg.STD,
					glg.NONE,
					glg.NONE,
				}
				if !reflect.DeepEqual(got, want) {
					return errors.Errorf("got: %v, want: %v", got, want)
				}
				return nil
			},
		},
		{
			name: "run with log level, info",
			args: args{
				cfg: config.Config{
					NToken: config.NToken{
						Enable:        true,
						RefreshPeriod: "invalid",
					},
					Log: config.Log{
						Level: "info",
					},
				},
			},
			checkFunc: func(gotErrs []error) error {
				wantExitingErr := "tenant error: ntokend error: invalid token refresh period invalid, time: invalid duration invalid"
				if gotErrs == nil || gotErrs[0].Error() != wantExitingErr {
					return errors.Errorf("Unexpected exit: %v", gotErrs)
				}

				g := glg.Get()
				got := []glg.MODE{
					g.GetCurrentMode(glg.FATAL),
					g.GetCurrentMode(glg.ERR),
					g.GetCurrentMode(glg.WARN),
					g.GetCurrentMode(glg.INFO),
					g.GetCurrentMode(glg.DEBG),
				}
				want := []glg.MODE{
					glg.STD,
					glg.STD,
					glg.STD,
					glg.STD,
					glg.NONE,
				}
				if !reflect.DeepEqual(got, want) {
					return errors.Errorf("got: %v, want: %v", got, want)
				}
				return nil
			},
		},
		{
			name: "run with log level, debug",
			args: args{
				cfg: config.Config{
					NToken: config.NToken{
						Enable:        true,
						RefreshPeriod: "invalid",
					},
					Log: config.Log{
						Level: "debug",
					},
				},
			},
			checkFunc: func(gotErrs []error) error {
				wantExitingErr := "tenant error: ntokend error: invalid token refresh period invalid, time: invalid duration invalid"
				if gotErrs == nil || gotErrs[0].Error() != wantExitingErr {
					return errors.Errorf("Unexpected exit: %v", gotErrs)
				}

				g := glg.Get()
				got := []glg.MODE{
					g.GetCurrentMode(glg.FATAL),
					g.GetCurrentMode(glg.ERR),
					g.GetCurrentMode(glg.WARN),
					g.GetCurrentMode(glg.INFO),
					g.GetCurrentMode(glg.DEBG),
				}
				want := []glg.MODE{
					glg.STD,
					glg.STD,
					glg.STD,
					glg.STD,
					glg.STD,
				}
				if !reflect.DeepEqual(got, want) {
					return errors.Errorf("got: %v, want: %v", got, want)
				}
				return nil
			},
		},
		{
			name: "run with log color",
			args: args{
				cfg: config.Config{
					NToken: config.NToken{
						Enable:        true,
						RefreshPeriod: "invalid",
					},
					Log: config.Log{
						Level: "info",
						Color: true,
					},
				},
			},
			checkFunc: func(gotErrs []error) error {
				wantExitingErr := "tenant error: ntokend error: invalid token refresh period invalid, time: invalid duration invalid"
				if gotErrs == nil || gotErrs[0].Error() != wantExitingErr {
					return errors.Errorf("Unexpected exit: %v", gotErrs)
				}

				// glg.logger.isColor is private, cannot test
				return nil
			},
		},
		{
			name: "invalid log level",
			args: args{
				cfg: config.Config{
					Log: config.Log{
						Level: "invalid",
					},
				},
			},
			checkFunc: func(gotErrs []error) error {
				want := "invalid log level"
				if len(gotErrs) != 1 {
					return errors.New("len(gotErrs) != 1")
				}
				if gotErrs[0].Error() != want {
					return errors.Errorf("gotErrs: %v, want: %v", gotErrs[0], want)
				}
				return nil
			},
		},
		{
			name: "run error",
			args: args{
				cfg: config.Config{
					NToken: config.NToken{
						Enable:         true,
						AthenzDomain:   "domain",
						ServiceName:    "service",
						RefreshPeriod:  "1h",
						KeyVersion:     "keyId",
						Expiry:         "1h",
						PrivateKeyPath: "./test/data/dummyServer.key",
					},
					RoleToken: config.RoleToken{
						Enable:        true,
						RefreshPeriod: "dummy",
					},
				},
			},
			checkFunc: func(gotErrs []error) error {
				want := "tenant error: role token service error: RefreshPeriod: time: invalid duration dummy: Invalid config"
				if len(gotErrs) != 1 {
					return errors.New("len(gotErrs) != 1")
				}
				if gotErrs[0].Error() != want {
					return errors.Errorf("gotErrs: %v, want: %v", gotErrs[0], want)
				}
				return nil
			},
		},
		{
			name: "daemon init error",
			args: args{
				cfg: config.Config{
					NToken: config.NToken{
						Enable:        true,
						RefreshPeriod: "dummy",
					},
				},
			},
			checkFunc: func(gotErrs []error) error {
				want := "tenant error: ntokend error: invalid token refresh period dummy, time: invalid duration dummy"
				if len(gotErrs) != 1 {
					return errors.New("len(gotErrs) != 1")
				}
				if gotErrs[0].Error() != want {
					return errors.Errorf("gotErrs: %v, want: %v", gotErrs[0], want)
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotErrs := run(tt.args.cfg)
			if err := tt.checkFunc(gotErrs); err != nil {
				t.Errorf("run() fails: %v", err)
			}
		})
	}
}

func Test_getVersion(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{
			name: "default",
			want: "development version",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getVersion(); got != tt.want {
				t.Errorf("getVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}
