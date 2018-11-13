package config

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestGetVersion(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{
			name: "Get Tenant Sidecar version",
			want: "v1.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetVersion(); got != tt.want {
				t.Errorf("GetVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNew(t *testing.T) {
	type args struct {
		path string
	}
	type test struct {
		name    string
		args    args
		want    *Config
		wantErr error
	}
	tests := []test{
		test{
			name: "Read valid config file",
			args: args{
				path: "./assets/valid_config.yaml",
			},
			want: &Config{
				Version: "v1.0.0",
				Server: Server{
					Port:             8080,
					HealthzPort:      80,
					HealthzPath:      "/healthz",
					Timeout:          "10s",
					ShutdownDuration: "5s",
					TLS: TLS{
						Enabled: true,
						CertKey: "cert",
						KeyKey:  "key",
						CAKey:   "ca",
					},
				},
				Token: Token{
					AthenzDomain:    "_athenz_domain_",
					ServiceName:     "_service_name_",
					NTokenPath:      "/tmp/ntoken",
					PrivateKeyPath:  "_athenz_private_key_",
					ValidateToken:   false,
					RefreshDuration: "30m",
					KeyVersion:      "v1.0",
					Expiration:      "20m",
				},
				Role: Role{
					AuthHeader:  "Yahoo-Principal-Auth",
					AthenzURL:   "https://alpha.zts.athenz.yahoo.co.jp:4443/zts/v1",
					TokenExpiry: "30m",
				},
				Proxy: Proxy{
					AuthHeader: "Athenz-Principal-Auth",
					RoleHeader: "Athenz-Role-Auth",
					BufferSize: 1024,
				},
			},
		},
		test{
			name: "Read invalid config file",
			args: args{
				path: "./assets/invalid_config.yaml",
			},
			wantErr: fmt.Errorf("yaml: line "),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.args.path)
			if err != nil && tt.wantErr == nil {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("want error: %v, got nil", tt.wantErr)
					return
				}
				if !strings.HasPrefix(err.Error(), tt.wantErr.Error()) {
					t.Errorf("New() error: %v, want: %v", err, tt.wantErr)
					return
				}
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
				return
			}
		})
	}
}

func TestGetActualValue(t *testing.T) {
	type args struct {
		cfg string
	}
	tests := []struct {
		name       string
		args       args
		beforeFunc func() error
		afterFunc  func() error
		want       string
	}{
		{
			name: "Get value from environment variable with prefix and suffix",
			args: args{
				cfg: "_KEY_WITH_PREFIX_AND_SUFFIX_",
			},
			beforeFunc: func() error {
				return os.Setenv("KEY_WITH_PREFIX_AND_SUFFIX", "value_for_key_with_prefix_and_suffix")
			},
			afterFunc: func() error {
				return os.Unsetenv("KEY_WITH_PREFIX_AND_SUFFIX")
			},
			want: "value_for_key_with_prefix_and_suffix",
		},
		{
			name: "Get config string directly if prefix and suffix are not set",
			args: args{
				cfg: "KEY_WITHOUT_PREFIX_AND_SUFFIX",
			},
			want: "KEY_WITHOUT_PREFIX_AND_SUFFIX",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.beforeFunc != nil {
				tt.beforeFunc()
			}
			if tt.afterFunc != nil {
				defer tt.afterFunc()
			}
			if got := GetActualValue(tt.args.cfg); got != tt.want {
				t.Errorf("GetActualValue() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_checkPrefixAndSuffix(t *testing.T) {
	type args struct {
		str  string
		pref string
		suf  string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Check the string with specified prefix and suffix",
			args: args{
				str:  "_teststr_",
				pref: "_",
				suf:  "_",
			},
			want: true,
		},
		{
			name: "Check the string without prefix and suffix",
			args: args{
				str:  "teststr",
				pref: "_",
				suf:  "_",
			},
			want: false,
		},
		{
			name: "Check the string with prefix only",
			args: args{
				str:  "_teststr",
				pref: "_",
				suf:  "_",
			},
			want: false,
		},
		{
			name: "Check the string with suffix only",
			args: args{
				str:  "teststr_",
				pref: "_",
				suf:  "_",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checkPrefixAndSuffix(tt.args.str, tt.args.pref, tt.args.suf); got != tt.want {
				t.Errorf("checkPrefixAndSuffix() = %v, want %v", got, tt.want)
			}
		})
	}
}
