package service

import (
	"crypto/tls"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"ghe.corp.yahoo.co.jp/athenz/athenz-tenant-sidecar/config"
)

func TestNewTLSConfig(t *testing.T) {
	type args struct {
		CertKeyPath string
		KeyKeyPath  string
		CAKeyPath   string
		cfg         config.TLS
	}
	type test struct {
		name       string
		args       args
		want       *tls.Config
		beforeFunc func(args args)
		afterFunc  func(args args)
		checkFunc  func(*tls.Config, *tls.Config) error
		wantErr    error
	}

	defaultArgs := args{
		CertKeyPath: "./assets/dummyServer.crt",
		KeyKeyPath:  "./assets/dummyServer.key",
		CAKeyPath:   "./assets/dummyCa.pem",
		cfg: config.TLS{
			CertKey: "test_cert",
			KeyKey:  "test_key",
			CAKey:   "test_ca",
		},
	}

	tests := []test{
		test{
			name: "Check the minimum SSL/TLS version",
			args: defaultArgs,
			want: &tls.Config{
				MinVersion: tls.VersionTLS12,
				// CurvePreferences: []tls.CurveID{
				// 	tls.CurveP521,
				// 	tls.CurveP384,
				// 	tls.CurveP256,
				// 	tls.X25519,
				// },
				// SessionTicketsDisabled: true,
				// Certificates: func() []tls.Certificate {
				// 	cert, _ := tls.LoadX509KeyPair(defaultArgs.CertKeyPath, defaultArgs.KeyKeyPath)
				// 	return []tls.Certificate{cert}
				// }(),
				// ClientAuth: tls.RequireAndVerifyClientCert,
			},
			beforeFunc: func(args args) {
				os.Setenv(args.cfg.CertKey, args.CertKeyPath)
				os.Setenv(args.cfg.KeyKey, args.KeyKeyPath)
				os.Setenv(args.cfg.CAKey, args.CAKeyPath)
			},
			afterFunc: func(args args) {
				os.Unsetenv(args.cfg.CertKey)
				os.Unsetenv(args.cfg.KeyKey)
				os.Unsetenv(args.cfg.CAKey)
			},
			checkFunc: func(got, want *tls.Config) error {
				if got.MinVersion != want.MinVersion {
					return fmt.Errorf("MinVersion unmatched: got: %d  want: %d", got.MinVersion, want.MinVersion)
				}
				return nil
			},
		},
		test{
			name: "Check values of 'CurvePreferences'",
			args: defaultArgs,
			want: &tls.Config{
				// MinVersion: tls.VersionTLS12,
				CurvePreferences: []tls.CurveID{
					tls.CurveP256,
					tls.CurveP384,
					tls.CurveP521,
					tls.X25519,
				},
				// SessionTicketsDisabled: true,
				// Certificates: func() []tls.Certificate {
				// 	cert, _ := tls.LoadX509KeyPair(defaultArgs.CertKeyPath, defaultArgs.KeyKeyPath)
				// 	return []tls.Certificate{cert}
				// }(),
				// ClientAuth: tls.RequireAndVerifyClientCert,
			},
			beforeFunc: func(args args) {
				os.Setenv(args.cfg.CertKey, args.CertKeyPath)
				os.Setenv(args.cfg.KeyKey, args.KeyKeyPath)
				os.Setenv(args.cfg.CAKey, args.CAKeyPath)
			},
			afterFunc: func(args args) {
				os.Unsetenv(args.cfg.CertKey)
				os.Unsetenv(args.cfg.KeyKey)
				os.Unsetenv(args.cfg.CAKey)
			},
			checkFunc: func(got, want *tls.Config) error {
				if len(got.CurvePreferences) != len(want.CurvePreferences) {
					return fmt.Errorf("The length of CurvePreferences not matched: got: %d  want: %d", len(got.CurvePreferences), len(want.CurvePreferences))
				}

				for _, actual := range got.CurvePreferences {
					var hasValue bool
					for _, expected := range want.CurvePreferences {
						if actual == expected {
							hasValue = true
							break
						}
					}
					if !hasValue {
						return fmt.Errorf("The actual value of CurvePreferences not found in the expected: got: %v  want: %v", got.CurvePreferences, want.CurvePreferences)
					}
				}

				return nil
			},
		},
		test{
			name: "Check whether the value of 'SessionTicketsDisabled' is true",
			args: defaultArgs,
			want: &tls.Config{
				// MinVersion: tls.VersionTLS12,
				// CurvePreferences: []tls.CurveID{
				// 	tls.CurveP256,
				// 	tls.CurveP384,
				// 	tls.CurveP521,
				// 	tls.X25519,
				// },
				SessionTicketsDisabled: true,
				// Certificates: func() []tls.Certificate {
				// 	cert, _ := tls.LoadX509KeyPair(defaultArgs.CertKeyPath, defaultArgs.KeyKeyPath)
				// 	return []tls.Certificate{cert}
				// }(),
				// ClientAuth: tls.RequireAndVerifyClientCert,
			},
			beforeFunc: func(args args) {
				os.Setenv(args.cfg.CertKey, args.CertKeyPath)
				os.Setenv(args.cfg.KeyKey, args.KeyKeyPath)
				os.Setenv(args.cfg.CAKey, args.CAKeyPath)
			},
			afterFunc: func(args args) {
				os.Unsetenv(args.cfg.CertKey)
				os.Unsetenv(args.cfg.KeyKey)
				os.Unsetenv(args.cfg.CAKey)
			},
			checkFunc: func(got, want *tls.Config) error {
				if got.SessionTicketsDisabled != want.SessionTicketsDisabled {
					return fmt.Errorf("SessionTicketsDisabled is not as same as wanted: got: %t  want: %t", got.SessionTicketsDisabled, want.SessionTicketsDisabled)
				}
				return nil
			},
		},
		test{
			name: "Check certificates",
			args: defaultArgs,
			want: &tls.Config{
				// MinVersion: tls.VersionTLS12,
				// CurvePreferences: []tls.CurveID{
				// 	tls.CurveP256,
				// 	tls.CurveP384,
				// 	tls.CurveP521,
				// 	tls.X25519,
				// },
				// SessionTicketsDisabled: true,
				Certificates: func() []tls.Certificate {
					cert, _ := tls.LoadX509KeyPair(defaultArgs.CertKeyPath, defaultArgs.KeyKeyPath)
					return []tls.Certificate{cert}
				}(),
				// ClientAuth: tls.RequireAndVerifyClientCert,
			},
			beforeFunc: func(args args) {
				os.Setenv(args.cfg.CertKey, args.CertKeyPath)
				os.Setenv(args.cfg.KeyKey, args.KeyKeyPath)
				os.Setenv(args.cfg.CAKey, args.CAKeyPath)
			},
			afterFunc: func(args args) {
				os.Unsetenv(args.cfg.CertKey)
				os.Unsetenv(args.cfg.KeyKey)
				os.Unsetenv(args.cfg.CAKey)
			},
			checkFunc: func(got, want *tls.Config) error {
				if !reflect.DeepEqual(got.Certificates, want.Certificates) {
					return fmt.Errorf("Certificates unmatched: got: %v  want: %v", got.Certificates, want.Certificates)
				}
				return nil
			},
		},
		test{
			name: "Check whether ClientAuth is 'RequireAndVerifyClientCert'",
			args: defaultArgs,
			want: &tls.Config{
				// MinVersion: tls.VersionTLS12,
				// CurvePreferences: []tls.CurveID{
				// 	tls.CurveP256,
				// 	tls.CurveP384,
				// 	tls.CurveP521,
				// 	tls.X25519,
				// },
				// SessionTicketsDisabled: true,
				// Certificates: func() []tls.Certificate {
				// 	cert, _ := tls.LoadX509KeyPair(defaultArgs.CertKeyPath, defaultArgs.KeyKeyPath)
				// 	return []tls.Certificate{cert}
				// }(),
				ClientAuth: tls.RequireAndVerifyClientCert,
			},
			beforeFunc: func(args args) {
				os.Setenv(args.cfg.CertKey, args.CertKeyPath)
				os.Setenv(args.cfg.KeyKey, args.KeyKeyPath)
				os.Setenv(args.cfg.CAKey, args.CAKeyPath)
			},
			afterFunc: func(args args) {
				os.Unsetenv(args.cfg.CertKey)
				os.Unsetenv(args.cfg.KeyKey)
				os.Unsetenv(args.cfg.CAKey)
			},
			checkFunc: func(got, want *tls.Config) error {
				if got.ClientAuth != want.ClientAuth {
					return fmt.Errorf("ClientAuth is not 'RequireAndVerifyClientCert': got: %d  want: %d", got.ClientAuth, want.ClientAuth)
				}
				return nil
			},
		},
		test{
			name: "Request without cert file",
			args: defaultArgs,
			beforeFunc: func(args args) {
				os.Setenv(args.cfg.KeyKey, args.KeyKeyPath)
				os.Setenv(args.cfg.CAKey, args.CAKeyPath)
			},
			afterFunc: func(args args) {
				os.Unsetenv(args.cfg.KeyKey)
				os.Unsetenv(args.cfg.CAKey)
			},
			wantErr: fmt.Errorf("Cert/Key path not found"),
		},
		test{
			name: "Request without key file",
			args: defaultArgs,
			beforeFunc: func(args args) {
				os.Setenv(args.cfg.CertKey, args.CertKeyPath)
				os.Setenv(args.cfg.CAKey, args.CAKeyPath)
			},
			afterFunc: func(args args) {
				os.Unsetenv(args.cfg.CertKey)
				os.Unsetenv(args.cfg.CAKey)
			},
			wantErr: fmt.Errorf("Cert/Key path not found"),
		},
		test{
			name: "Check whether ClientAuth is 'NoClientCert' when requesting without CA file",
			args: defaultArgs,
			want: &tls.Config{
				// MinVersion: tls.VersionTLS12,
				// CurvePreferences: []tls.CurveID{
				// 	tls.CurveP256,
				// 	tls.CurveP384,
				// 	tls.CurveP521,
				// 	tls.X25519,
				// },
				// SessionTicketsDisabled: true,
				// Certificates: func() []tls.Certificate {
				// 	cert, _ := tls.LoadX509KeyPair(defaultArgs.CertKeyPath, defaultArgs.KeyKeyPath)
				// 	return []tls.Certificate{cert}
				// }(),
				ClientAuth: tls.NoClientCert,
			},
			beforeFunc: func(args args) {
				os.Setenv(args.cfg.CertKey, args.CertKeyPath)
				os.Setenv(args.cfg.KeyKey, args.KeyKeyPath)
			},
			afterFunc: func(args args) {
				os.Unsetenv(args.cfg.CertKey)
				os.Unsetenv(args.cfg.KeyKey)
			},
			checkFunc: func(got, want *tls.Config) error {
				if got.ClientAuth != want.ClientAuth {
					return fmt.Errorf("ClientAuth is not 'NoClientCert': got: %d  want: %d", got.ClientAuth, want.ClientAuth)
				}
				return nil
			},
		},
		test{
			name: "Request with invalid cert file",
			args: defaultArgs,
			beforeFunc: func(args args) {
				args.CertKeyPath = "./assets/invalid_dummyServer.crt"
				os.Setenv(args.cfg.CertKey, args.CertKeyPath)
				os.Setenv(args.cfg.KeyKey, args.KeyKeyPath)
				os.Setenv(args.cfg.CAKey, args.CAKeyPath)
			},
			afterFunc: func(args args) {
				os.Unsetenv(args.cfg.CertKey)
				os.Unsetenv(args.cfg.KeyKey)
				os.Unsetenv(args.cfg.CAKey)
			},
			wantErr: fmt.Errorf("tls: failed to find any PEM data in certificate input"),
		},
		test{
			name: "Request with invalid key file",
			args: defaultArgs,
			beforeFunc: func(args args) {
				args.KeyKeyPath = "./assets/invalid_dummyServer.key"
				os.Setenv(args.cfg.CertKey, args.CertKeyPath)
				os.Setenv(args.cfg.KeyKey, args.KeyKeyPath)
				os.Setenv(args.cfg.CAKey, args.CAKeyPath)
			},
			afterFunc: func(args args) {
				os.Unsetenv(args.cfg.CertKey)
				os.Unsetenv(args.cfg.KeyKey)
				os.Unsetenv(args.cfg.CAKey)
			},
			wantErr: fmt.Errorf("tls: failed to find any PEM data in key input"),
		},
		test{
			name: "Request with invalid CA file",
			args: defaultArgs,
			beforeFunc: func(args args) {
				args.CAKeyPath = "./assets/invalid_dummyCa.pem"
				os.Setenv(args.cfg.CertKey, args.CertKeyPath)
				os.Setenv(args.cfg.KeyKey, args.KeyKeyPath)
				os.Setenv(args.cfg.CAKey, args.CAKeyPath)
			},
			afterFunc: func(args args) {
				os.Unsetenv(args.cfg.CertKey)
				os.Unsetenv(args.cfg.KeyKey)
				os.Unsetenv(args.cfg.CAKey)
			},
			wantErr: fmt.Errorf("Certification Failed"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.beforeFunc != nil {
				tt.beforeFunc(tt.args)
			}
			if tt.afterFunc != nil {
				defer tt.afterFunc(tt.args)
			}

			got, err := NewTLSConfig(tt.args.cfg)

			if tt.wantErr == nil && err != nil {
				t.Errorf("NewTLSConfig() error: %v  wantErr: %v", err, tt.wantErr)
				return
			}
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("Error should occur: want error: %v  want: %v", err, tt.wantErr)
					return
				}
				// Here is comparing error message with expected
				if err.Error() != tt.wantErr.Error() {
					t.Errorf("Assertion failed: got: %v  want: %v", err, tt.wantErr)
					return
				}
			}

			if tt.checkFunc != nil {
				err = tt.checkFunc(got, tt.want)
				if err != nil {
					t.Errorf("NewTLSConfig() error = %v", err)
					return
				}
			}
		})
	}
}

func TestNewX509CertPool(t *testing.T) {
	type args struct {
		path string
	}
	type test struct {
		name    string
		args    args
		wantErr error
	}

	tests := []test{
		test{
			name: "Get CA cert pool",
			args: args{
				path: "./assets/dummyCa.pem",
			},
		},
		test{
			name: "Missing CA file",
			args: args{
				path: "/tmp/CAfilenotfound.pem",
			},
			wantErr: fmt.Errorf("no such file or directory"),
		},
		test{
			name: "Argument not specified",
			args: args{
				path: "",
			},
			wantErr: fmt.Errorf("no such file or directory"),
		},
		test{
			name: "Request with invalid CA file",
			args: args{
				path: "./assets/invalid_dummyCa.pem",
			},
			wantErr: fmt.Errorf("Certification Failed"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewX509CertPool(tt.args.path)
			if err != nil && tt.wantErr == nil {
				t.Errorf("NewX509CertPool() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("want error: %v  got: %v", tt.wantErr, err)
					return
				}
				if !strings.Contains(err.Error(), tt.wantErr.Error()) {
					t.Errorf("NewX509CertPool() error: %v, want: %v", err, tt.wantErr)
					return
				}
			} else {
				if got == nil {
					t.Errorf("CertPool should not be empty: got: %v", got)
					return
				}
			}
		})
	}
}
