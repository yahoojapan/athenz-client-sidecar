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
package config

import (
	"os"
	"strings"

	yaml "gopkg.in/yaml.v2"
)

// Config represents the configuration of client sidecar application.
type Config struct {
	// Version represent the client sidecar application version.
	Version string `yaml:"version"`

	// EnableColorLogging represents if user want to enable colorized logging.
	EnableColorLogging bool `yaml:"enable_log_color"`

	// Server represent the client sidecar and health check server configuration.
	Server Server `yaml:"server"`

	// Token represent the configuration to generate N-token to connect to athenz.
	Token Token `yaml:"ntoken"`

	// Role represent the configuration to generate role token from athenz server.
	Role Role `yaml:"roletoken"`

	// Proxy represent the configuration of the reverse proxy server to connect to athenz to get N-token and role token.
	Proxy Proxy `yaml:"proxy"`
}

// Server represent client sidecar server and health check server configuration.
type Server struct {
	// Port represent client sidecar server port.
	Port int `yaml:"port"`

	// HealthzPort represent health check server port for K8s.
	HealthzPort int `yaml:"health_check_port"`

	// HealthzPath represent the server path (pattern) for health check server.
	HealthzPath string `yaml:"health_check_path"`

	// Timeout represent the client sidecar server timeout value.
	Timeout string `yaml:"timeout"`

	// ShutdownDuration represent the parse duration before the server shutdown.
	ShutdownDuration string `yaml:"shutdown_duration"`

	// ProbeWaitTime represent the parse duration between health check server and client sidecar server shutdown.
	ProbeWaitTime string `yaml:"probe_wait_time"`

	// TLS represent the TLS configuration for client sidecar server.
	TLS TLS `yaml:"tls"`
}

// TLS represent the TLS configuration for client sidecar server.
type TLS struct {
	// Enable represent the client sidecar server enable TLS or not.
	Enabled bool `yaml:"enabled"`

	// Cert represent the certificate used to start client sidecar server.
	Cert string `yaml:"cert"`

	// Key represent the private key used to start client sidecar server.
	Key string `yaml:"key"`

	// CAKey represent the CA certificate used to start client sidecar server.
	CA string `yaml:"ca"`
}

// Proxy represent the reverse proxy configuration to connect to Athenz server
type Proxy struct {
	// PrincipalAuthHeaderName represent the HTTP header key name of the authenication token for N-Token proxy request
	PrincipalAuthHeaderName string `yaml:"auth_header_key"`

	// RoleAuthHeaderName represent the HTTP header key name of the role token for Role token proxy request
	RoleAuthHeaderName string `yaml:"role_header_key"`

	// BufferSize represent the reverse proxy buffer size
	BufferSize uint64 `yaml:"buffer_size"`
}

// Token represent the N-token detail to get the host certificate and role token
type Token struct {
	// AthenzDomain represent the athenz domain value to generate the N-token.
	AthenzDomain string `yaml:"athenz_domain"`

	// ServiceName represent the athenz service name value to generate the N-token.
	ServiceName string `yaml:"service_name"`

	// NTokenPath represent the N-token path, this field is only for Copper Argos.
	NTokenPath string `yaml:"ntoken_path"`

	// PrivateKeyPath represent the private key environment name to sign the token.
	PrivateKeyPath string `yaml:"private_key_path"`

	// ValidateToken represent to validate the token or not, this should be set to true when the NTokenPath is set.
	ValidateToken bool `yaml:"validate_token"`

	// RefreshDuration represent the token refresh duration, weather it is generated, or it is Copper Argos.
	RefreshDuration string `yaml:"refresh_duration"`

	// KeyVersion represent the key version on the N-token.
	KeyVersion string `yaml:"key_version"`

	// Expiration represent the duration of the expiration.
	Expiration string `yaml:"expiration"`
}

// Role represent the Role token configuration
type Role struct {
	// PrincipalAuthHeaderName is the HTTP header name for holding the n-token.
	PrincipalAuthHeaderName string `yaml:"auth_header_key"`

	// AthenzURL represent the athenz URL to get the role token
	AthenzURL string `yaml:"athenz_url"`

	// AthenzRootCA represent the Athenz server Root Certificate
	AthenzRootCA string `yaml:"athenz_root_ca"`

	// TokenExpiry represent the duration of the expiration
	TokenExpiry string `yaml:"expiration"`
}

const (
	currentVersion = "v1.0.0"
)

// New returns *Config or error when decode the configuration file to actually *Config struct.
func New(path string) (*Config, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0600)
	if err != nil {
		return nil, err
	}
	cfg := new(Config)
	err = yaml.NewDecoder(f).Decode(&cfg)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

// GetVersion returns the current version of the client sidecar version.
func GetVersion() string {
	return currentVersion
}

// GetActualValue returns the environment variable value if the val has prefix and suffix "_", otherwise the val will directly return.
func GetActualValue(val string) string {
	if checkPrefixAndSuffix(val, "_", "_") {
		return os.Getenv(strings.TrimPrefix(strings.TrimSuffix(val, "_"), "_"))
	}
	return val
}

// checkPrefixAndSuffix checks if the str has prefix and suffix
func checkPrefixAndSuffix(str, pref, suf string) bool {
	return strings.HasPrefix(str, pref) && strings.HasSuffix(str, suf)
}
