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

const (
	currentVersion = "v2.0.0"
)

// Config represents the configuration of client sidecar application.
type Config struct {
	// Version represents the client sidecar application version.
	Version string `yaml:"version"`

	// EnableColorLogging represents if user want to enable colorized logging.
	EnableColorLogging bool `yaml:"enable_log_color"`

	// Server represents the client sidecar and health check server configuration.
	Server Server `yaml:"server"`

	// Token represents the configuration to generate N-token to connect to Athenz.
	Token Token `yaml:"ntoken"`

	// Access represents the configuration to retrieve access token from Athenz server.
	Access Access `yaml:"access_token"`

	// Role represents the configuration to retrieve role token from Athenz server.
	Role Role `yaml:"roletoken"`

	// Proxy represents the configuration of the reverse proxy server to connect to Athenz to get N-token and role token.
	Proxy Proxy `yaml:"proxy"`

	// ServiceCert represents the configuration of the service identify in the form of short-lived X.509 certificates that can be used instead of N-token in Athenz.
	ServiceCert ServiceCert `yaml:"service_cert"`

	// Log represents the logger configuration.
	Log Log `yaml:"log"`
}

// Server represents client sidecar server and health check server configuration.
type Server struct {
	// Port represents client sidecar server port.
	Port int `yaml:"port"`

	// HealthzPort represents health check server port for K8s.
	HealthzPort int `yaml:"health_check_port"`

	// HealthzPath represents the server path (pattern) for health check server.
	HealthzPath string `yaml:"health_check_path"`

	// Timeout represents the client sidecar server timeout value.
	Timeout string `yaml:"timeout"`

	// ShutdownDuration represents the parse duration before the server shutdown.
	ShutdownDuration string `yaml:"shutdown_duration"`

	// ProbeWaitTime represents the parse duration between health check server and client sidecar server shutdown.
	ProbeWaitTime string `yaml:"probe_wait_time"`

	// TLS represents the TLS configuration for client sidecar server.
	TLS TLS `yaml:"tls"`
}

// TLS represents the TLS configuration for client sidecar server.
type TLS struct {
	// Enable represents the client sidecar server enable TLS or not.
	Enabled bool `yaml:"enabled"`

	// Cert represents the certificate used to start client sidecar server.
	Cert string `yaml:"cert"`

	// Key represents the private key used to start client sidecar server.
	Key string `yaml:"key"`

	// CAKey represents the CA certificate used to start client sidecar server.
	CA string `yaml:"ca"`
}

// Proxy represents the reverse proxy configuration to connect to Athenz server
type Proxy struct {
	// PrincipalAuthHeaderName represents the HTTP header key name of the authenication token for N-Token proxy request
	PrincipalAuthHeaderName string `yaml:"auth_header_key"`

	// RoleAuthHeaderName represents the HTTP header key name of the role token for Role token proxy request
	RoleAuthHeaderName string `yaml:"role_header_key"`

	// BufferSize represents the reverse proxy buffer size
	BufferSize uint64 `yaml:"buffer_size"`
}

// Token represents the N-token detail to retrieve other Athenz credentials
type Token struct {
	// AthenzDomain represents the Athenz domain value to generate the N-token.
	AthenzDomain string `yaml:"athenz_domain"`

	// ServiceName represents the Athenz service name value to generate the N-token.
	ServiceName string `yaml:"service_name"`

	// NTokenPath represents the N-token path, this field is only for Copper Argos.
	NTokenPath string `yaml:"ntoken_path"`

	// PrivateKeyPath represents the private key environment name to sign the token.
	PrivateKeyPath string `yaml:"private_key_path"`

	// ValidateToken represents to validate the token or not, this should be set to true when the NTokenPath is set.
	ValidateToken bool `yaml:"validate_token"`

	// RefreshDuration represents the token refresh duration, weather it is generated, or it is Copper Argos.
	RefreshDuration string `yaml:"refresh_duration"`

	// KeyVersion represents the key version on the N-token.
	KeyVersion string `yaml:"key_version"`

	// Expiration represents the duration of the expiration.
	Expiration string `yaml:"expiration"`
}

// Access represents the Access token configuration
type Access struct {
	// Enable decides wheather use access token
	Enable bool `yaml:"enable"`

	// PrincipalAuthHeaderName is the HTTP header name for holding the n-token.
	PrincipalAuthHeaderName string `yaml:"auth_header_key"`

	// AthenzURL represents the Athenz URL to retrieve the access token
	AthenzURL string `yaml:"athenz_url"`

	// AthenzRootCA represents the Athenz server Root Certificate
	AthenzRootCA string `yaml:"athenz_root_ca"`

	// TokenExpiry represents the duration of the expiration
	TokenExpiry string `yaml:"expiration"`

	// RefreshInterval represents the access token refresh duration.
	RefreshInterval string `yaml:"refresh_interval"`

	// ErrRetryMaxCount represents the maximum error retry count during refreshing the access token cache.
	ErrRetryMaxCount int `yaml:"err_retry_max_count"`

	// ErrRetryInterval represents the error retry interval when refreshing the access token cache.
	ErrRetryInterval string `yaml:"err_retry_interval"`
}

// Role represents the Role token configuration
type Role struct {
	// PrincipalAuthHeaderName is the HTTP header name for holding the n-token.
	PrincipalAuthHeaderName string `yaml:"auth_header_key"`

	// AthenzURL represents the Athenz URL to retrieve the role token
	AthenzURL string `yaml:"athenz_url"`

	// AthenzRootCA represents the Athenz server Root Certificate
	AthenzRootCA string `yaml:"athenz_root_ca"`

	// TokenExpiry represents the duration of the expiration
	TokenExpiry string `yaml:"expiration"`

	// RefreshInterval represents the role token refresh duration.
	RefreshInterval string `yaml:"refresh_interval"`

	// ErrRetryMaxCount represents the maximum error retry count during refreshing the role token cache.
	ErrRetryMaxCount int `yaml:"err_retry_max_count"`

	// ErrRetryInterval represents the error retry interval when refreshing the role token cache.
	ErrRetryInterval string `yaml:"err_retry_interval"`
}

// ServiceCert represents the service cert configuration
type ServiceCert struct {
	// Enable decides wheather use service cert
	Enable bool `yaml:"enable"`

	// AthenzURL represents the Athenz URL to retrieve the service certificate
	AthenzURL string `yaml:"athenz_url"`

	// AthenzRootCA represents the Athenz server Root Certificate
	AthenzRootCA string `yaml:"athenz_root_ca"`

	// DNSSuffix is the suffix of SAN
	DNSSuffix string `yaml:"dns_suffix"`

	// RefreshDuration represents the svccert refresh duration
	RefreshDuration string `yaml:"refresh_duration"`

	// ExpireMargin represents the duration.
	// Certificate is updated before ExpireMargin in "Not After" field.
	ExpireMargin string `yaml:"expire_margin"`

	// Expiration represents the duration of expire time for the certificate.
	Expiration string `yaml:"expiration"`

	// IntermediateCert decides wheather concatinate intermediate cert to end-entity cert
	IntermediateCert bool `yaml:"intermediate_cert"`

	// PrincipalAuthHeaderName is the HTTP header name for holding the n-token.
	PrincipalAuthHeaderName string `yaml:"auth_header_key"`

	// Spiffe decides wheather include spiffe or not
	Spiffe bool `yaml:"spiffe"`

	// Subject is subject fields of the certificate
	Subject Subject `yaml:"subject"`
}

// Subject represents subject fields of the certificate
type Subject struct {
	// Country is the Subject C/Country field of certificate
	Country string `yaml:"country"`

	// Province is the Subject ST/State or Province field of certificate
	Province string `yaml:"province"`

	// Organization is the Subject O/Organization field of the certificate
	Organization string `yaml:"organization"`

	// OrganizationalUnit is the Subject OU/OrganizationalUnit field of the certificate
	OrganizationalUnit string `yaml:"organizational_unit"`
}


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
