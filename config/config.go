package config

import (
	"os"
	"strings"

	yaml "gopkg.in/yaml.v2"
)

// Config represents the configuration of tenant sidecar application.
type Config struct {
	// Version represent the tenant sidecar application version.
	Version string `yaml:"version"`

	// Server represent the tenant sidecar and health check server configuration.
	Server Server `yaml:"server"`

	// Token represent the configuration to generate N-token to connect to athenz.
	Token Token `yaml:"ntoken"`

	// Role represent the configuration to generate role token from athenz server.
	Role Role `yaml:"roletoken"`

	// Proxy represent the configuration of the reverse proxy server to connect to athenz to get N-token and role token.
	Proxy Proxy `yaml:"proxy"`
}

// Server represent tenant sidecar server and health check server configuration.
type Server struct {
	// Port represent tenant sidecar server port.
	Port int `yaml:"port"`

	// HealthzPort represent health check server port for K8s.
	HealthzPort int `yaml:"health_check_port"`

	// HealthzPath represent the server path (pattern) for health check server.
	HealthzPath string `yaml:"health_check_path"`

	// Timeout represent the tenant sidecar server timeout value.
	Timeout string `yaml:"timeout"`

	// ShutdownDuration represent the parse duration before the server shutdown.
	ShutdownDuration string `yaml:"shutdown_duration"`

	// ProbeWaitTime represent the parse duration between health check server and tenant sidecar server shutdown.
	ProbeWaitTime string `yaml:"probe_wait_time"`

	// TLS represent the TLS configuration for tenant sidecar server.
	TLS TLS `yaml:"tls"`
}

// TLS represent the TLS configuration for tenant sidecar server.
type TLS struct {
	// Enable represent the tenant sidecar server enable TLS or not.
	Enabled bool `yaml:"enabled"`

	// CertKey represent the certificate environment variable key used to start tenant sidecar server.
	CertKey string `yaml:"cert_key"`

	// KeyKey represent the private key environment variable key used to start tenant sidecar server.
	KeyKey string `yaml:"key_key"`

	// CAKey represent the CA certificate environment variable key used to start tenant sidecar server.
	CAKey string `yaml:"ca_key"`
}

// Proxy represent the reverse proxy configuration to connect to Athenz server
type Proxy struct {
	// AuthHeader represent the HTTP header key name of the authenication token for N-Token proxy request
	AuthHeader string `yaml:"auth_header_key"`

	// RoleHeader represent the HTTP header key name of the role token for Role token proxy request
	RoleHeader string `yaml:"role_header_key"`

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
	// AuthHeader is the HTTP header name for holding the n-token.
	AuthHeader string `yaml:"auth_header_key"`

	// AthenzURL represent the athenz URL to get the role token
	AthenzURL string `yaml:"athenz_url"`

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

// GetVersion returns the current version of the tenant sidecar version.
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
