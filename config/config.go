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

	// UDB represent the configuration of user database server.
	UDB UDB `yaml:"udb"`

	// HC represent the configuration of generate host certificate(YCA) from athenz server.
	HC HC `yaml:"hc"`

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

type Proxy struct {
	AuthHeader string `yaml:"auth_header_key"`
	RoleHeader string `yaml:"role_header_key"`
	BufferSize int64  `yaml:"buffer_size"`
}

type UDB struct {
	URL string `yaml:"url"`
}

type HC struct {
	AthenzURL        string `yaml:"athenz_url"`
	Hostname         string `yaml:"hostname"`
	IP               string `yaml:"ip"`
	CertExpire       string `yaml:"cert_expire"`
	CertExpireMargin string `yaml:"cert_expire_margin"`
}

type Token struct {
	AthenzDomain    string `yaml:"athenz_domain"`
	ServiceName     string `yaml:"service_name"`
	NTokenPath      string `yaml:"ntoken_path"`
	PrivateKeyPath  string `yaml:"private_key_path"`
	ValidateToken   bool   `yaml:"validate_token"`
	RefreshDuration string `yaml:"refresh_duration"`
	KeyVersion      string `yaml:"key_version"`
	Expiration      string `yaml:"expiration"`
}

type Role struct {
	AthenzURL      string `yaml:"athenz_url"`
	ProxyPrincipal string `yaml:"proxy_principal"`
	TokenExpiry    string `yaml:"expiration"`
}

const (
	currentVersion = "v1.0.0"
)

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

func GetVersion() string {
	return currentVersion
}

func GetValue(cfg string) string {
	if checkPrefixAndSuffix(cfg, "_", "_") {
		return os.Getenv(strings.TrimPrefix(strings.TrimSuffix(cfg, "_"), "_"))
	}
	return cfg
}

func checkPrefixAndSuffix(str, pref, suf string) bool {
	return strings.HasPrefix(str, pref) && strings.HasSuffix(str, suf)
}
