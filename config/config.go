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
	// currentVersion represents the current configuration version.
	currentVersion = "v2.0.0"
)

// Config represents the configuration (config.yaml) of client sidecar.
type Config struct {
	// Version represents the configuration file version.
	Version string `yaml:"version"`

	// Server represents the client sidecar and the health check server configuration.
	Server Server `yaml:"server"`

	// NToken represents the configuration to generate N-token for connecting to the Athenz server.
	NToken NToken `yaml:"nToken"`

	// AccessToken represents the configuration to retrieve access token from the Athenz server.
	AccessToken AccessToken `yaml:"accessToken"`

	// RoleToken represents the configuration to retrieve role token from the Athenz server.
	RoleToken RoleToken `yaml:"roleToken"`

	// ServiceCert represents the configuration to retrieve short-lived X.509 service certificates from the Athenz server.
	ServiceCert ServiceCert `yaml:"serviceCert"`

	// Proxy represents the configuration of the forward proxy that automatically injects N-token or role token to the requests.
	Proxy Proxy `yaml:"proxy"`

	// Log represents the logger configuration.
	Log Log `yaml:"log"`
}

// Server represents the client sidecar and the health check server configuration.
type Server struct {
	// Port represents the server listening port.
	Port int `yaml:"port"`

	// Timeout represents the maximum request handling duration.
	Timeout string `yaml:"timeout"`

	// ShutdownTimeout represents the duration before force shutdown.
	ShutdownTimeout string `yaml:"shutdownTimeout"`

	// ShutdownDelay represents the delay duration between the health check server shutdown and the client sidecar server shutdown.
	ShutdownDelay string `yaml:"shutdownDelay"`

	// TLS represents the TLS configuration of the client sidecar server.
	TLS TLS `yaml:"tls"`

	// HealthCheck represents the health check server configuration.
	HealthCheck HealthCheck `yaml:"healthCheck"`
}

// TLS represents the TLS configuration of the client sidecar server.
type TLS struct {
	// Enable represents whether to enable TLS.
	Enable bool `yaml:"enable"`

	// CertPath represents the server certificate file path.
	CertPath string `yaml:"certPath"`

	// KeyPath represents the private key file path of the server certificate.
	KeyPath string `yaml:"keyPath"`

	// CAPath represents the CA certificate chain file path for verifying client certificates.
	CAPath string `yaml:"caPath"`
}

// HealthCheck represents the health check server configuration.
type HealthCheck struct {
	// Port represents the server listening port.
	Port int `yaml:"port"`

	// Endpoint represents the health check endpoint (pattern).
	Endpoint string `yaml:"endpoint"`
}

// NToken represents the configuration to generate N-token for connecting to the Athenz server.
type NToken struct {
	// Enable represents whether to enable retrieving endpoint.
	Enable bool `yaml:"enable"`

	// AthenzDomain represents the Athenz domain.
	AthenzDomain string `yaml:"athenzDomain"`

	// ServiceName represents the Athenz service name.
	ServiceName string `yaml:"serviceName"`

	// PrivateKeyPath represents the private key file path for signing the N-token.
	PrivateKeyPath string `yaml:"privateKeyPath"`

	// KeyVersion represents the key version.
	KeyVersion string `yaml:"keyVersion"`

	// Expiry represents the duration before expires.
	Expiry string `yaml:"expiry"`

	// RefreshPeriod represents the duration of the refresh period.
	RefreshPeriod string `yaml:"refreshPeriod"`

	// ExistingTokenPath represents the existing N-token file path. (ONLY for Copper Argos)
	ExistingTokenPath string `yaml:"existingTokenPath"`

	// Validate represents whether to validate the N-token. Set to true when ExistingTokenPath is set.
	Validate bool `yaml:"validate"`
}

// AccessToken represents the configuration to retrieve access token from the Athenz server.
type AccessToken struct {
	// Enable represents whether to enable retrieving endpoint.
	Enable bool `yaml:"enable"`

	// PrincipalAuthHeader represents the HTTP header for injecting N-token.
	PrincipalAuthHeader string `yaml:"principalAuthHeader"`

	// AthenzURL represents the Athenz API URL.
	AthenzURL string `yaml:"athenzURL"`

	// AthenzCAPath represents the Athenz CA certificate chain file path.
	AthenzCAPath string `yaml:"athenzCAPath"`

	// CertPath represents the client certificate file path.
	CertPath string `yaml:"certPath"`

	// CertKeyPath represents the client certificate's private key file path.
	CertKeyPath string `yaml:"certKeyPath"`

	// Expiry represents the duration before expires.
	Expiry string `yaml:"expiry"`

	// RefreshPeriod represents the duration of the refresh period.
	RefreshPeriod string `yaml:"refreshPeriod"`

	// Retry represents the retry configuration.
	Retry Retry `yaml:"retry"`
}

// RoleToken represents the configuration to retrieve role token from the Athenz server.
type RoleToken struct {
	// Enable represents whether to enable retrieving endpoint.
	Enable bool `yaml:"enable"`

	// PrincipalAuthHeader represents the HTTP header for injecting N-token.
	PrincipalAuthHeader string `yaml:"principalAuthHeader"`

	// AthenzURL represents the Athenz API URL.
	AthenzURL string `yaml:"athenzURL"`

	// AthenzCAPath represents the Athenz CA certificate chain file path.
	AthenzCAPath string `yaml:"athenzCAPath"`

	// CertPath represents the client certificate file path.
	CertPath string `yaml:"certPath"`

	// CertKeyPath represents the client certificate's private key file path.
	CertKeyPath string `yaml:"certKeyPath"`

	// Expiry represents the duration before expires.
	Expiry string `yaml:"expiry"`

	// RefreshPeriod represents the duration of the refresh period.
	RefreshPeriod string `yaml:"refreshPeriod"`

	// Retry represents the retry configuration.
	Retry Retry `yaml:"retry"`
}

// ServiceCert represents the configuration to retrieve short-lived X.509 service certificates from the Athenz server.
type ServiceCert struct {
	// Enable represents whether to enable retrieving endpoint.
	Enable bool `yaml:"enable"`

	// PrincipalAuthHeader represents the HTTP header for injecting N-token.
	PrincipalAuthHeader string `yaml:"principalAuthHeader"`

	// AthenzURL represents the Athenz API URL.
	AthenzURL string `yaml:"athenzURL"`

	// AthenzCAPath represents the Athenz CA certificate chain file path.
	AthenzCAPath string `yaml:"athenzCAPath"`

	// Expiry represents the duration before expires.
	Expiry string `yaml:"expiry"`

	// RefreshPeriod represents the duration of the refresh period.
	RefreshPeriod string `yaml:"refreshPeriod"`

	// ExpiryMargin represents the certificate ("Not After" field) expiry margin to force refresh certificates beforehand.
	ExpiryMargin string `yaml:"expiryMargin"`

	// DNSSuffix is the suffix of SAN.
	DNSSuffix string `yaml:"dnsSuffix"`

	// IntermediateCert represents whether to concatenate intermediate cert in the response.
	IntermediateCert bool `yaml:"intermediateCert"`

	// Spiffe represents whether to include spiffe ID in the certificate.
	Spiffe bool `yaml:"spiffe"`

	// Subject represents the certificate subject field.
	Subject Subject `yaml:"subject"`
}

// Subject represents the certificate subject field.
type Subject struct {
	// Country is the Subject C/Country field.
	Country string `yaml:"country"`

	// Province is the Subject ST/StateOrProvince field.
	Province string `yaml:"province"`

	// Organization is the Subject O/Organization field.
	Organization string `yaml:"organization"`

	// OrganizationalUnit is the Subject OU/OrganizationalUnit field.
	OrganizationalUnit string `yaml:"organizationalUnit"`
}

// Proxy represents the configuration of the forward proxy that automatically injects N-token or role token to the requests.
type Proxy struct {
	// Enable represents whether to enable retrieving endpoint.
	Enable bool `yaml:"enable"`

	// PrincipalAuthHeader represents the HTTP header for injecting N-token.
	PrincipalAuthHeader string `yaml:"principalAuthHeader"`

	// RoleAuthHeader represents the HTTP header for injecting role token.
	RoleAuthHeader string `yaml:"roleAuthHeader"`

	// BufferSize represents the forward proxy buffer size.
	BufferSize uint64 `yaml:"bufferSize"`
}

// Log represents the logger configuration.
type Log struct {
	// Level represents the logger output level. Values: "debug", "info", "warn", "error", "fatal".
	Level string `yaml:"level"`

	// Color represents whether to print ANSI escape code.
	Color bool `yaml:"color"`
}

// Retry represents the retry configuration.
type Retry struct {
	// Attempts represents number of attempts to retry.
	Attempts int `yaml:"attempts"`

	// Delay represents the duration between each retry.
	Delay string `yaml:"delay"`
}

// New returns *Config or error when decode the configuration file to actually *Config struct.
func New(path string) (*Config, error) {
	f, err := os.OpenFile(path, os.O_RDONLY, 0600)
	if err != nil {
		return nil, err
	}
	cfg := &Config{
		NToken: NToken{
			Enable: true,
		},
		RoleToken: RoleToken{
			Enable: true,
		},
		Proxy: Proxy{
			Enable: true,
		},
	}
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
