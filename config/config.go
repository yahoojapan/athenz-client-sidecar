package config

import (
	"os"
	"strings"

	"gopkg.in/yaml.v2"
)

type Config struct {
	Version string `yaml:"version"`
	Server  Server `yaml:"server"`
	Token   Token  `yaml:"token"`
	UDB     UDB    `yaml:"udb"`
	HCC     HCC    `yaml:"hcc"`
}

type Server struct {
	Port             int    `yaml:"port"`
	HealthzPort      int    `yaml:"health_check_port"`
	HealthzPath      string `yaml:"health_check_path"`
	Timeout          string `yaml:"timeout"`
	ShutdownDuration string `yaml:"shutdown_duration"`
	TLS              TLS    `yaml:"tls"`
}

type TLS struct {
	Enabled bool   `yaml:"enabled"`
	Cert    string `yaml:"cert"`
	Key     string `yaml:"key"`
	CA      string `yaml:"ca"`
}

type UDB struct {
	URL string `yaml:"url"`
	// Scheme  string   `yaml:"scheme"`
	// Host    string   `yaml:"host"`
	// Port    int      `yaml:"port"`
	// Version string   `yaml:"version"`
	Keys []string `yaml:"keys"`
}

type HCC struct {
	Hostname string `yaml:"hostname"`
	IP       string `yaml:"ip"`
}

type Token struct {
	AthenzDomain      string `yaml:"athenz_domain"`
	ServiceName       string `yaml:"service_name"`
	NTokenPath        string `yaml:"ntoken_path"`
	PrivateKeyEnvName string `yaml:"private_key_env_name"`
	ValidateToken     bool   `yaml:"validate_token"`
	RefreshDuration   string `yaml:"refresh_duration"`
	KeyVersion        string `yaml:"key_version"`
	Expiration        string `yaml:"expiration"`
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
