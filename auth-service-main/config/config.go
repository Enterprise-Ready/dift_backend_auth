package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v2"
)

type AuthConfig struct {
	JWTSecret           string `yaml:"jwt_secret"`
	RefreshJWTSecret    string `yaml:"refresh_jwt_secret"`
	AccessTokenExpires  string `yaml:"access_token_expires"`
	RefreshTokenExpires string `yaml:"refresh_token_expires"`
}

type ServicesConfig struct {
	IdentityURL      string `yaml:"identity_url"`
	IdentityGRPCAddr string `yaml:"identity_grpc_addr"`
	RedisAddr        string `yaml:"redis_addr"`
}

type CORSConfig struct {
	AllowOrigins []string `yaml:"allow_origins"`
	AllowHeaders []string `yaml:"allow_headers"`
	AllowMethods []string `yaml:"allow_methods"`
}

type ServerConfig struct {
	Port            int        `yaml:"port"`
	ReadTimeoutSec  int        `yaml:"read_timeout_seconds"`
	WriteTimeoutSec int        `yaml:"write_timeout_seconds"`
	IdleTimeoutSec  int        `yaml:"idle_timeout_seconds"`
	ShutdownSec     int        `yaml:"shutdown_timeout_seconds"`
	CORS            CORSConfig `yaml:"cors"`
}

type AppConfig struct {
	Server   ServerConfig   `yaml:"server"`
	Auth     AuthConfig     `yaml:"auth"`
	Services ServicesConfig `yaml:"services"`
}

func Load(path string) (*AppConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg AppConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	cfg.applyEnvOverrides()
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *AppConfig) applyDefaults() {
	if c.Server.Port == 0 {
		c.Server.Port = 3010
	}
	if c.Server.ReadTimeoutSec <= 0 {
		c.Server.ReadTimeoutSec = 10
	}
	if c.Server.WriteTimeoutSec <= 0 {
		c.Server.WriteTimeoutSec = 10
	}
	if c.Server.IdleTimeoutSec <= 0 {
		c.Server.IdleTimeoutSec = 60
	}
	if c.Server.ShutdownSec <= 0 {
		c.Server.ShutdownSec = 10
	}
	if c.Services.IdentityGRPCAddr == "" {
		c.Services.IdentityGRPCAddr = "localhost:9091"
	}
	if len(c.Server.CORS.AllowOrigins) == 0 {
		c.Server.CORS.AllowOrigins = []string{"http://localhost:3000", "http://localhost:5173"}
	}
	if len(c.Server.CORS.AllowHeaders) == 0 {
		c.Server.CORS.AllowHeaders = []string{"Origin", "Content-Type", "Authorization", "X-Request-ID"}
	}
	if len(c.Server.CORS.AllowMethods) == 0 {
		c.Server.CORS.AllowMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	}
}

func (c *AppConfig) applyEnvOverrides() {
	overrideInt(&c.Server.Port, "SERVER_PORT")
	overrideInt(&c.Server.ReadTimeoutSec, "SERVER_READ_TIMEOUT_SECONDS")
	overrideInt(&c.Server.WriteTimeoutSec, "SERVER_WRITE_TIMEOUT_SECONDS")
	overrideInt(&c.Server.IdleTimeoutSec, "SERVER_IDLE_TIMEOUT_SECONDS")
	overrideInt(&c.Server.ShutdownSec, "SERVER_SHUTDOWN_TIMEOUT_SECONDS")
	overrideString(&c.Auth.JWTSecret, "AUTH_JWT_SECRET")
	overrideString(&c.Auth.RefreshJWTSecret, "AUTH_REFRESH_JWT_SECRET")
	overrideString(&c.Auth.AccessTokenExpires, "AUTH_ACCESS_TOKEN_EXPIRES")
	overrideString(&c.Auth.RefreshTokenExpires, "AUTH_REFRESH_TOKEN_EXPIRES")
	overrideString(&c.Services.IdentityURL, "IDENTITY_URL")
	overrideString(&c.Services.IdentityGRPCAddr, "IDENTITY_GRPC_ADDR")
	overrideString(&c.Services.RedisAddr, "REDIS_ADDR")
}

func (c *AppConfig) validate() error {
	if c.Auth.JWTSecret == "" || c.Auth.RefreshJWTSecret == "" {
		return fmt.Errorf("auth secrets are required")
	}
	if c.Services.IdentityGRPCAddr == "" {
		return fmt.Errorf("services.identity_grpc_addr is required")
	}
	if c.Server.Port <= 0 {
		return fmt.Errorf("server.port must be greater than zero")
	}
	return nil
}

func overrideString(dest *string, key string) {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		*dest = v
	}
}

func overrideInt(dest *int, key string) {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			*dest = n
		}
	}
}
