package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	ServerAddr string
	TLSCert    string
	TLSKey     string

	// JWT
	AccessTokenSecret  string
	RefreshTokenSecret string
	AccessTokenTTL     time.Duration
	RefreshTokenTTL    time.Duration
	StepUpTokenTTL     time.Duration

	// Biometric
	ChallengeSecret  string
	ChallengeTTL     time.Duration
	MaxDevicesPerUser int
	SignatureAlgo    string // ES256 or RS256

	// Security
	MaxLoginAttempts   int
	LockoutDuration    time.Duration
	ReplayWindowSize   time.Duration
	MaxTokensPerDevice int

	// PBKDF2 / Argon2
	HashMemory      uint32
	HashIterations  uint32
	HashParallelism uint8
	HashKeyLength   uint32

	Environment string
}

func Load() *Config {
	return &Config{
		ServerAddr: getEnv("SERVER_ADDR", ":8443"),
		TLSCert:    getEnv("TLS_CERT", "certs/server.crt"),
		TLSKey:     getEnv("TLS_KEY", "certs/server.key"),

		AccessTokenSecret:  requireEnv("ACCESS_TOKEN_SECRET"),
		RefreshTokenSecret: requireEnv("REFRESH_TOKEN_SECRET"),
		AccessTokenTTL:     getDuration("ACCESS_TOKEN_TTL", 15*time.Minute),
		RefreshTokenTTL:    getDuration("REFRESH_TOKEN_TTL", 30*24*time.Hour),
		StepUpTokenTTL:     getDuration("STEP_UP_TOKEN_TTL", 5*time.Minute),

		ChallengeSecret:   requireEnv("CHALLENGE_SECRET"),
		ChallengeTTL:      getDuration("CHALLENGE_TTL", 2*time.Minute),
		MaxDevicesPerUser: getInt("MAX_DEVICES_PER_USER", 5),
		SignatureAlgo:     getEnv("SIGNATURE_ALGO", "ES256"),

		MaxLoginAttempts:   getInt("MAX_LOGIN_ATTEMPTS", 5),
		LockoutDuration:    getDuration("LOCKOUT_DURATION", 15*time.Minute),
		ReplayWindowSize:   getDuration("REPLAY_WINDOW", 5*time.Minute),
		MaxTokensPerDevice: getInt("MAX_TOKENS_PER_DEVICE", 3),

		// Argon2id params (OWASP recommended)
		HashMemory:      64 * 1024, // 64MB
		HashIterations:  3,
		HashParallelism: 2,
		HashKeyLength:   32,

		Environment: getEnv("ENV", "production"),
	}
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func requireEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		panic("required env var missing: " + key)
	}
	return v
}

func getDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func getInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return def
}
