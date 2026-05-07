//go:build legacy
// +build legacy

package config

import (
	"time"
	"github.com/spf13/viper"
)

type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	Redis    RedisConfig
	JWT      JWTConfig
	OTP      OTPConfig
	OAuth    OAuthConfig
	Email    EmailConfig
	SMS      SMSConfig
	Face     FaceConfig
	Firebase FirebaseConfig
	Supabase SupabaseConfig
	Security SecurityConfig
	Audit    AuditConfig
}

type ServerConfig struct {
	Host         string        `mapstructure:"host"`
	Port         int           `mapstructure:"port"`
	Mode         string        `mapstructure:"mode"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
	TLSEnabled   bool          `mapstructure:"tls_enabled"`
	TLSCert      string        `mapstructure:"tls_cert"`
	TLSKey       string        `mapstructure:"tls_key"`
}

type DatabaseConfig struct {
	Driver          string        `mapstructure:"driver"`
	DSN             string        `mapstructure:"dsn"`
	MaxOpenConns    int           `mapstructure:"max_open_conns"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
}

type RedisConfig struct {
	Addr         string        `mapstructure:"addr"`
	Password     string        `mapstructure:"password"`
	DB           int           `mapstructure:"db"`
	PoolSize     int           `mapstructure:"pool_size"`
	MaxRetries   int           `mapstructure:"max_retries"`
	DialTimeout  time.Duration `mapstructure:"dial_timeout"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
}

type JWTConfig struct {
	AccessSecret      string        `mapstructure:"access_secret"`
	RefreshSecret     string        `mapstructure:"refresh_secret"`
	AccessExpiry      time.Duration `mapstructure:"access_expiry"`
	RefreshExpiry     time.Duration `mapstructure:"refresh_expiry"`
	Issuer            string        `mapstructure:"issuer"`
	Algorithm         string        `mapstructure:"algorithm"`
	RotationEnabled   bool          `mapstructure:"rotation_enabled"`
	RotationInterval  time.Duration `mapstructure:"rotation_interval"`
}

type OTPConfig struct {
	Length          int           `mapstructure:"length"`
	Expiry          time.Duration `mapstructure:"expiry"`
	MaxAttempts     int           `mapstructure:"max_attempts"`
	CooldownPeriod  time.Duration `mapstructure:"cooldown_period"`
	TOTPEnabled     bool          `mapstructure:"totp_enabled"`
	TOTPIssuer      string        `mapstructure:"totp_issuer"`
}

type OAuthConfig struct {
	Google GoogleOAuthConfig
	Apple  AppleOAuthConfig
}

type GoogleOAuthConfig struct {
	ClientID     string   `mapstructure:"client_id"`
	ClientSecret string   `mapstructure:"client_secret"`
	RedirectURL  string   `mapstructure:"redirect_url"`
	Scopes       []string `mapstructure:"scopes"`
}

type AppleOAuthConfig struct {
	ClientID    string `mapstructure:"client_id"`
	TeamID      string `mapstructure:"team_id"`
	KeyID       string `mapstructure:"key_id"`
	PrivateKey  string `mapstructure:"private_key"`
	RedirectURL string `mapstructure:"redirect_url"`
}

type EmailConfig struct {
	Provider   string `mapstructure:"provider"` // sendgrid, ses, smtp, mailgun
	From       string `mapstructure:"from"`
	FromName   string `mapstructure:"from_name"`
	// SendGrid
	SendGridAPIKey string `mapstructure:"sendgrid_api_key"`
	// AWS SES
	AWSRegion    string `mapstructure:"aws_region"`
	AWSAccessKey string `mapstructure:"aws_access_key"`
	AWSSecretKey string `mapstructure:"aws_secret_key"`
	// SMTP
	SMTPHost     string `mapstructure:"smtp_host"`
	SMTPPort     int    `mapstructure:"smtp_port"`
	SMTPUsername string `mapstructure:"smtp_username"`
	SMTPPassword string `mapstructure:"smtp_password"`
	// Mailgun
	MailgunAPIKey string `mapstructure:"mailgun_api_key"`
	MailgunDomain string `mapstructure:"mailgun_domain"`
}

type SMSConfig struct {
	Provider string `mapstructure:"provider"` // twilio, aws_sns, vonage
	// Twilio
	TwilioSID        string `mapstructure:"twilio_sid"`
	TwilioAuthToken  string `mapstructure:"twilio_auth_token"`
	TwilioFromNumber string `mapstructure:"twilio_from_number"`
	// AWS SNS
	AWSSNSRegion    string `mapstructure:"aws_sns_region"`
	AWSSNSAccessKey string `mapstructure:"aws_sns_access_key"`
	AWSSNSSecretKey string `mapstructure:"aws_sns_secret_key"`
	// Vonage
	VonageAPIKey    string `mapstructure:"vonage_api_key"`
	VonageAPISecret string `mapstructure:"vonage_api_secret"`
}

type FaceConfig struct {
	ModelPath       string  `mapstructure:"model_path"`
	Tolerance       float32 `mapstructure:"tolerance"`
	MinConfidence   float32 `mapstructure:"min_confidence"`
	StoragePath     string  `mapstructure:"storage_path"`
	MaxFaceSize     int     `mapstructure:"max_face_size"`
	LivenessEnabled bool    `mapstructure:"liveness_enabled"`
}

type FirebaseConfig struct {
	Enabled         bool   `mapstructure:"enabled"`
	ServiceAccount  string `mapstructure:"service_account"`
	ProjectID       string `mapstructure:"project_id"`
	StorageBucket   string `mapstructure:"storage_bucket"`
}

type SupabaseConfig struct {
	Enabled    bool   `mapstructure:"enabled"`
	URL        string `mapstructure:"url"`
	AnonKey    string `mapstructure:"anon_key"`
	ServiceKey string `mapstructure:"service_key"`
}

type SecurityConfig struct {
	BcryptCost          int           `mapstructure:"bcrypt_cost"`
	MaxLoginAttempts    int           `mapstructure:"max_login_attempts"`
	LockoutDuration     time.Duration `mapstructure:"lockout_duration"`
	PasswordMinLength   int           `mapstructure:"password_min_length"`
	PasswordRequireUpper bool         `mapstructure:"password_require_upper"`
	PasswordRequireLower bool         `mapstructure:"password_require_lower"`
	PasswordRequireDigit bool         `mapstructure:"password_require_digit"`
	PasswordRequireSpec  bool         `mapstructure:"password_require_special"`
	SessionMaxDevices   int           `mapstructure:"session_max_devices"`
	MFARequired         bool          `mapstructure:"mfa_required"`
	IPWhitelist         []string      `mapstructure:"ip_whitelist"`
	RateLimit           RateLimitConfig
}

type RateLimitConfig struct {
	LoginPerMinute    int `mapstructure:"login_per_minute"`
	OTPPerHour        int `mapstructure:"otp_per_hour"`
	RegisterPerDay    int `mapstructure:"register_per_day"`
	GlobalPerSecond   int `mapstructure:"global_per_second"`
}

type AuditConfig struct {
	Enabled     bool   `mapstructure:"enabled"`
	LogLevel    string `mapstructure:"log_level"`
	RetentionDays int  `mapstructure:"retention_days"`
	WebhookURL  string `mapstructure:"webhook_url"`
}

func Load() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./configs")
	viper.AddConfigPath(".")
	viper.AutomaticEnv()

	// Defaults
	viper.SetDefault("server.host", "0.0.0.0")
	viper.SetDefault("server.port", 8080)
	viper.SetDefault("server.mode", "release")
	viper.SetDefault("jwt.access_expiry", "15m")
	viper.SetDefault("jwt.refresh_expiry", "7d")
	viper.SetDefault("jwt.algorithm", "HS512")
	viper.SetDefault("otp.length", 6)
	viper.SetDefault("otp.expiry", "5m")
	viper.SetDefault("otp.max_attempts", 5)
	viper.SetDefault("security.bcrypt_cost", 12)
	viper.SetDefault("security.max_login_attempts", 5)
	viper.SetDefault("security.lockout_duration", "15m")
	viper.SetDefault("security.password_min_length", 8)

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
