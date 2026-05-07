# 🔐 Enterprise Auth Engine

> Go-based enterprise authentication & authorization engine with face recognition, TOTP MFA, OAuth 2.0, multi-provider OTP, and full audit logging.

---

## 📦 Features

| Feature | Details |
|---------|---------|
| **Registration** | Email, Phone, Password |
| **Login** | Password, OTP (email/SMS), Face, OAuth |
| **OAuth** | Google Sign-In, Apple ID (extensible) |
| **MFA / 2FA** | TOTP (Google Authenticator), Backup Codes |
| **OTP** | Email + SMS via SendGrid, AWS SES, SMTP, Mailgun, Twilio, AWS SNS, Vonage |
| **Face Auth** | Enrollment + Liveness check + Similarity matching |
| **JWT** | HS512 Access + Refresh tokens with rotation |
| **API Keys** | Scoped API keys with rate limits & expiry |
| **Sessions** | Multi-device, max-device enforcement |
| **Security** | Bcrypt, AES-GCM encryption, rate limiting (sliding window + token bucket) |
| **Audit** | Full audit log with risk scoring + webhook alerts |
| **Admin** | User management, session control, audit history |
| **External** | Firebase Auth, Supabase Auth (pluggable) |
| **Workers** | Background cleanup jobs |

---

## 🗂️ Project Structure

```
auth-engine/
├── cmd/
│   └── server/main.go          # Entry point + DI wiring
├── configs/
│   └── config.yaml             # All configuration
├── deployments/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── migrations.sql
├── internal/
│   ├── admin/                  # Admin HTTP handlers
│   ├── apikey/                 # API key service + middleware
│   ├── audit/                  # Audit log + risk engine
│   ├── auth/                   # Core auth service + HTTP handlers
│   ├── config/                 # Config loader
│   ├── crypto/                 # Password hashing, AES-GCM, key gen
│   ├── face/                   # Face enrollment + verification
│   ├── middleware/             # JWT, rate limit, security headers
│   ├── models/                 # All data models + DTOs
│   ├── oauth/                  # Google + Apple OAuth providers
│   ├── otp/                    # OTP service (email/SMS/TOTP)
│   ├── providers/              # Email (SG/SES/SMTP/Mailgun) + SMS (Twilio/SNS/Vonage)
│   ├── repository/             # GORM + Redis data stores
│   └── worker/                 # Background scheduler
└── pkg/
    ├── jwt/                    # JWT manager
    ├── ratelimit/              # Token bucket + sliding window
    └── validator/              # Password policy engine
```

---

## 🚀 Quick Start

### 1. Clone & Configure

```bash
cp configs/config.yaml configs/config.local.yaml
# Edit config.local.yaml with your credentials
```

### 2. Docker Compose (Recommended)

```bash
cd deployments
docker-compose up -d postgres redis
# Wait for services to be healthy
docker-compose up auth-engine
```

### 3. Run Locally

```bash
# Prerequisites: Go 1.22+, PostgreSQL, Redis
go mod tidy
go run ./cmd/server
```

---

## 📡 API Reference

### Auth Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/auth/register` | Register with email/phone + password |
| `POST` | `/api/v1/auth/login` | Login with password (+ optional MFA) |
| `POST` | `/api/v1/auth/login/oauth` | OAuth login (Google / Apple) |
| `POST` | `/api/v1/auth/login/face` | Face recognition login |
| `POST` | `/api/v1/auth/token/refresh` | Refresh access token |
| `POST` | `/api/v1/auth/logout` | Revoke current session |
| `POST` | `/api/v1/auth/logout/all` | Revoke all sessions |
| `GET`  | `/api/v1/auth/me` | Get current user |
| `POST` | `/api/v1/auth/otp/send` | Send OTP (email or SMS) |
| `POST` | `/api/v1/auth/otp/verify` | Verify OTP code |
| `POST` | `/api/v1/auth/password/forgot` | Request password reset |
| `POST` | `/api/v1/auth/password/reset` | Reset password with OTP code |
| `POST` | `/api/v1/auth/mfa/enable` | Start MFA setup (returns QR) |
| `POST` | `/api/v1/auth/mfa/confirm` | Confirm MFA setup |
| `DELETE` | `/api/v1/auth/mfa` | Disable MFA |
| `POST` | `/api/v1/auth/face/enroll` | Enroll face |

### API Keys

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/api-keys` | Create API key |
| `GET` | `/api/v1/api-keys` | List API keys |
| `DELETE` | `/api/v1/api-keys/:id` | Revoke API key |

### Admin (requires `admin` role)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/admin/users` | List all users |
| `GET` | `/api/v1/admin/users/:id` | Get user |
| `PATCH` | `/api/v1/admin/users/:id/status` | Update status |
| `POST` | `/api/v1/admin/users/:id/lock` | Lock account |
| `POST` | `/api/v1/admin/users/:id/unlock` | Unlock account |
| `DELETE` | `/api/v1/admin/users/:id` | Soft delete user |
| `GET` | `/api/v1/admin/users/:id/sessions` | List sessions |
| `DELETE` | `/api/v1/admin/users/:id/sessions` | Revoke all sessions |
| `GET` | `/api/v1/admin/users/:id/audit` | Audit log by user |
| `GET` | `/api/v1/admin/stats` | System stats |

---

## 🔒 Security Architecture

```
Request
  │
  ├─ SecurityHeaders (HSTS, CSP, X-Frame-Options)
  ├─ RequestID
  ├─ RateLimit (Sliding Window / Token Bucket via Redis)
  ├─ IPWhitelist (admin routes)
  ├─ JWTAuth (HS512, 15min access / 7d refresh)
  ├─ RequireMFA (optional per-route)
  ├─ RequireRole (RBAC)
  └─ RiskScorer (IP, UA, time, frequency analysis)
```

### Password Security
- bcrypt cost 12 (configurable up to 14)
- Policy: min length, upper/lower/digit/special, no common passwords, no sequential patterns
- Password breach check (configurable via HaveIBeenPwned API)

### Token Security
- Access tokens: 15 minutes (HS512)
- Refresh tokens: 7 days, stored in DB, rotated on use
- MFA backup codes: one-time use, SHA-256 hashed
- MFA secrets: AES-256-GCM encrypted at rest

### Face Security
- Liveness detection (anti-spoofing)
- 128-dimension face descriptor
- Configurable tolerance (default 0.4)
- Enrollment requires minimum confidence threshold

---

## ⚙️ Configuration Reference

See `configs/config.yaml` for full reference.

### Key Environment Variables

```bash
JWT_ACCESS_SECRET=<32+ char secret>
JWT_REFRESH_SECRET=<32+ char secret>
DATABASE_DSN=host=localhost user=auth password=secret dbname=auth_engine port=5432 sslmode=disable
REDIS_ADDR=localhost:6379
```

---

## 🔌 Provider Integration

### Email
| Provider | Config Key | Notes |
|----------|-----------|-------|
| SendGrid | `sendgrid_api_key` | Recommended for production |
| AWS SES  | `aws_access_key` + `aws_secret_key` | Best for AWS stacks |
| SMTP     | `smtp_host` + credentials | Gmail, custom SMTP |
| Mailgun  | `mailgun_api_key` + `mailgun_domain` | |

### SMS
| Provider | Config Key | Notes |
|----------|-----------|-------|
| Twilio   | `twilio_sid` + `twilio_auth_token` | Most reliable globally |
| AWS SNS  | `aws_sns_access_key` + `aws_sns_secret_key` | |
| Vonage   | `vonage_api_key` + `vonage_api_secret` | |

### OAuth
| Provider | Requirements |
|----------|-------------|
| Google   | OAuth 2.0 client ID + secret |
| Apple    | Team ID + Key ID + P8 private key |

### External Auth
| Service | Config | Notes |
|---------|--------|-------|
| Firebase | `service_account` JSON path | Token verification + user sync |
| Supabase | `url` + `service_key` | JWT verification + user sync |

---

## 🧩 Extending

### Add a new OAuth provider
1. Implement `oauth.Provider` interface in `internal/oauth/`
2. Register in `oauth.NewRegistry()`

### Add a new Email provider
1. Implement `providers.EmailProvider` interface
2. Add case in `providers.NewEmailProvider()`

### Add a new SMS provider
1. Implement `providers.SMSProvider` interface
2. Add case in `providers.NewSMSProvider()`

---

## 📊 Database Schema

See `deployments/migrations.sql` for complete schema.

Tables:
- `users` — core user record with security fields
- `sessions` — device sessions with refresh tokens
- `otps` — OTP codes (also cached in Redis)
- `oauth_providers` — linked social accounts
- `face_enrollments` — face descriptors (float4[])
- `audit_logs` — full audit trail with risk scores
- `api_keys` — scoped API keys (hash stored, never plaintext)

---

## 🏗️ Production Checklist

- [ ] Change all secrets in `config.yaml`
- [ ] Enable TLS (`tls_enabled: true`)
- [ ] Set `server.mode: release`
- [ ] Configure real email + SMS providers
- [ ] Set `security.mfa_required: true` for high-security environments
- [ ] Configure `audit.webhook_url` for SIEM integration
- [ ] Set `security.ip_whitelist` for admin routes
- [ ] Enable Firebase or Supabase if using those platforms
- [ ] Configure face model path (`face.model_path`)
- [ ] Set backup code encryption key (same as JWT secret)
- [ ] Review rate limits for your traffic patterns
- [ ] Set up log aggregation (Datadog, ELK, CloudWatch)
- [ ] Configure Prometheus metrics endpoint
