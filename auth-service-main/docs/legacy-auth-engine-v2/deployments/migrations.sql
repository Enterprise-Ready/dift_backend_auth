-- ============================================================
-- Enterprise Auth Engine - Database Migrations
-- ============================================================

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ─── Users ───────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS users (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email               VARCHAR(255) UNIQUE,
    phone               VARCHAR(32)  UNIQUE,
    password_hash       TEXT,
    display_name        VARCHAR(128) NOT NULL DEFAULT '',
    avatar_url          TEXT,
    status              VARCHAR(32)  NOT NULL DEFAULT 'pending',
    role                VARCHAR(64)  NOT NULL DEFAULT 'user',
    email_verified      BOOLEAN      NOT NULL DEFAULT FALSE,
    phone_verified      BOOLEAN      NOT NULL DEFAULT FALSE,
    face_enrolled       BOOLEAN      NOT NULL DEFAULT FALSE,
    mfa_enabled         BOOLEAN      NOT NULL DEFAULT FALSE,
    mfa_secret          TEXT,
    mfa_backup_codes    TEXT[]       NOT NULL DEFAULT '{}',
    failed_login_count  INT          NOT NULL DEFAULT 0,
    locked_until        TIMESTAMPTZ,
    last_login_at       TIMESTAMPTZ,
    last_login_ip       VARCHAR(64),
    password_changed_at TIMESTAMPTZ,
    metadata            JSONB        NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    deleted_at          TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_users_email       ON users(email) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_users_phone       ON users(phone) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_users_status      ON users(status);
CREATE INDEX IF NOT EXISTS idx_users_created_at  ON users(created_at DESC);

-- ─── Sessions ─────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS sessions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token TEXT        NOT NULL,
    device_info   JSONB       NOT NULL DEFAULT '{}',
    ip_address    VARCHAR(64) NOT NULL DEFAULT '',
    user_agent    TEXT        NOT NULL DEFAULT '',
    is_active     BOOLEAN     NOT NULL DEFAULT TRUE,
    expires_at    TIMESTAMPTZ NOT NULL,
    last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id       ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_refresh_token ON sessions(refresh_token);
CREATE INDEX IF NOT EXISTS idx_sessions_active        ON sessions(user_id, is_active, expires_at);

-- ─── OTP ─────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS otps (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code       VARCHAR(16) NOT NULL,
    purpose    VARCHAR(64) NOT NULL,
    channel    VARCHAR(32) NOT NULL,
    recipient  VARCHAR(255) NOT NULL,
    attempts   INT         NOT NULL DEFAULT 0,
    verified   BOOLEAN     NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_otps_user_purpose ON otps(user_id, purpose, verified, expires_at);
CREATE INDEX IF NOT EXISTS idx_otps_recipient    ON otps(recipient, purpose);

-- ─── OAuth Providers ──────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS oauth_providers (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider      VARCHAR(64) NOT NULL,
    provider_uid  VARCHAR(255) NOT NULL,
    access_token  TEXT        NOT NULL DEFAULT '',
    refresh_token TEXT,
    expires_at    TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(provider, provider_uid)
);

CREATE INDEX IF NOT EXISTS idx_oauth_user_id  ON oauth_providers(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_provider ON oauth_providers(provider, provider_uid);

-- ─── Face Enrollments ─────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS face_enrollments (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    descriptor  FLOAT4[] NOT NULL,
    image_path  TEXT     NOT NULL DEFAULT '',
    confidence  FLOAT4   NOT NULL DEFAULT 0,
    is_active   BOOLEAN  NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_face_user_id ON face_enrollments(user_id, is_active);

-- ─── Audit Logs ───────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS audit_logs (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID,
    action     VARCHAR(128) NOT NULL,
    resource   VARCHAR(128) NOT NULL DEFAULT '',
    ip_address VARCHAR(64)  NOT NULL DEFAULT '',
    user_agent TEXT         NOT NULL DEFAULT '',
    status     VARCHAR(32)  NOT NULL DEFAULT 'success',
    details    JSONB        NOT NULL DEFAULT '{}',
    risk_score FLOAT4       NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_user_id   ON audit_logs(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action    ON audit_logs(action, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_created   ON audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_risk      ON audit_logs(risk_score DESC) WHERE risk_score >= 0.5;

-- ─── API Keys ─────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS api_keys (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        VARCHAR(128) NOT NULL,
    key_hash    VARCHAR(256) NOT NULL UNIQUE,
    prefix      VARCHAR(32)  NOT NULL,
    permissions TEXT[]       NOT NULL DEFAULT '{}',
    scopes      TEXT[]       NOT NULL DEFAULT '{}',
    rate_limit  INT          NOT NULL DEFAULT 1000,
    expires_at  TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    is_active   BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_api_keys_user_id  ON api_keys(user_id, is_active);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash     ON api_keys(key_hash);

-- ─── Auto-update updated_at ───────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ─── Cleanup Indexes (Partial) ────────────────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_sessions_cleanup ON sessions(expires_at) WHERE is_active = false;
CREATE INDEX IF NOT EXISTS idx_otps_cleanup     ON otps(expires_at) WHERE verified = false;
