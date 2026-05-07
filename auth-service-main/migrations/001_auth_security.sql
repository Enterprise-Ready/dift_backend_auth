-- auth-service operational tables (security + audit + idempotency)
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS auth_refresh_token_blacklist (
  token_jti UUID PRIMARY KEY,
  user_id UUID NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  reason TEXT NOT NULL DEFAULT 'logout'
);
CREATE INDEX IF NOT EXISTS idx_auth_refresh_blacklist_user_id ON auth_refresh_token_blacklist(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_refresh_blacklist_expires_at ON auth_refresh_token_blacklist(expires_at);

CREATE TABLE IF NOT EXISTS auth_idempotency_keys (
  id BIGSERIAL PRIMARY KEY,
  service_name TEXT NOT NULL DEFAULT 'auth-service',
  idempotency_key TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  response_code INT,
  response_body JSONB,
  status TEXT NOT NULL DEFAULT 'processing' CHECK (status IN ('processing','completed','failed')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_auth_idem_key ON auth_idempotency_keys(service_name, idempotency_key);
CREATE INDEX IF NOT EXISTS idx_auth_idem_expires_at ON auth_idempotency_keys(expires_at);

CREATE TABLE IF NOT EXISTS auth_audit_events (
  id BIGSERIAL PRIMARY KEY,
  request_id TEXT,
  actor_user_id UUID,
  action TEXT NOT NULL,
  resource_type TEXT,
  resource_id TEXT,
  client_ip INET,
  user_agent TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_auth_audit_actor ON auth_audit_events(actor_user_id);
CREATE INDEX IF NOT EXISTS idx_auth_audit_action_created ON auth_audit_events(action, created_at DESC);

CREATE OR REPLACE FUNCTION auth_set_updated_at() RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_auth_idempotency_updated_at ON auth_idempotency_keys;
CREATE TRIGGER trg_auth_idempotency_updated_at
BEFORE UPDATE ON auth_idempotency_keys
FOR EACH ROW EXECUTE FUNCTION auth_set_updated_at();
