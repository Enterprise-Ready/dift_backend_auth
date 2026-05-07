-- Engine Core unified infra primitives (idempotent)
-- Safe to apply multiple times.

CREATE TABLE IF NOT EXISTS infra_outbox (
  id UUID PRIMARY KEY,
  topic VARCHAR(255) NOT NULL,
  payload JSONB NOT NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'pending',
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  published_at TIMESTAMP NULL
);

CREATE TABLE IF NOT EXISTS infra_inbox (
  id UUID PRIMARY KEY,
  topic VARCHAR(255) NOT NULL,
  payload JSONB NOT NULL,
  received_at TIMESTAMP NOT NULL DEFAULT NOW(),
  processed_at TIMESTAMP NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'received'
);

CREATE TABLE IF NOT EXISTS infra_dlq (
  id UUID PRIMARY KEY,
  topic VARCHAR(255) NOT NULL,
  payload JSONB NOT NULL,
  error_message TEXT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_infra_outbox_status_created_at ON infra_outbox(status, created_at);
CREATE INDEX IF NOT EXISTS idx_infra_inbox_status_received_at ON infra_inbox(status, received_at);
CREATE INDEX IF NOT EXISTS idx_infra_dlq_topic_created_at ON infra_dlq(topic, created_at);
