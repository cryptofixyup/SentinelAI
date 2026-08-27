CREATE TABLE IF NOT EXISTS reputation_entries (
    chain_id BIGINT NOT NULL,
    address TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('trusted', 'unknown', 'malicious')),
    confidence TEXT NOT NULL CHECK (confidence IN ('low', 'medium', 'high')),
    source TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (chain_id, address)
);

CREATE TABLE IF NOT EXISTS decision_events (
    id UUID PRIMARY KEY,
    request_id UUID NOT NULL,
    chain_id BIGINT NOT NULL,
    from_address TEXT NOT NULL,
    to_address TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('allow', 'warn', 'block')),
    risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    category TEXT NOT NULL,
    confidence TEXT NOT NULL CHECK (confidence IN ('low', 'medium', 'high')),
    reasons JSONB NOT NULL,
    latency_ms INTEGER NOT NULL CHECK (latency_ms >= 0),
    runtime_mode TEXT NOT NULL CHECK (runtime_mode IN ('shadow', 'enforce')),
    policy_version TEXT NOT NULL,
    user_action TEXT CHECK (user_action IS NULL OR user_action IN ('accepted', 'cancelled', 'overridden')),
    wallet_outcome TEXT CHECK (wallet_outcome IS NULL OR wallet_outcome IN ('blocked', 'submitted', 'rejected', 'failed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS decision_events_created_idx ON decision_events (created_at);
CREATE INDEX IF NOT EXISTS decision_events_decision_idx ON decision_events (decision);
CREATE INDEX IF NOT EXISTS decision_events_request_idx ON decision_events (request_id);
