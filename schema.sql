-- SEKS Broker Database Schema

-- Clients (human users who own API keys)
CREATE TABLE IF NOT EXISTS clients (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Agents (AI agents that access secrets)
CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    token TEXT UNIQUE NOT NULL,
    scopes TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen_at TEXT
);

-- Secrets (encrypted API keys and credentials)
CREATE TABLE IF NOT EXISTS secrets (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    provider TEXT NOT NULL,
    encrypted_value TEXT NOT NULL,
    metadata TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(client_id, name)
);

-- Audit log
CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    agent_id TEXT,
    action TEXT NOT NULL,
    resource TEXT,
    status TEXT NOT NULL,
    ip_address TEXT,
    details TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Sessions (web UI authentication)
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Fake tokens (proxy passthrough tokens)
CREATE TABLE IF NOT EXISTS fake_tokens (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    token TEXT UNIQUE NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_used_at TEXT,
    UNIQUE(agent_id, provider)
);

-- Secret access (junction table for per-agent secrets)
-- If a secret has NO entries here, it's global (all agents can access)
-- If it has entries, only those agents can access it
CREATE TABLE IF NOT EXISTS secret_access (
    secret_id TEXT NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (secret_id, agent_id)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_secret_access_secret ON secret_access(secret_id);
CREATE INDEX IF NOT EXISTS idx_secret_access_agent ON secret_access(agent_id);
CREATE INDEX IF NOT EXISTS idx_agents_client ON agents(client_id);
CREATE INDEX IF NOT EXISTS idx_agents_token ON agents(token);
CREATE INDEX IF NOT EXISTS idx_secrets_client ON secrets(client_id);
CREATE INDEX IF NOT EXISTS idx_audit_client ON audit_log(client_id);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_sessions_client ON sessions(client_id);
CREATE INDEX IF NOT EXISTS idx_fake_tokens_token ON fake_tokens(token);
CREATE INDEX IF NOT EXISTS idx_fake_tokens_agent ON fake_tokens(agent_id);
