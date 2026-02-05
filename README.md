# SEKS Broker

Cloud-native secret management for AI agents.

**Bring Your Own Keys. Everything Just Works.**

## What is this?

SEKS Broker is a REST service that manages API credentials for AI agents. Agents authenticate with a token, and the broker handles secret storage, encryption, and API proxying.

- **Multi-tenant:** Each client has isolated secrets and agents
- **Encrypted:** All secrets encrypted at rest (AES-GCM)
- **Audited:** Every access logged
- **Web UI:** Human-friendly admin interface

## Deployment

### Cloudflare Workers (recommended)

```bash
# Install dependencies
npm install

# Create the D1 database
wrangler d1 create seks-broker-db

# Update wrangler.toml with the database_id from above

# Run migrations
npm run db:migrate:prod

# Set the master encryption key
wrangler secret put MASTER_KEY
# Paste a 64-character hex string (32 bytes)

# Deploy
npm run deploy
```

### Local Development

```bash
npm install
npm run db:migrate
npm run dev
```

## API

### Authentication

All API endpoints require a bearer token:

```
Authorization: Bearer seks_agent_...
```

### Endpoints

#### `GET /v1/health`

Health check.

#### `POST /v1/secrets/get`

Fetch a secret value.

```json
{ "name": "OPENAI_API_KEY" }
```

#### `POST /v1/secrets/list`

List available secrets (names only).

#### `POST /v1/proxy/request`

Proxy a request with credential injection.

```json
{
  "service": "openai",
  "method": "POST",
  "path": "/v1/chat/completions",
  "body": { ... }
}
```

Supported services: `openai`, `anthropic`, `claude`

## Web UI

Visit the root URL to access the admin interface:

- **Dashboard:** Overview and quick start
- **Secrets:** Add/remove API keys
- **Agents:** Create/manage agent tokens
- **Activity:** View audit log

## Security

- Secrets encrypted with AES-GCM using a master key
- Master key should be stored in Cloudflare Secrets (or KMS in production)
- Passwords hashed with PBKDF2 (100k iterations)
- Sessions expire after 24 hours

## License

MIT
