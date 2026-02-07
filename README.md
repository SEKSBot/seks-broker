# SEKS Broker

Cloud-native secret management for AI agents.

**Bring Your Own Keys. Everything Just Works.**

## What is this?

SEKS Broker is a REST service that manages API credentials for AI agents. Agents authenticate with a token, and the broker handles secret storage, encryption, and API proxying.

- **Multi-tenant:** Each client has isolated secrets and agents
- **Encrypted:** All secrets encrypted at rest (AES-GCM)
- **Audited:** Every access logged
- **Passthrough Proxy:** Use real SDKs with fake tokens

## Quick Start

1. Visit https://seks-broker.stcredzero.workers.dev
2. Create an account (email + password)
3. Add your API keys (Secrets page)
4. Create an agent (Agents page)
5. Generate proxy tokens for each provider

## Passthrough Proxy

The broker proxies API requests with credential injection. Your agent uses a fake token, the broker substitutes the real one.

### Supported Providers

| Provider | Proxy URL | Required Secret |
|----------|-----------|-----------------|
| OpenAI | `/api/openai/*` | `OPENAI_API_KEY` |
| Anthropic | `/api/anthropic/*` | `ANTHROPIC_API_KEY` |
| GitHub | `/api/github/*` | `GITHUB_PERSONAL_ACCESS_TOKEN` |
| Notion | `/api/notion/*` | `NOTION_API_KEY` |
| Gemini | `/api/gemini/*` | `GEMINI_API_KEY` |
| Cloudflare | `/api/cloudflare/*` | `CLOUDFLARE_API_TOKEN` |
| Brave Search | `/api/brave/*` | `BRAVE_BASE_AI_TOKEN` |
| AWS S3 | `/api/aws/s3/<region>/<bucket>/<key>` | `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` |

### Usage Examples

#### OpenAI (Python SDK)

```python
from openai import OpenAI

client = OpenAI(
    api_key="seks_openai_abc123...",  # Proxy token from broker UI
    base_url="https://seks-broker.stcredzero.workers.dev/api/openai"
)

response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Hello!"}]
)
```

#### Anthropic (Python SDK)

```python
from anthropic import Anthropic

client = Anthropic(
    api_key="seks_anthropic_xyz789...",
    base_url="https://seks-broker.stcredzero.workers.dev/api/anthropic"
)

message = client.messages.create(
    model="claude-3-opus-20240229",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Hello!"}]
)
```

#### GitHub (curl)

```bash
curl https://seks-broker.stcredzero.workers.dev/api/github/user \
  -H "Authorization: Bearer seks_github_..."
```

#### AWS S3 (curl)

```bash
# GET object
curl https://seks-broker.stcredzero.workers.dev/api/aws/s3/us-west-2/my-bucket/path/to/file.txt \
  -H "Authorization: Bearer seks_aws_..."

# PUT object
curl -X PUT https://seks-broker.stcredzero.workers.dev/api/aws/s3/us-west-2/my-bucket/new-file.txt \
  -H "Authorization: Bearer seks_aws_..." \
  -H "Content-Type: text/plain" \
  -d "Hello, S3!"

# DELETE object
curl -X DELETE https://seks-broker.stcredzero.workers.dev/api/aws/s3/us-west-2/my-bucket/old-file.txt \
  -H "Authorization: Bearer seks_aws_..."
```

#### Brave Search (curl)

```bash
curl "https://seks-broker.stcredzero.workers.dev/api/brave/res/v1/web/search?q=hello+world" \
  -H "Authorization: Bearer seks_brave_..."
```

## Direct API Access

For tools that need direct secret access (not recommended):

```bash
# List available secrets
curl -X POST https://seks-broker.stcredzero.workers.dev/v1/secrets/list \
  -H "Authorization: Bearer seks_agent_..." \
  -H "Content-Type: application/json"

# Get a secret value
curl -X POST https://seks-broker.stcredzero.workers.dev/v1/secrets/get \
  -H "Authorization: Bearer seks_agent_..." \
  -H "Content-Type: application/json" \
  -d '{"name": "OPENAI_API_KEY"}'
```

## Security Model

1. **Secrets encrypted at rest** — AES-GCM with a master key
2. **Fake tokens** — Agents use randomly generated tokens, not real API keys
3. **Per-provider isolation** — Each provider gets its own token
4. **Audit logging** — All access logged with timestamps
5. **Token renewal** — Regenerate tokens anytime, old ones stop working

## Deployment

### Cloudflare Workers (production)

```bash
npm install
wrangler d1 create seks-broker-db
# Update wrangler.toml with database_id
npm run db:migrate:prod
wrangler secret put MASTER_KEY  # 64-char hex string
npm run deploy
```

### Local Development

```bash
npm install
npm run db:migrate
npm run dev  # http://localhost:8787
```

## License

MIT
