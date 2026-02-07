#!/bin/bash
# Import Doppler secrets into SEKS Broker
#
# Usage: ./scripts/import-doppler.sh <MASTER_KEY>
#
# The MASTER_KEY is the same one you set with `wrangler secret put MASTER_KEY`

set -e

MASTER_KEY="${1:-}"
BROKER_URL="${2:-https://seks-broker.stcredzero.workers.dev}"
EMAIL="${3:-peter@stcredzero.com}"

if [ -z "$MASTER_KEY" ]; then
  echo "Usage: $0 <MASTER_KEY> [BROKER_URL] [EMAIL]"
  echo ""
  echo "Get MASTER_KEY from wherever you stored it when running:"
  echo "  wrangler secret put MASTER_KEY"
  exit 1
fi

echo "Fetching secrets from Doppler..."
DOPPLER_JSON=$(doppler secrets --json)

echo "Building import payload..."

# Extract secrets and build JSON array
SECRETS_JSON=$(echo "$DOPPLER_JSON" | jq '[
  to_entries[] | 
  select(.key | test("^DOPPLER_") | not) |
  {name: .key, value: .value.computed}
]')

# Build full payload
PAYLOAD=$(jq -n \
  --arg adminKey "$MASTER_KEY" \
  --arg email "$EMAIL" \
  --argjson secrets "$SECRETS_JSON" \
  '{adminKey: $adminKey, email: $email, password: "changeme123", secrets: $secrets}')

echo "Importing $(echo "$SECRETS_JSON" | jq length) secrets to $BROKER_URL..."

# Make the request
RESPONSE=$(curl -s -X POST "$BROKER_URL/v1/admin/import" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD")

echo ""
echo "Response:"
echo "$RESPONSE" | jq .

if echo "$RESPONSE" | jq -e '.ok == true' > /dev/null; then
  echo ""
  echo "✅ Import complete!"
  echo ""
  echo "Next steps:"
  echo "1. Visit $BROKER_URL and log in with $EMAIL"
  echo "2. Change your password"
  echo "3. Create an agent for seksh"
else
  echo ""
  echo "❌ Import failed"
  exit 1
fi
