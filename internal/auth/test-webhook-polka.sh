#!/bin/bash

set -e

BASE_URL="http://localhost:8080/api"
EMAIL="chirpyred@example.com"
PASSWORD="verysecurepassword123"
POLKA_API_KEY=
BAD_API_KEY="wrongkey123"

echo "🧑 Creating test user..."
CREATE_OUT=$(mktemp)
curl -s -o "$CREATE_OUT" -w "%{http_code}" -X POST "$BASE_URL/users" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\", \"password\":\"$PASSWORD\"}" > /dev/null

USER_ID=$(jq -r '.id' "$CREATE_OUT")
echo "✅ User created with ID: $USER_ID"
rm "$CREATE_OUT"

echo "🚫 Sending Polka webhook with WRONG API key..."
WEBHOOK_BAD_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/polka/webhooks" \
  -H "Content-Type: application/json" \
  -H "Authorization: ApiKey $BAD_API_KEY" \
  -d "{
        \"event\": \"user.upgraded\",
        \"data\": {
          \"user_id\": \"$USER_ID\"
        }
      }")

if [ "$WEBHOOK_BAD_STATUS" != "204" ]; then
  echo "✅ Correctly rejected invalid API key with status: $WEBHOOK_BAD_STATUS"
else
  echo "❌ BAD: Webhook accepted a wrong API key — that’s a security hole"
  exit 1
fi

echo "📬 Sending Polka webhook with VALID API key..."
WEBHOOK_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/polka/webhooks" \
  -H "Content-Type: application/json" \
  -H "Authorization: ApiKey $POLKA_API_KEY" \
  -d "{
        \"event\": \"user.upgraded\",
        \"data\": {
          \"user_id\": \"$USER_ID\"
        }
      }")

echo "Webhook Status: $WEBHOOK_STATUS"

if [ "$WEBHOOK_STATUS" == "204" ]; then
  echo "✅ Polka webhook accepted, user upgraded to Chirpy Red"
else
  echo "❌ Webhook failed. Status: $WEBHOOK_STATUS"
  exit 1
fi

echo "🔐 Logging in to verify Chirpy Red upgrade..."
LOGIN_OUT=$(mktemp)
curl -s -o "$LOGIN_OUT" -w "%{http_code}" -X POST "$BASE_URL/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\", \"password\":\"$PASSWORD\"}" > /dev/null

IS_RED=$(jq -r '.is_chirpy_red' "$LOGIN_OUT")
rm "$LOGIN_OUT"

if [ "$IS_RED" == "true" ]; then
  echo "🎉 Confirmed: User is now a Chirpy Red member"
else
  echo "❌ User was NOT upgraded to Chirpy Red"
  exit 1
fi
