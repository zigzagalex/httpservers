#!/bin/bash

set -e

BASE_URL="http://localhost:8080/api"
EMAIL="testuser@example.com"
PASSWORD="supersecurepassword123"
NEW_EMAIL="updateduser@example.com"
NEW_PASSWORD="evenmoresecure456"

echo "🧑 Creating user..."
CREATE_OUTPUT=$(mktemp)
CREATE_STATUS=$(curl -s -o "$CREATE_OUTPUT" -w "%{http_code}" -X POST "$BASE_URL/users" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\", \"password\":\"$PASSWORD\"}")

echo "Status: $CREATE_STATUS"
cat "$CREATE_OUTPUT" | jq .

echo "🔑 Logging in..."
LOGIN_OUTPUT=$(mktemp)
LOGIN_STATUS=$(curl -s -o "$LOGIN_OUTPUT" -w "%{http_code}" -X POST "$BASE_URL/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\", \"password\":\"$PASSWORD\"}")

echo "Status: $LOGIN_STATUS"
cat "$LOGIN_OUTPUT" | jq .

TOKEN=$(jq -r '.token' "$LOGIN_OUTPUT")
REFRESH=$(jq -r '.refresh_token' "$LOGIN_OUTPUT")

echo ""
echo "📦 Access Token: $TOKEN"
echo "🔁 Refresh Token: $REFRESH"

echo "✏️ Updating user email and password..."
UPDATE_OUTPUT=$(mktemp)
UPDATE_STATUS=$(curl -s -o "$UPDATE_OUTPUT" -w "%{http_code}" -X PUT "$BASE_URL/users" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$NEW_EMAIL\", \"password\":\"$NEW_PASSWORD\"}")

echo "Update Status: $UPDATE_STATUS"
cat "$UPDATE_OUTPUT" | jq .

echo "🔐 Verifying new credentials..."
VERIFY_OUTPUT=$(mktemp)
VERIFY_STATUS=$(curl -s -o "$VERIFY_OUTPUT" -w "%{http_code}" -X POST "$BASE_URL/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$NEW_EMAIL\", \"password\":\"$NEW_PASSWORD\"}")

echo "Login with new credentials Status: $VERIFY_STATUS"
cat "$VERIFY_OUTPUT" | jq .

echo "⛔ Revoking refresh token..."
REVOKE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/revoke" \
  -H "Authorization: Bearer $REFRESH")

echo "Revoke Status: $REVOKE_STATUS"

# Cleanup
rm "$CREATE_OUTPUT" "$LOGIN_OUTPUT" "$UPDATE_OUTPUT" "$VERIFY_OUTPUT"
