#!/bin/bash

BASE_URL="http://localhost:8080"
EMAIL="testuser@example.com"
PASSWORD="supersecurepassword123"

# 🛠 Create user
echo "Creating user..."
curl -X POST "$BASE_URL/api/users" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "'"$EMAIL"'",
    "password": "'"$PASSWORD"'"
  }' \
  -w "\nStatus: %{http_code}\n" \
  -s

echo -e "\nUser created (or already exists)\n"

# 🔐 Log in user
echo "Logging in..."
curl -X POST "$BASE_URL/api/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "'"$EMAIL"'",
    "password": "'"$PASSWORD"'"
  }' \
  -w "\nStatus: %{http_code}\n" \
  -s

echo -e "\nLogin request complete"
