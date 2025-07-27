# Chirpy API Documentation

This is the complete documentation for the **Chirpy API** — a microblogging platform with user authentication, JWT support, refresh tokens, and Chirpy Red upgrade capability.

---

## 🔐 Authentication

### Access Token

- Obtained via `/api/login`.
- Used as a `Bearer` token in `Authorization` headers.

### Refresh Token

- Issued alongside the access token.
- Used in `/api/revoke`.

---

## 📋 Endpoints

### `GET /api/healthz`

Check server health.

**Response:**

- `200 OK` with body `OK`

---

### `POST /api/users`

Register a new user.

**Body:**

```json
{
  "email": "user@example.com",
  "password": "supersecurepassword123"
}
```

**Responses:**

- `201 Created`: Returns user info (without password).
- `400 Bad Request`: Missing/invalid fields.

---

### `PUT /api/users`

Update your email and password. Requires **access token**.

**Header:** `Authorization: Bearer <ACCESS_TOKEN>`

**Body:**

```json
{
  "email": "new@example.com",
  "password": "newsecurepassword456"
}
```

**Responses:**

- `200 OK`: Updated user.
- `401 Unauthorized`: Missing or invalid token.

---

### `POST /api/login`

Login and receive access + refresh tokens.

**Body:**

```json
{
  "email": "user@example.com",
  "password": "supersecurepassword123",
  "expires_in_seconds": 3600
}
```

**Response:**

- `200 OK`: User object with `token` and `refresh_token`.

---

### `POST /api/revoke`

Revoke a refresh token.

**Header:** `Authorization: Bearer <REFRESH_TOKEN>`

**Responses:**

- `204 No Content`: Success.
- `401 Unauthorized`: Invalid or expired token.

---

### `POST /api/chirps`

Create a new chirp (max 140 chars). Requires **access token**.

**Body:**

```json
{
  "body": "This is my chirp!",
  "user_id": "<UUID>"
}
```

**Response:**

- `201 Created`: Returns the created chirp.
- `400 Bad Request`: Invalid input.

---

### `GET /api/chirps`

Get all chirps or filter by author.

**Optional Query:**

- `author_id=<UUID>`

**Response:**

- `200 OK`: List of chirps.

---

### `GET /api/chirps/{chirpID}`

Get a specific chirp by ID.

**Response:**

- `200 OK`: Returns chirp.
- `404 Not Found`: Chirp doesn’t exist.

---

### `DELETE /api/chirps/{chirpID}`

Delete your own chirp. Requires **access token**.

**Header:** `Authorization: Bearer <ACCESS_TOKEN>`

**Response:**

- `204 No Content`: Chirp deleted.
- `403 Forbidden`: Not the author.
- `404 Not Found`: Chirp doesn’t exist.

---

### `POST /api/polka/webhooks`

Webhook to mark a user as **Chirpy Red**.

**Header:** `Authorization: ApiKey <POLKA_KEY>`

**Body:**

```json
{
  "event": "user.upgraded",
  "data": {
    "user_id": "<UUID>"
  }
}
```

**Responses:**

- `204 No Content`: Successfully marked user as Chirpy Red.
- `404 Not Found`: User doesn’t exist.
- `400 Bad Request`: Invalid payload or API key.

---

## 🛠️ Admin Endpoints (Dev Only)

### `GET /admin/metrics`

View how many times the app has been accessed.

### `POST /admin/reset`

Reset hit counter and user database (dev only).

---

## 🧑 User Object

```json
{
  "id": "uuid",
  "created_at": "timestamp",
  "updated_at": "timestamp",
  "email": "user@example.com",
  "token": "<JWT>",
  "refresh_token": "<refresh>",
  "is_chirpy_red": true
}
```

## 🐦 Chirp Object

```json
{
  "id": "uuid",
  "created_at": "timestamp",
  "updated_at": "timestamp",
  "body": "This is my chirp!",
  "user_id": "uuid"
}
```

---

### 🚀 Notes

- JWTs expire based on `expires_in_seconds` passed during login.
- Refresh tokens are long-lived and must be revoked manually.
- Bad words like `kerfuffle`, `sharbert`, and `fornax` are censored.

---

Welcome to Chirpy. Tweet responsibly. 🐥

