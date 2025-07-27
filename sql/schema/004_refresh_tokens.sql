-- +goose Up
CREATE TABLE refresh_tokens (
    token TEXT PRIMARY KEY DEFAULT 'unset',
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    user_id UUID NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP,
    CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)
;

-- +goose Down
DROP TABLE refresh_tokens;