-- name: GetChirpsByAuthorID :many
SELECT * FROM chirps
WHERE user_id = $1
ORDER BY created_at ASC;
