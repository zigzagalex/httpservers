package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/zigzagalex/httpservers/internal/auth"
	"github.com/zigzagalex/httpservers/internal/database"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	platform       string
	secret         string
	polkaKey       string
}

type User struct {
	ID           uuid.UUID `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Email        string    `json:"email"`
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
	IsChirpyRed  bool      `json:"is_chirpy_red"`
}

func convertToAPIUser(dbUser database.User, token string, refresh_token string) User {
	return User{
		ID:           dbUser.ID,
		CreatedAt:    dbUser.CreatedAt,
		UpdatedAt:    dbUser.UpdatedAt,
		Email:        dbUser.Email,
		Token:        token,
		RefreshToken: refresh_token,
		IsChirpyRed:  dbUser.IsChirpyRed,
	}
}

type Chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

func convertToAPIChirp(dbChirp database.Chirp) Chirp {
	return Chirp{
		ID:        dbChirp.ID,
		CreatedAt: dbChirp.CreatedAt,
		UpdatedAt: dbChirp.UpdatedAt,
		Body:      dbChirp.Body,
		UserID:    dbChirp.UserID,
	}
}

func (cfg *apiConfig) incrementHits(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) writeHits(w http.ResponseWriter, r *http.Request) {
	count := cfg.fileserverHits.Load()
	html := fmt.Sprintf(`
				<html>
				<body>
					<h1>Welcome, Chirpy Admin</h1>
					<p>Chirpy has been visited %d times!</p>
				</body>
				</html>`, count)
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))

}

func (cfg *apiConfig) resetHits(w http.ResponseWriter, r *http.Request) {

	if cfg.platform != "dev" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// Reset website hit counter
	cfg.fileserverHits.Store(0)

	// Reset user database
	cfg.db.Reset(r.Context())

	// Status
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hit counter and user db reset."))

}

func readinessHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(200)
	w.Write([]byte("OK"))
}

func (cfg *apiConfig) createUserHandler(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	var params request
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&params)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Error while decoding.",
		})
		return
	}

	if params.Email == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Email is required",
		})
		return
	}

	if params.Password == "" || len(params.Password) < 12 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Password is required and must be of lenght >= 12",
		})
		return
	}

	hashedPassword, err := auth.HashPassword(params.Password)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Could not hash password",
		})
		return
	}

	newUser := database.CreateUserParams{
		ID:             uuid.New(),
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
		Email:          params.Email,
		HashedPassword: hashedPassword,
	}

	createdUser, err := cfg.db.CreateUser(r.Context(), newUser)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Database error, could not create user.",
		})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	// Map to User struct
	responseUser := convertToAPIUser(createdUser, "", "unset")
	json.NewEncoder(w).Encode(responseUser)

}

func (cfg *apiConfig) createChirpHandler(w http.ResponseWriter, r *http.Request) {
	type chirp struct {
		Body   string    `json:"body"`
		UserId uuid.UUID `json:"user_id"`
	}

	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		http.Error(w, `{"error":"Missing or invalid Authorization header"}`, http.StatusUnauthorized)
	}
	_, err = auth.ValidateJWT(token, cfg.secret)
	if err != nil {
		http.Error(w, `{"error":"Invalid or expired token"}`, http.StatusUnauthorized)
	}

	var params chirp
	decoder := json.NewDecoder(r.Body)
	err = decoder.Decode(&params)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Error while decoding.",
		})
		return
	}

	if params.Body == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Chirp body is required",
		})
		return
	}

	if len(params.Body) > 140 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Chirp is too long",
		})
		return
	}

	// Swear word filter
	badWords := map[string]bool{
		"kerfuffle": true,
		"sharbert":  true,
		"fornax":    true,
	}

	words := strings.Fields(params.Body)
	for i, word := range words {
		// Lowercase version without punctuation
		lower := strings.ToLower(word)

		// Check for exact match only (no punctuation)
		if badWords[lower] {
			words[i] = "****"
		}
	}

	cleaned := strings.Join(words, " ")

	newChirp := database.CreateChirpParams{
		ID:        uuid.New(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Body:      cleaned,
		UserID:    params.UserId,
	}

	_, err = cfg.db.GetUserById(r.Context(), params.UserId)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "User not found.",
		})
		return
	}

	createdChirp, err := cfg.db.CreateChirp(r.Context(), newChirp)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Database error, could not create chirp.",
		})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	// Map to User struct
	responseChirp := convertToAPIChirp(createdChirp)
	json.NewEncoder(w).Encode(responseChirp)

}

func (cfg *apiConfig) getChirpsHandler(w http.ResponseWriter, r *http.Request) {
	authorIDStr := r.URL.Query().Get("author_id")

	var chirpsFromDB []database.Chirp
	var err error

	if authorIDStr != "" {
		authorID, parseErr := uuid.Parse(authorIDStr)
		if parseErr != nil {
			http.Error(w, `{"error":"Invalid author_id"}`, http.StatusBadRequest)
			return
		}

		chirpsFromDB, err = cfg.db.GetChirpsByAuthorID(r.Context(), authorID)
	} else {
		chirpsFromDB, err = cfg.db.GetChirps(r.Context())
	}

	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Failed to retrieve chirps",
		})
		return
	}

	chirps := make([]Chirp, len(chirpsFromDB))
	for i, dbChirp := range chirpsFromDB {
		chirps[i] = convertToAPIChirp(dbChirp)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(chirps)
}

func (cfg *apiConfig) getChirpByIDHandler(w http.ResponseWriter, r *http.Request) {
	chirpIDStr := r.PathValue("chirpID")

	id, err := uuid.Parse(chirpIDStr)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Invalid chirp ID format",
		})
		return
	}

	chirp, err := cfg.db.GetChirp(r.Context(), id)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		if err.Error() == "sql: no rows in result set" {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Chirp not found",
			})
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Failed to retrieve chirp",
			})
		}
		return
	}

	responseChirp := convertToAPIChirp(chirp)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(responseChirp)
}

func (cfg *apiConfig) loginUserHandler(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Email            string `json:"email"`
		Password         string `json:"password"`
		ExpiresInSeconds int    `json:"expires_in_seconds"`
	}

	// Unmarshal json
	var params request
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&params)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Error while decoding.",
		})
		return
	}

	if params.Email == "" || params.Password == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Email and password are required",
		})
		return
	}

	// Get the users info from database
	user, err := cfg.db.GetUserByEmail(r.Context(), params.Email)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Incorrect email or password",
		})
		return
	}

	// Check the input password against hashed password in database
	err = auth.CheckPasswordHash(params.Password, user.HashedPassword)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Incorrect password",
		})
		return
	}

	// Determine token expiration
	expiration := time.Hour // default
	if params.ExpiresInSeconds > 0 {
		limit := int(time.Hour.Seconds())
		if params.ExpiresInSeconds < limit {
			expiration = time.Duration(params.ExpiresInSeconds) * time.Second
		}
	}

	// Create JWT
	token, err := auth.MakeJWT(user.ID, cfg.secret, expiration)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Could not generate token",
		})
		return
	}

	// Create refresh token and store in db
	refreshToken, err := auth.MakeRefreshToken()
	refreshTokenParams := database.CreateRefreshTokenParams{
		Token:     refreshToken,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		UserID:    user.ID,
		ExpiresAt: time.Now().AddDate(0, 0, 60),
	}
	_, err = cfg.db.CreateRefreshToken(r.Context(), refreshTokenParams)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Could not create refresh token",
		})
		return
	}

	responseUser := convertToAPIUser(user, token, refreshToken)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(responseUser)

}

func (cfg *apiConfig) revokeTokenHandler(w http.ResponseWriter, r *http.Request) {
	// Get token from Authorization header
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Missing or malformed token",
		})
		return
	}

	// Find the refresh token in DB
	rt, err := cfg.db.GetRefreshToken(r.Context(), token)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Invalid or expired token",
		})
		return
	}

	// Revoke the token
	updateParams := database.RevokeRefreshTokenParams{
		RevokedAt: sql.NullTime{Time: time.Now(), Valid: true},
		UpdatedAt: time.Now(),
		Token:     rt.Token,
	}

	err = cfg.db.RevokeRefreshToken(r.Context(), updateParams)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Could not revoke token",
		})
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) updateUserHandler(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		http.Error(w, `{"error":"Missing or invalid token"}`, http.StatusUnauthorized)
		return
	}

	userID, err := auth.ValidateJWT(token, cfg.secret)
	if err != nil {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	// Parse request body
	type request struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	var params request
	decoder := json.NewDecoder(r.Body)
	err = decoder.Decode(&params)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Error while decoding.",
		})
		return
	}

	// Validate fields
	if params.Email == "" || params.Password == "" || len(params.Password) < 12 {
		http.Error(w, `{"error":"Email and password (min 12 chars) required"}`, http.StatusBadRequest)
		return
	}

	// Hash new password
	hashedPassword, err := auth.HashPassword(params.Password)
	if err != nil {
		http.Error(w, `{"error":"Failed to hash password"}`, http.StatusInternalServerError)
		return
	}

	// Update the user
	updateParams := database.UpdateUserParams{
		ID:             userID,
		Email:          params.Email,
		HashedPassword: hashedPassword,
		UpdatedAt:      time.Now(),
	}

	updatedUser, err := cfg.db.UpdateUser(r.Context(), updateParams)
	if err != nil {
		http.Error(w, `{"error":"Could not update user"}`, http.StatusInternalServerError)
		return
	}

	// Return updated user (no tokens)
	responseUser := convertToAPIUser(updatedUser, "", "unset")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(responseUser)
}

func (cfg *apiConfig) polkaWebhookHandler(w http.ResponseWriter, r *http.Request) {
	type polkaRequest struct {
		Event string `json:"event"`
		Data  struct {
			UserID string `json:"user_id"`
		} `json:"data"`
	}

	polkaKey, err := auth.GetAPIKey(r.Header)
	if err != nil {
		http.Error(w, `{"error":"Error retrieving api key from header"}`, http.StatusBadRequest)
		return
	}
	if polkaKey != cfg.polkaKey {
		http.Error(w, `{"error":"Invalid api key"}`, http.StatusBadRequest)
		return
	}

	var payload polkaRequest
	err = json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	if payload.Event != "user.upgraded" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	userUUID, err := uuid.Parse(payload.Data.UserID)
	if err != nil {
		http.Error(w, `{"error":"Invalid user_id"}`, http.StatusBadRequest)
		return
	}

	_, err = cfg.db.UpgradeUserChipyRed(r.Context(), userUUID)
	if err != nil {
		http.Error(w, `{"error":"User not found or failed to upgrade"}`, http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) deleteChirpHandler(w http.ResponseWriter, r *http.Request) {
	// Extract and validate JWT
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		http.Error(w, `{"error":"Missing or malformed Authorization header"}`, http.StatusUnauthorized)
		return
	}

	userID, err := auth.ValidateJWT(token, cfg.secret)
	if err != nil {
		http.Error(w, `{"error":"Invalid or expired token"}`, http.StatusUnauthorized)
		return
	}

	// Parse chirp ID
	chirpIDStr := r.PathValue("chirpID")
	chirpID, err := uuid.Parse(chirpIDStr)
	if err != nil {
		http.Error(w, `{"error":"Invalid chirp ID format"}`, http.StatusBadRequest)
		return
	}

	// Retrieve chirp
	chirp, err := cfg.db.GetChirp(r.Context(), chirpID)
	if err != nil {
		http.Error(w, `{"error":"Chirp not found"}`, http.StatusNotFound)
		return
	}

	// Check if user owns the chirp
	if chirp.UserID != userID {
		http.Error(w, `{"error":"You do not have permission to delete this chirp"}`, http.StatusForbidden)
		return
	}

	// Delete chirp
	err = cfg.db.DeleteChirp(r.Context(), chirpID)
	if err != nil {
		http.Error(w, `{"error":"Could not delete chirp"}`, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func main() {
	// Get env variables
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	platform := os.Getenv("PLATFORM")
	secret := os.Getenv("SECRET")
	polkaKey := os.Getenv("POLKA_KEY")

	// Open connection to Postgres database
	db, err := sql.Open("postgres", dbURL)
	dbQueries := database.New(db)

	// Set up server
	serveMux := http.NewServeMux()

	server := http.Server{
		Addr:    ":8080",
		Handler: serveMux,
	}

	// Set API config
	apiCfg := apiConfig{
		db:       dbQueries,
		platform: platform,
		secret:   secret,
		polkaKey: polkaKey,
	}

	fileServer := http.FileServer(http.Dir("."))
	fileHandler := apiCfg.incrementHits(http.StripPrefix("/app/", fileServer))
	serveMux.Handle("/app/", fileHandler)

	serveMux.HandleFunc("GET /api/healthz", readinessHandler)
	serveMux.HandleFunc("POST /api/users", apiCfg.createUserHandler)
	serveMux.HandleFunc("PUT /api/users", apiCfg.updateUserHandler)
	serveMux.HandleFunc("POST /api/login", apiCfg.loginUserHandler)
	serveMux.HandleFunc("POST /api/revoke", apiCfg.revokeTokenHandler)
	serveMux.HandleFunc("POST /api/chirps", apiCfg.createChirpHandler)
	serveMux.HandleFunc("GET /api/chirps", apiCfg.getChirpsHandler)
	serveMux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.getChirpByIDHandler)
	serveMux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.deleteChirpHandler)

	serveMux.HandleFunc("GET /admin/metrics", apiCfg.writeHits)
	serveMux.HandleFunc("POST /admin/reset", apiCfg.resetHits)

	serveMux.HandleFunc("POST /api/polka/webhooks", apiCfg.polkaWebhookHandler)

	err = http.ListenAndServe(server.Addr, server.Handler)
	if err != nil {
		fmt.Println(err)
	}

}
