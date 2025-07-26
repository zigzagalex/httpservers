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
	"github.com/zigzagalex/httpservers/internal/database"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	platform       string
}

type User struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
}

func convertToAPIUser(dbUser database.User) User {
	return User{
		ID:        dbUser.ID,
		CreatedAt: dbUser.CreatedAt,
		UpdatedAt: dbUser.UpdatedAt,
		Email:     dbUser.Email,
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
		Email string `json:"email"`
	}

	var params request
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&params)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Something went wrong",
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

	newUser := database.CreateUserParams{
		ID:        uuid.New(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Email:     params.Email,
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
	responseUser := convertToAPIUser(createdUser)
	json.NewEncoder(w).Encode(responseUser)

}

func (cfg *apiConfig) createChirpHandler(w http.ResponseWriter, r *http.Request) {
	type chirp struct {
		Body   string    `json:"body"`
		UserId uuid.UUID `json:"user_id"`
	}

	var params chirp
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&params)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Something went wrong",
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

	// Swear word filter 🔥
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

	_, err = cfg.db.GetUser(r.Context(), params.UserId)
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
	chirpsFromDB, err := cfg.db.GetChirps(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Failed to retrieve chirps",
		})
		return
	}

	// Map to public Chirp struct
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

func main() {
	// Get env variables
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	platform := os.Getenv("PLATFORM")

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
	}

	fileServer := http.FileServer(http.Dir("."))
	fileHandler := apiCfg.incrementHits(http.StripPrefix("/app/", fileServer))
	serveMux.Handle("/app/", fileHandler)

	serveMux.HandleFunc("GET /api/healthz", readinessHandler)
	serveMux.HandleFunc("POST /api/users", apiCfg.createUserHandler)
	serveMux.HandleFunc("POST /api/chirps", apiCfg.createChirpHandler)
	serveMux.HandleFunc("GET /api/chirps", apiCfg.getChirpsHandler)
	serveMux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.getChirpByIDHandler)

	serveMux.HandleFunc("GET /admin/metrics", apiCfg.writeHits)
	serveMux.HandleFunc("POST /admin/reset", apiCfg.resetHits)

	err = http.ListenAndServe(server.Addr, server.Handler)
	if err != nil {
		fmt.Println(err)
	}

}
