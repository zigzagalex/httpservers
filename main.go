package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
)

type apiConfig struct {
	fileserverHits atomic.Int32
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
	cfg.fileserverHits.Store(0)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hit counter reset."))
}

func readinessHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(200)
	w.Write([]byte("OK"))
}

func validateChirpHandler(w http.ResponseWriter, r *http.Request) {
	type chirp struct {
		Body string `json:"body"`
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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"cleaned_body": cleaned,
	})
}

func main() {

	serveMux := http.NewServeMux()

	server := http.Server{
		Addr:    ":8080",
		Handler: serveMux,
	}

	apiCfg := apiConfig{}

	fileServer := http.FileServer(http.Dir("."))
	fileHandler := apiCfg.incrementHits(http.StripPrefix("/app/", fileServer))
	serveMux.Handle("/app/", fileHandler)

	serveMux.HandleFunc("GET /api/healthz", readinessHandler)
	serveMux.HandleFunc("POST /api/validate_chirp", validateChirpHandler)

	serveMux.HandleFunc("GET /admin/metrics", apiCfg.writeHits)
	serveMux.HandleFunc("POST /admin/reset", apiCfg.resetHits)

	err := http.ListenAndServe(server.Addr, server.Handler)
	if err != nil {
		fmt.Println(err)
	}

}
