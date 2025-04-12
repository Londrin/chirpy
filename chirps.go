package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Londrin/chirpy/internal/auth"
	"github.com/Londrin/chirpy/internal/database"
	"github.com/google/uuid"
)

type Chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	User_ID   uuid.UUID `json:"user_id"`
}

type Parameters struct {
	Body string `json:"body"`
}

func decodeParams(req *http.Request) (Parameters, error) {
	decoder := json.NewDecoder(req.Body)
	params := Parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		return Parameters{}, err
	}

	return params, nil
}

func (cfg *apiConfig) handlerValidateChirp(w http.ResponseWriter, req *http.Request) {
	params, err := decodeParams(req)
	if err != nil {
		log.Printf("Decoding Error - JSON: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Decoding Error", err)
	}

	token, err := auth.GetBearerToken(req.Header)
	if err != nil {
		log.Printf("Create Chirp - Bearer Token Error: %s", err)
		respondWithError(w, http.StatusBadRequest, "Invalid Header", err)
		return
	}

	userID, err := auth.ValidateJWT(token, cfg.jwt_secret)
	if err != nil {
		log.Printf("Create Chirp - Unable to validate JWT token: %s", err)
		respondWithError(w, http.StatusUnauthorized, "Please relogin", err)
		return
	}

	const maxChirpLength = 140
	if len(params.Body) > maxChirpLength {
		respondWithError(w, http.StatusBadRequest, "Chirp is too long", nil)
		return
	}

	badWords := map[string]struct{}{
		"kerfuffle": {},
		"sharbert":  {},
		"fornax":    {},
	}

	chirp, err := cfg.db.CreateChirp(context.Background(), database.CreateChirpParams{
		Body:   cleanChirpBody(params.Body, badWords),
		UserID: userID,
	})
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Unable to create Chirp", err)
		return
	}

	respondWithJSON(w, http.StatusCreated, Chirp{
		ID:        chirp.ID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body:      cleanChirpBody(chirp.Body, badWords),
		User_ID:   chirp.UserID,
	})
}

func cleanChirpBody(msg string, badWords map[string]struct{}) string {
	text := strings.Split(msg, " ")

	for i, word := range text {
		if _, ok := badWords[strings.ToLower(word)]; ok {
			text[i] = "****"
		}
	}

	cleaned := strings.Join(text, " ")

	return cleaned
}

func (cfg *apiConfig) handlerGetChirps(w http.ResponseWriter, req *http.Request) {
	s := req.URL.Query().Get("author_id")
	sortType := req.URL.Query().Get("sort")
	var chirps []database.Chirp
	var err error
	if s != "" {
		user_id, err := uuid.Parse(s)
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, "Invalid author ID", err)
			return
		}
		chirps, err = cfg.db.GetChirpsByID(req.Context(), user_id)
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, "Unable to get chirps", err)
			return
		}
	} else {
		chirps, err = cfg.db.GetAllChirps(req.Context())
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, "Unable to get Chirps", err)
			return
		}
	}

	responseChirps := []Chirp{}

	for _, chirp := range chirps {
		responseChirps = append(responseChirps, Chirp{
			ID:        chirp.ID,
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			Body:      chirp.Body,
			User_ID:   chirp.UserID,
		})
	}

	if sortType == "desc" {
		sort.Slice(responseChirps, func(i, j int) bool { return responseChirps[i].CreatedAt.After(responseChirps[j].CreatedAt) })
	}

	respondWithJSON(w, http.StatusOK, responseChirps)
}

func (cfg *apiConfig) handlerGetChirpByID(w http.ResponseWriter, req *http.Request) {
	path := req.PathValue("chirpID")

	id, err := uuid.Parse(path)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Unable to get ID", err)
		return
	}
	chirp, err := cfg.db.GetChirpByID(req.Context(), id)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "Unable to get chirp", err)
	}

	respondWithJSON(w, http.StatusOK, Chirp{
		ID:        chirp.ID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body:      chirp.Body,
		User_ID:   chirp.UserID,
	})
}

func (cfg *apiConfig) handlerDeleteChirp(w http.ResponseWriter, req *http.Request) {
	incToken, err := auth.GetBearerToken(req.Header)
	if err != nil {
		log.Printf("Handler Delete Chirp - Invalid Header: %v", err)
		respondWithError(w, http.StatusUnauthorized, "Missing Auth Header", err)
		return
	}

	user_ID, err := auth.ValidateJWT(incToken, cfg.jwt_secret)
	if err != nil {
		log.Printf("Handler Delete Chirp - Unable to validate JWT: %v", err)
		respondWithError(w, http.StatusForbidden, "Invalid JWT Token", err)
		return
	}

	chirp_ID, err := uuid.Parse(req.PathValue("chirpID"))
	if err != nil {
		log.Printf("Handler Delete Chirp - Cannot parse Chirp ID: %v", err)
		respondWithError(w, http.StatusBadRequest, "Invalid ID Type", err)
		return
	}

	chirp, err := cfg.db.GetChirpByID(req.Context(), chirp_ID)
	if err != nil {
		log.Printf("Handler Delete Chirp - Chirp not found: %v", err)
		respondWithError(w, http.StatusNotFound, "Chirp not found", err)
		return
	}

	if chirp.UserID != user_ID {
		log.Printf("Handler Delete Chirp - User not authorized to delete this chirp")
		respondWithError(w, http.StatusForbidden, "You can only delete your own chirps", nil)
		return
	}

	err = cfg.db.DeleteChirp(req.Context(), database.DeleteChirpParams{
		ID:     chirp_ID,
		UserID: user_ID,
	})
	if err != nil {
		log.Printf("Handler Delete Chirp - Unable to delete Chirp: %v", err)
		respondWithError(w, http.StatusNotFound, "Chirp not found", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
