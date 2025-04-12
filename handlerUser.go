package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/Londrin/chirpy/internal/auth"
	"github.com/Londrin/chirpy/internal/database"
	"github.com/google/uuid"
)

func (cfg *apiConfig) handlerCreateUser(w http.ResponseWriter, req *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	decoder := json.NewDecoder(req.Body)
	incomingUser := parameters{}
	err := decoder.Decode(&incomingUser)
	if err != nil {
		log.Printf("Decoding Error - Unable to create user - JSON: %s", err)
		respondWithError(w, http.StatusInternalServerError, "Decoding Error", err)
		return
	}

	hashPw, err := auth.HashPassword(incomingUser.Password)
	if err != nil {
		log.Printf("Error - Unable to hash password: %s", err)
		respondWithError(w, http.StatusBadRequest, "Unable to create user", err)
		return
	}

	usr, err := cfg.db.CreateUser(req.Context(), database.CreateUserParams{
		Email:          incomingUser.Email,
		HashedPassword: hashPw,
	})
	if err != nil {
		log.Printf("Error - Unable to Create User: %s", err)
		respondWithError(w, http.StatusInternalServerError, "Unable to create user", err)
		return
	}

	respondWithJSON(w, http.StatusCreated, User{
		ID:        usr.ID,
		CreatedAt: usr.CreatedAt,
		UpdatedAt: usr.UpdatedAt,
		Email:     usr.Email,
	})
	log.Printf("Created User: %s - ID: %v\n", usr.Email, usr.ID)
}

func (cfg *apiConfig) handlerUpdateUser(w http.ResponseWriter, req *http.Request) {
	jwtToken, err := auth.GetBearerToken(req.Header)
	if err != nil {
		log.Printf("Update User Handler - Invalid Auth Token: %v", err)
		respondWithError(w, http.StatusUnauthorized, "Invalid Token in Header", err)
		return
	}

	user_ID, err := auth.ValidateJWT(jwtToken, cfg.jwt_secret)
	if err != nil {
		log.Printf("Update User Handler - Unable to validate JWT Token: %v", err)
		respondWithError(w, http.StatusUnauthorized, "Invalid JWT Token", err)
		return
	}

	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	decoder := json.NewDecoder(req.Body)
	params := parameters{}
	err = decoder.Decode(&params)
	if err != nil {
		log.Printf("Unable to decode json: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Unable to decode JSON", err)
		return
	}

	hashed_pw, err := auth.HashPassword(params.Password)
	if err != nil {
		log.Printf("Unable to hash password: %v", err)
		respondWithError(w, http.StatusUnauthorized, "Unable to hash password", err)
		return
	}

	type response struct {
		User
	}

	usr, err := cfg.db.UpdateUser(req.Context(), database.UpdateUserParams{
		Email:          params.Email,
		HashedPassword: hashed_pw,
		ID:             user_ID,
	})
	if err != nil {
		log.Printf("Handler Update User - Unable to update user: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Unable to update user", err)
		return
	}

	respondWithJSON(w, http.StatusOK, response{
		User: User{
			ID:         usr.ID,
			Email:      usr.Email,
			CreatedAt:  usr.CreatedAt,
			UpdatedAt:  usr.UpdatedAt,
			Chirpy_Red: usr.IsChirpyRed,
		},
	})
}

func (cfg *apiConfig) handlerUpdateChirpyRed(w http.ResponseWriter, req *http.Request) {
	apikey, err := auth.GetAPIKey(req.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid request", err)
		return
	}

	if cfg.polka_key != apikey {
		respondWithError(w, http.StatusUnauthorized, "Bad Request", err)
		return
	}

	type parameters struct {
		Event string `json:"event"`
		Data  struct {
			User_ID uuid.UUID `json:"user_id"`
		} `json:"data"`
	}

	decoder := json.NewDecoder(req.Body)
	params := parameters{}
	err = decoder.Decode(&params)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Unable to decode JSON", err)
		return
	}

	if params.Event != "user.upgraded" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	_, err = cfg.db.UpdateUserRed(req.Context(), params.Data.User_ID)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "Invalid User", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
