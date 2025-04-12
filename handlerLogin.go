package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/Londrin/chirpy/internal/auth"
	"github.com/Londrin/chirpy/internal/database"
)

func (cfg *apiConfig) handlerLogin(w http.ResponseWriter, req *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	type response struct {
		User
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
	}

	decoder := json.NewDecoder(req.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		log.Printf("Login Error - Decoding Error: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Issue decoding input", err)
		return
	}

	usr, err := cfg.db.GetUserByEmail(req.Context(), params.Email)
	if err != nil {
		log.Printf("Login Error - Unable to find user: %s", err)
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password", err)
		return
	}

	err = auth.CheckPasswordHash(usr.HashedPassword, params.Password)
	if err != nil {
		log.Printf("Login Issue: User attempted login with bad password: %s", err)
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password", err)
		return
	}
	oneHour := time.Duration(3600)

	token, err := auth.MakeJWT(usr.ID, cfg.jwt_secret, time.Duration(oneHour*time.Second))
	if err != nil {
		log.Printf("Login Issues: Couldn't produce JWT Token: %s", err)
		respondWithError(w, http.StatusInternalServerError, "Unable to create access JWT", err)
		return
	}

	refreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		log.Printf("Login Error - Unable to create refresh token: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Unable to create refresh token", err)
		return
	}

	_, err = cfg.db.CreateRefreshToken(req.Context(), database.CreateRefreshTokenParams{
		Token:     refreshToken,
		UserID:    usr.ID,
		ExpiresAt: time.Now().AddDate(0, 0, 60),
	})
	if err != nil {
		log.Printf("Login Error - Unable to save refresh token: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Couldn't save refresh token", err)
		return
	}

	respondWithJSON(w, http.StatusOK, response{
		User: User{
			ID:         usr.ID,
			CreatedAt:  usr.CreatedAt,
			UpdatedAt:  usr.UpdatedAt,
			Email:      usr.Email,
			Chirpy_Red: usr.IsChirpyRed,
		},
		Token:        token,
		RefreshToken: refreshToken,
	})
}
