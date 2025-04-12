package main

import (
	"log"
	"net/http"
	"time"

	"github.com/Londrin/chirpy/internal/auth"
)

func (cfg *apiConfig) handlerRefresh(w http.ResponseWriter, req *http.Request) {
	incomingToken, err := auth.GetBearerToken(req.Header)
	if err != nil {
		log.Printf("Refresh handler - Invalid Header: %v", err)
		respondWithError(w, http.StatusBadRequest, "Invalid Header", err)
		return
	}

	usr, err := cfg.db.GetUserFromRefreshToken(req.Context(), incomingToken)
	if err != nil {
		log.Printf("Refresh handler - Invalid token: %v", err)
		respondWithError(w, http.StatusUnauthorized, "Relogin", err)
		return
	}

	type response struct {
		Token string `json:"token"`
	}

	oneHour := time.Duration(1 * time.Hour)

	token, err := auth.MakeJWT(usr.ID, cfg.jwt_secret, oneHour)
	if err != nil {
		log.Printf("Refresh Handler - Unable to create token: %v", err)
		respondWithError(w, http.StatusUnauthorized, "Unable to validate token", err)
		return
	}

	respondWithJSON(w, http.StatusOK, response{
		Token: token,
	})
}

func (cfg *apiConfig) handlerRevoke(w http.ResponseWriter, req *http.Request) {
	incomingToken, err := auth.GetBearerToken(req.Header)
	if err != nil {
		log.Printf("Revoke Handler - Invalid Header: %v", err)
		respondWithError(w, http.StatusBadRequest, "Invalid header", err)
		return
	}

	err = cfg.db.RevokeRefreshToken(req.Context(), incomingToken)
	if err != nil {
		log.Printf("Revoke Handler - Failed to revoke token: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Unable to revoke session", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
