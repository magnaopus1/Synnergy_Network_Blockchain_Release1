package syn1100

import (
	"encoding/json"
	"net/http"
	"time"
	"log"
	"github.com/gorilla/mux"
)

// TokenHandler manages HTTP requests related to healthcare data tokens.
type TokenHandler struct {
	Storage *Storage
}

// NewTokenHandler creates a new handler with a reference to storage operations.
func NewTokenHandler(storage *Storage) *TokenHandler {
	return &TokenHandler{Storage: storage}
}

// CreateTokenHandler handles the creation of new tokens.
func (h *TokenHandler) CreateTokenHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Owner    string          `json:"owner"`
		Patient  string          `json:"patient_id"`
		Identity IdentityDetails `json:"identity"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		log.Printf("Failed to parse create token request: %v", err)
		return
	}

	token := NewToken(GenerateTokenID(req.Patient, req.Identity.Records), req.Owner, req.Identity)
	if err := h.Storage.SaveToken(token); err != nil {
		http.Error(w, "Failed to create token", http.StatusInternalServerError)
		log.Printf("Failed to save new token: %v", err)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(token)
	log.Printf("New token created successfully: %s", token.ID)
}

// GrantAccessHandler handles requests to grant access to a token's data.
func (h *TokenHandler) GrantAccessHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tokenID := vars["id"]
	userAddress := vars["user"]

	token, err := h.Storage.GetToken(tokenID)
	if err != nil {
		http.Error(w, "Token not found", http.StatusNotFound)
		log.Printf("Token %s not found: %v", tokenID, err)
		return
	}

	token.GrantAccess(userAddress)
	log.Printf("Access granted to %s for token %s", userAddress, tokenID)
	json.NewEncoder(w).Encode(map[string]string{"status": "access granted"})
}

// RevokeAccessHandler handles requests to revoke access to a token's data.
func (h *TokenHandler) RevokeAccessHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tokenID := vars["id"]
	userAddress := vars["user"]

	token, err := h.Storage.GetToken(tokenID)
	if err != nil {
		http.Error(w, "Token not found", http.StatusNotFound)
		log.Printf("Token %s not found: %v", tokenID, err)
		return
	}

	token.RevokeAccess(userAddress)
	log.Printf("Access revoked from %s for token %s", userAddress, tokenID)
	json.NewEncoder(w).Encode(map[string]string{"status": "access revoked"})
}

// TokenDetailsHandler provides detailed information about a specific token.
func (h *TokenHandler) TokenDetailsHandler(w http.ResponseWriter, r *http.Request) {
	tokenID := mux.Vars(r)["id"]

	token, err := h.Storage.GetToken(tokenID)
	if err != nil {
		http.Error(w, "Token not found", http.StatusNotFound)
		log.Printf("Failed to retrieve token %s: %v", tokenID, err)
		return
	}

	json.NewEncoder(w).Encode(token)
	log.Printf("Details retrieved for token %s", tokenID)
}

// RegisterRoutes registers the HTTP routes associated with token operations.
func (h *TokenHandler) RegisterRoutes(router *mux.Router) {
	router.HandleFunc("/tokens", h.CreateTokenHandler).Methods("POST")
	router.HandleFunc("/tokens/{id}/grant/{user}", h.GrantAccessHandler).Methods("PUT")
	router.HandleFunc("/tokens/{id}/revoke/{user}", h.RevokeAccessHandler).Methods("PUT")
	router.HandleFunc("/tokens/{id}", h.TokenDetailsHandler).Methods("GET")
	log.Println("Token handlers registered")
}
