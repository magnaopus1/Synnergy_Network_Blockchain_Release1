package syn70

import (
	"encoding/json"
	"net/http"
	"log"

	"synthron-blockchain/pkg/common"
)

// TokenHandler manages HTTP requests related to SYN70 tokens.
type TokenHandler struct {
	Storage *Storage
}

// NewTokenHandler creates a new TokenHandler with the necessary storage.
func NewTokenHandler(storage *Storage) *TokenHandler {
	return &TokenHandler{Storage: storage}
}

// CreateToken processes the creation of a new token.
func (h *TokenHandler) CreateToken(w http.ResponseWriter, r *http.Request) {
	var token Token
	err := json.NewDecoder(r.Body).Decode(&token)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		log.Printf("Error decoding token data: %v", err)
		return
	}

	err = h.Storage.SaveToken(&token)
	if err != nil {
		http.Error(w, "Failed to create token", http.StatusInternalServerError)
		log.Printf("Failed to save token: %v", err)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(token)
	log.Printf("Token created with ID: %s", token.ID)
}

// GetToken handles requests to fetch a token.
func (h *TokenHandler) GetToken(w http.ResponseWriter, r *http.Request) {
	tokenID := r.URL.Query().Get("id")
	if tokenID == "" {
		http.Error(w, "Token ID is required", http.StatusBadRequest)
		return
	}

	token, err := h.Storage.GetToken(tokenID)
	if err != nil {
		http.Error(w, "Token not found", http.StatusNotFound)
		log.Printf("Token not found: %v", err)
		return
	}

	json.NewEncoder(w).Encode(token)
	log.Printf("Token retrieved: %s", tokenID)
}

// UpdateToken processes requests to update a token.
func (h *TokenHandler) UpdateToken(w http.ResponseWriter, r *http.Request) {
	tokenID := r.URL.Query().Get("id")
	if tokenID == "" {
		http.Error(w, "Token ID is required", http.StatusBadRequest)
		return
	}

	var token Token
	err := json.NewDecoder(r.Body).Decode(&token)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		log.Printf("Error decoding token data: %v", err)
		return
	}

	token.ID = tokenID
	err = h.Storage.SaveToken(&token)
	if err != nil {
		http.Error(w, "Failed to update token", http.StatusInternalServerError)
		log.Printf("Failed to update token: %v", err)
		return
	}

	json.NewEncoder(w).Encode(token)
	log.Printf("Token updated with ID: %s", token.ID)
}

// DeleteToken handles requests to delete a token.
func (h *TokenHandler) DeleteToken(w http.ResponseWriter, r *http.Request) {
	tokenID := r.URL.Query().Get("id")
	if tokenID == "" {
		http.Error(w, "Token ID is required", http.StatusBadRequest)
		return
	}

	err := h.Storage.DeleteToken(tokenID)
	if err != nil {
		http.Error(w, "Failed to delete token", http.StatusInternalServerError)
		log.Printf("Failed to delete token: %v", err)
		return
	}

	w.WriteHeader(http.StatusOK)
	log.Printf("Token deleted with ID: %s", tokenID)
}

// RegisterRoutes registers the SYN70 token-related HTTP handlers.
func (h *TokenHandler) RegisterRoutes(router *http.ServeMux) {
	router.HandleFunc("/api/tokens/create", h.CreateToken)
	router.HandleFunc("/api/tokens/get", h.GetToken)
	router.HandleFunc("/api/tokens/update", h.UpdateToken)
	router.HandleFunc("/api/tokens/delete", h.DeleteToken)
	log.Println("SYN70 token routes registered")
}
