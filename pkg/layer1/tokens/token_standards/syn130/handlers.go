package syn130

import (
	"encoding/json"
	"net/http"
	"log"
	"database/sql"
	"github.com/gorilla/mux"
)

// TokenHandler manages HTTP requests for asset tokens.
type TokenHandler struct {
	Storage *Storage
}

// NewTokenHandler creates a new handler for asset tokens.
func NewTokenHandler(db *sql.DB) *TokenHandler {
	return &TokenHandler{
		Storage: NewStorage(db),
	}
}

// RegisterRoutes registers the HTTP routes for asset token operations.
func (h *TokenHandler) RegisterRoutes(router *mux.Router) {
	router.HandleFunc("/tokens", h.CreateToken).Methods("POST")
	router.HandleFunc("/tokens/{tokenID}", h.GetToken).Methods("GET")
	router.HandleFunc("/tokens/{tokenID}", h.UpdateToken).Methods("PUT")
	router.HandleFunc("/tokens/{tokenID}", h.DeleteToken).Methods("DELETE")
	log.Println("Token routes registered successfully.")
}

// CreateToken handles creating a new asset token.
func (h *TokenHandler) CreateToken(w http.ResponseWriter, r *http.Request) {
	var token AssetToken
	if err := json.NewDecoder(r.Body).Decode(&token); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		log.Printf("Failed to decode token data: %v", err)
		return
	}
	
	if err := h.Storage.SaveToken(&token); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	log.Printf("New token created with ID %s by owner %s", token.TokenID, token.Owner)
}

// GetToken handles retrieving an asset token by its ID.
func (h *TokenHandler) GetToken(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tokenID := vars["tokenID"]
	token, err := h.Storage.GetToken(tokenID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if token == nil {
		http.NotFound(w, r)
		return
	}

	if err := json.NewEncoder(w).Encode(token); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
	log.Printf("Token retrieved: %s", token.TokenID)
}

// UpdateToken handles updating an existing asset token.
func (h *TokenHandler) UpdateToken(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tokenID := vars["tokenID"]
	var token AssetToken
	if err := json.NewDecoder(r.Body).Decode(&token); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	token.TokenID = tokenID // Ensure the ID is set correctly from the URL
	if err := h.Storage.UpdateToken(&token); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	log.Printf("Token updated: %s", token.TokenID)
}

// DeleteToken handles deleting an asset token.
func (h *TokenHandler) DeleteToken(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tokenID := vars["tokenID"]
	if err := h.Storage.DeleteToken(tokenID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
	log.Printf("Token deleted: %s", tokenID)
}
