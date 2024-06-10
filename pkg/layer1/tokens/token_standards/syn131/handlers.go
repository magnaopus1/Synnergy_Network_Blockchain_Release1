package syn131

import (
	"encoding/json"
	"net/http"
	"log"
)

// TokenHandler encapsulates the logic for handling token requests.
type TokenHandler struct {
	Storage *TokenStorage
}

// NewTokenHandler creates a new handler with the given storage.
func NewTokenHandler(storage *TokenStorage) *TokenHandler {
	return &TokenHandler{Storage: storage}
}

// RegisterRoutes registers the HTTP routes for token operations.
func (h *TokenHandler) RegisterRoutes(router *http.ServeMux) {
	router.HandleFunc("/token/create", h.CreateToken)
	router.HandleFunc("/token/get", h.GetToken)
	router.HandleFunc("/token/update", h.UpdateToken)
	router.HandleFunc("/token/delete", h.DeleteToken)
	log.Println("Token routes registered successfully.")
}

// CreateToken handles the creation of a new token.
func (h *TokenHandler) CreateToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var token Token
	if err := json.NewDecoder(r.Body).Decode(&token); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		log.Printf("Failed to decode token data: %v", err)
		return
	}

	if err := h.Storage.SaveToken(&token); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Printf("Failed to create token: %v", err)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(token)
	log.Printf("Token created successfully: %+v", token)
}

// GetToken handles retrieving a token by ID.
func (h *TokenHandler) GetToken(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "Token ID is required", http.StatusBadRequest)
		return
	}

	token, err := h.Storage.FetchToken(id)
	if err != nil {
		http.Error(w, "Token not found", http.StatusNotFound)
		log.Printf("Failed to retrieve token: %v", err)
		return
	}

	json.NewEncoder(w).Encode(token)
	log.Printf("Token retrieved successfully: %+v", token)
}

// UpdateToken handles the update of an existing token.
func (h *TokenHandler) UpdateToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var token Token
	if err := json.NewDecoder(r.Body).Decode(&token); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		log.Printf("Failed to decode token data: %v", err)
		return
	}

	if err := h.Storage.SaveToken(&token); err != nil {
		http.Error(w, "Failed to update token", http.StatusInternalServerError)
		log.Printf("Failed to update token: %v", err)
		return
	}

	json.NewEncoder(w).Encode(token)
	log.Printf("Token updated successfully: %+v", token)
}

// DeleteToken handles the deletion of a token.
func (h *TokenHandler) DeleteToken(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "Token ID is required", http.StatusBadRequest)
		return
	}

	if err := h.Storage.DeleteToken(id); err != nil {
		http.Error(w, "Failed to delete token", http.StatusInternalServerError)
		log.Printf("Failed to delete token: %v", err)
		return
	}

	w.WriteHeader(http.StatusOK)
	log.Printf("Token deleted successfully: %s", id)
}
