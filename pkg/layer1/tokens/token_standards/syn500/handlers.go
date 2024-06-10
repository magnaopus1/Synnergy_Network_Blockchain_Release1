package syn500

import (
	"encoding/json"
	"net/http"
	"log"

	"synthron-blockchain/pkg/common"
)

// Handlers struct will encapsulate methods for handling HTTP requests related to SYN500 tokens.
type Handlers struct {
	Storage *Storage
}

// NewHandlers creates a new Handlers instance with the given storage.
func NewHandlers(storage *Storage) *Handlers {
	return &Handlers{Storage: storage}
}

// CreateToken handles POST requests to create a new utility token.
func (h *Handlers) CreateToken(w http.ResponseWriter, r *http.Request) {
	var token Token
	err := json.NewDecoder(r.Body).Decode(&token)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		log.Printf("Failed to decode token creation request: %v", err)
		return
	}

	err = h.Storage.SaveToken(&token)
	if err != nil {
		http.Error(w, "Failed to save token", http.StatusInternalServerError)
		log.Printf("Error saving token: %v", err)
		return
	}

	response, err := json.Marshal(token)
	if err != nil {
		http.Error(w, "Failed to encode token response", http.StatusInternalServerError)
		log.Printf("Failed to encode token response: %v", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write(response)
	log.Printf("Created new utility token: %+v", token)
}

// GetToken handles GET requests to fetch a utility token by ID.
func (h *Handlers) GetToken(w http.ResponseWriter, r *http.Request) {
	tokenID := r.URL.Query().Get("id")
	if tokenID == "" {
		http.Error(w, "Token ID is required", http.StatusBadRequest)
		log.Println("Token ID not provided in request")
		return
	}

	token, err := h.Storage.GetToken(tokenID)
	if err != nil {
		http.Error(w, "Error fetching token", http.StatusInternalServerError)
		log.Printf("Error fetching token %s: %v", tokenID, err)
		return
	}

	if token == nil {
		http.Error(w, "Token not found", http.StatusNotFound)
		log.Printf("Token with ID %s not found", tokenID)
		return
	}

	response, err := json.Marshal(token)
	if err != nil {
		http.Error(w, "Failed to encode token response", http.StatusInternalServerError)
		log.Printf("Failed to encode token response: %v", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
	log.Printf("Retrieved utility token: %+v", token)
}

// RegisterRoutes sets up the HTTP routes for the utility token handlers.
func (h *Handlers) RegisterRoutes(router *common.Router) {
	router.HandleFunc("/token/create", h.CreateToken).Methods("POST")
	router.HandleFunc("/token/get", h.GetToken).Methods("GET")
	log.Println("Utility token routes registered")
}
