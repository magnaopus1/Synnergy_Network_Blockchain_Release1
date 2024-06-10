package syn1300

import (
	"encoding/json"
	"net/http"
	"sync"
	"log"
)

// TokenHandler manages HTTP requests related to Supply Chain Tokens.
type TokenHandler struct {
	storage *TokenStorage
	mutex   sync.Mutex
}

// NewTokenHandler creates a new handler with dependency injection for storage.
func NewTokenHandler(storage *TokenStorage) *TokenHandler {
	return &TokenHandler{storage: storage}
}

// CreateTokenHandler handles the creation of new tokens.
func (th *TokenHandler) CreateTokenHandler(w http.ResponseWriter, r *http.Request) {
	th.mutex.Lock()
	defer th.mutex.Unlock()

	decoder := json.NewDecoder(r.Body)
	var t Token
	if err := decoder.Decode(&t); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		log.Printf("CreateTokenHandler: Error decoding request: %v", err)
		return
	}
	defer r.Body.Close()

	if err := th.storage.SaveToken(&t); err != nil {
		http.Error(w, "Failed to create token", http.StatusInternalServerError)
		log.Printf("CreateTokenHandler: Error saving token: %v", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(t)
	log.Printf("CreateTokenHandler: Token created successfully: %s", t.ID)
}

// UpdateTokenHandler handles updating existing tokens for location or status.
func (th *TokenHandler) UpdateTokenHandler(w http.ResponseWriter, r *http.Request) {
	th.mutex.Lock()
	defer th.mutex.Unlock()

	decoder := json.NewDecoder(r.Body)
	var data struct {
		AssetID     string `json:"asset_id"`
		NewLocation string `json:"new_location"`
		NewStatus   string `json:"new_status"`
	}
	if err := decoder.Decode(&data); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		log.Printf("UpdateTokenHandler: Error decoding request: %v", err)
		return
	}
	defer r.Body.Close()

	// Assuming the token ID is passed as a URL parameter
	tokenID := r.URL.Query().Get("token_id")
	if tokenID == "" {
		http.Error(w, "Token ID is required", http.StatusBadRequest)
		return
	}

	if err := th.storage.UpdateTokenAsset(tokenID, data.AssetID, data.NewLocation, data.NewStatus); err != nil {
		http.Error(w, "Failed to update token", http.StatusInternalServerError)
		log.Printf("UpdateTokenHandler: Error updating token: %v", err)
		return
	}

	w.WriteHeader(http.StatusOK)
	log.Printf("UpdateTokenHandler: Token updated successfully: %s", tokenID)
}

// GetTokenDetailsHandler retrieves and sends token details.
func (th *TokenHandler) GetTokenDetailsHandler(w http.ResponseWriter, r *http.Request) {
	tokenID := r.URL.Query().Get("token_id")
	if tokenID == "" {
		http.Error(w, "Token ID is required", http.StatusBadRequest)
		return
	}

	token, err := th.storage.FetchToken(tokenID)
	if err != nil {
		http.Error(w, "Failed to fetch token", http.StatusInternalServerError)
		log.Printf("GetTokenDetailsHandler: Error fetching token: %v", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(token)
	log.Printf("GetTokenDetailsHandler: Token details retrieved: %s", tokenID)
}

// Example of setting up routes for these handlers in an HTTP server.
func ExampleSetupRoutes() {
	storage := NewTokenStorage(nil) // Here you would pass an actual initialized *sql.DB
	handler := NewTokenHandler(storage)

	http.HandleFunc("/create_token", handler.CreateTokenHandler)
	http.HandleFunc("/update_token", handler.UpdateTokenHandler)
	http.HandleFunc("/get_token_details", handler.GetTokenDetailsHandler)

	log.Println("Server started on :8080")
	http.ListenAndServe(":8080", nil)
}
