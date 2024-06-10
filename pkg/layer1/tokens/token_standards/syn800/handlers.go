package syn800

import (
	"encoding/json" // Re-imported to fix the undefined json error
	"errors"
	"log"
	"net/http"
	"sync"
)

// TokenRegistry manages tokens within the syn800 package.
type TokenRegistry struct {
	Tokens map[string]*Token
	mutex  sync.Mutex
}

func NewTokenRegistry() *TokenRegistry {
	return &TokenRegistry{
		Tokens: make(map[string]*Token),
	}
}

func (tr *TokenRegistry) CreateToken(owner string, asset AssetDetails) *Token {
	tr.mutex.Lock()
	defer tr.mutex.Unlock()
	token := NewToken(GenerateTokenID(asset), owner, asset)
	tr.Tokens[token.ID] = token
	return token
}

func (tr *TokenRegistry) TransferShares(tokenID, newOwner string, percentage float64) error {
	tr.mutex.Lock()
	defer tr.mutex.Unlock()
	token, exists := tr.Tokens[tokenID]
	if !exists {
		return logError("Token not found")
	}
	return token.TransferShares(token.Owner, newOwner, percentage)
}

func (tr *TokenRegistry) GetToken(tokenID string) (*Token, error) {
	tr.mutex.Lock()
	defer tr.mutex.Unlock()
	token, exists := tr.Tokens[tokenID]
	if !exists {
		return nil, logError("Token not found")
	}
	return token, nil
}

// TokenHandler manages HTTP requests for SYN800 tokens.
type TokenHandler struct {
	registry *TokenRegistry
	mutex    sync.Mutex
}

func NewTokenHandler(registry *TokenRegistry) *TokenHandler {
	return &TokenHandler{
		registry: registry,
	}
}

func (h *TokenHandler) CreateTokenHTTP(w http.ResponseWriter, r *http.Request) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	var data struct {
		Owner string        `json:"owner"`
		Asset AssetDetails  `json:"asset"`
	}
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	token := h.registry.CreateToken(data.Owner, data.Asset)
	response, err := json.Marshal(token)
	if err != nil {
		http.Error(w, "Failed to marshal token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write(response)
}

func (h *TokenHandler) TransferTokenHTTP(w http.ResponseWriter, r *http.Request) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	var data struct {
		TokenID    string  `json:"token_id"`
		NewOwner   string  `json:"new_owner"`
		Percentage float64 `json:"percentage"`
	}
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.registry.TransferShares(data.TokenID, data.NewOwner, data.Percentage); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (h *TokenHandler) GetTokenHTTP(w http.ResponseWriter, r *http.Request) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	tokenID := r.URL.Query().Get("token_id")
	token, err := h.registry.GetToken(tokenID)
	if err != nil {
		http.Error(w, "Token not found", http.StatusNotFound)
		return
	}

	response, err := json.Marshal(token)
	if err != nil {
		http.Error(w, "Failed to marshal token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(response)
}

func (h *TokenHandler) RegisterHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/tokens/create", h.CreateTokenHTTP)
	mux.HandleFunc("/tokens/transfer", h.TransferTokenHTTP)
	mux.HandleFunc("/tokens/get", h.GetTokenHTTP)
	log.Println("Token handlers registered.")
}

func logError(msg string) error {
	log.Println(msg)
	return errors.New(msg)
}
