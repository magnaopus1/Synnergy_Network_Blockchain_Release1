package syn722

import (
	"encoding/json"
	"net/http"
	"sync"
	"log"
	"errors"
)

// TokenRegistry is a mock structure assumed to manage tokens.
type TokenRegistry struct {
	Tokens map[string]*Token
	mutex  sync.Mutex
}

func NewTokenRegistry() *TokenRegistry {
	return &TokenRegistry{
		Tokens: make(map[string]*Token),
	}
}

func (tr *TokenRegistry) CreateToken(owner string, mode Mode, quantity uint64, metadata map[string]string) *Token {
	tr.mutex.Lock()
	defer tr.mutex.Unlock()
	token := NewToken(GenerateTokenID(owner, mode), owner, mode, quantity, metadata)
	tr.Tokens[token.ID] = token
	return token
}

func (tr *TokenRegistry) TransferToken(tokenID, newOwner string, quantity uint64) error {
	tr.mutex.Lock()
	defer tr.mutex.Unlock()
	token, exists := tr.Tokens[tokenID]
	if !exists {
		return logError("Token not found")
	}
	return token.Transfer(newOwner, quantity)
}

func (tr *TokenRegistry) ChangeMode(tokenID string, newMode Mode) error {
	tr.mutex.Lock()
	defer tr.mutex.Unlock()
	token, exists := tr.Tokens[tokenID]
	if !exists {
		return logError("Token not found")
	}
	return token.ChangeMode(newMode)
}

// TokenHandler handles HTTP requests related to SYN722 tokens.
type TokenHandler struct {
	Registry *TokenRegistry
	mutex    sync.Mutex
}

// NewTokenHandler creates a new handler for SYN722 tokens.
func NewTokenHandler(registry *TokenRegistry) *TokenHandler {
	return &TokenHandler{
		Registry: registry,
	}
}

// RegisterHandlers sets up the routing for SYN722 token related operations.
func (h *TokenHandler) RegisterHandlers(router *http.ServeMux) {
	router.HandleFunc("/token/create", h.CreateTokenHTTP)
	router.HandleFunc("/token/transfer", h.TransferTokenHTTP)
	router.HandleFunc("/token/changeMode", h.ChangeTokenModeHTTP)
	log.Println("SYN722 token routes registered.")
}

/// CreateTokenHTTP handles the HTTP request to create a new SYN722 token.
func (h *TokenHandler) CreateTokenHTTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Owner    string            `json:"owner"`
		Mode     Mode              `json:"mode"`
		Quantity uint64            `json:"quantity"`
		Metadata map[string]string `json:"metadata"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		log.Printf("Failed to decode create token request: %v", err)
		return
	}

	token := h.Registry.CreateToken(req.Owner, req.Mode, req.Quantity, req.Metadata)
	if token == nil {
		http.Error(w, "Failed to create token", http.StatusInternalServerError)
		return
	}

	response, err := json.Marshal(token)
	if err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		log.Printf("Failed to encode token response: %v", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write(response)
	log.Printf("Token created successfully: %s", token.ID)
}

// TransferTokenHTTP handles the HTTP request to transfer a SYN722 token.
func (h *TokenHandler) TransferTokenHTTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TokenID    string `json:"token_id"`
		NewOwner   string `json:"new_owner"`
		Quantity   uint64 `json:"quantity"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		log.Printf("Failed to decode transfer token request: %v", err)
		return
	}

	err := h.Registry.TransferToken(req.TokenID, req.NewOwner, req.Quantity)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Printf("Failed to transfer token: %v", err)
		return
	}

	w.WriteHeader(http.StatusOK)
	log.Printf("Token %s transferred to %s", req.TokenID, req.NewOwner)
}

// ChangeTokenModeHTTP handles the HTTP request to change a token's mode.
func (h *TokenHandler) ChangeTokenModeHTTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TokenID string `json:"token_id"`
		NewMode Mode   `json:"new_mode"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		log.Printf("Failed to decode change mode request: %v", err)
		return
	}

	err := h.Registry.ChangeMode(req.TokenID, req.NewMode)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Printf("Failed to change token mode: %v", err)
		return
	}

	w.WriteHeader(http.StatusOK)
	log.Printf("Token %s mode changed to %v", req.TokenID, req.NewMode)
}

// Helper function to log errors and return an error object.
func logError(msg string) error {
	log.Println(msg)
	return errors.New(msg)
}
