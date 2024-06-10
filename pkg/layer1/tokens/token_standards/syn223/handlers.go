package syn223

import (
	"encoding/json"
	"net/http"
	"strconv"
	"log"

	"synthron-blockchain/pkg/common"
)

// TokenHandler provides HTTP API handlers for token operations.
type TokenHandler struct {
	TokenService *TokenService // The business logic layer for token operations
}

// NewTokenHandler initializes a new TokenHandler with dependencies.
func NewTokenHandler(service *TokenService) *TokenHandler {
	return &TokenHandler{
		TokenService: service,
	}
}

// GetBalance is an HTTP handler for retrieving a token balance.
func (h *TokenHandler) GetBalance(w http.ResponseWriter, r *http.Request) {
	address := r.URL.Query().Get("address")
	if address == "" {
		http.Error(w, "Address parameter is missing", http.StatusBadRequest)
		return
	}

	balance, err := h.TokenService.GetBalance(address)
	if err != nil {
		log.Printf("Error getting balance for address %s: %v", address, err)
		http.Error(w, "Failed to get balance", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"address": address,
		"balance": balance,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
	log.Printf("Balance retrieved for address %s: %d", address, balance)
}

// TransferTokens is an HTTP handler for transferring tokens between addresses.
func (h *TokenHandler) TransferTokens(w http.ResponseWriter, r *http.Request) {
	var req struct {
		From    string `json:"from"`
		To      string `json:"to"`
		Amount  uint64 `json:"amount"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	err := h.TokenService.Transfer(req.From, req.To, req.Amount)
	if err != nil {
		log.Printf("Error transferring %d tokens from %s to %s: %v", req.Amount, req.From, req.To, err)
		http.Error(w, "Failed to transfer tokens", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	log.Printf("Transferred %d tokens from %s to %s successfully", req.Amount, req.From, req.To)
}

// SetAllowance is an HTTP handler that sets the allowance for a spender by the token owner.
func (h *TokenHandler) SetAllowance(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Owner   string `json:"owner"`
		Spender string `json:"spender"`
		Amount  uint64 `json:"amount"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	err := h.TokenService.SetAllowance(req.Owner, req.Spender, req.Amount)
	if err != nil {
		log.Printf("Error setting allowance for spender %s by owner %s: %v", req.Spender, req.Owner, err)
		http.Error(w, "Failed to set allowance", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	log.Printf("Allowance set for spender %s by owner %s: %d", req.Spender, req.Owner, req.Amount)
}

// RegisterHandlers registers all token-related HTTP handlers to a router.
func (h *TokenHandler) RegisterHandlers(router *http.ServeMux) {
	router.HandleFunc("/api/token/balance", h.GetBalance)
	router.HandleFunc("/api/token/transfer", h.TransferTokens)
	router.HandleFunc("/api/token/allowance", h.SetAllowance)
	log.Println("SYN223 token handlers registered.")
}
