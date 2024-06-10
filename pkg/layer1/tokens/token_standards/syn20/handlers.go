package syn20

import (
	"encoding/json"
	"net/http"
	"strconv"

	"synthron-blockchain/pkg/common"
)

// TokenAPI provides handlers for managing SYN20 tokens.
type TokenAPI struct {
	Token *Token // Token instance for SYN20 token logic.
}

// NewTokenAPI creates a new TokenAPI with the given Token instance.
func NewTokenAPI(token *Token) *TokenAPI {
	return &TokenAPI{Token: token}
}

// RegisterRoutes registers the token-related HTTP handlers.
func (api *TokenAPI) RegisterRoutes(router *http.ServeMux) {
	router.HandleFunc("/api/token/balance", api.GetBalance)
	router.HandleFunc("/api/token/transfer", api.Transfer)
	router.HandleFunc("/api/token/allowance", api.SetAllowance)
}

// GetBalance handles the balance query for an address.
func (api *TokenAPI) GetBalance(w http.ResponseWriter, r *http.Request) {
	address := r.URL.Query().Get("address")
	if address == "" {
		http.Error(w, "Address parameter is missing", http.StatusBadRequest)
		return
	}

	balance, err := api.Token.GetBalance(address)
	if err != nil {
		http.Error(w, "Failed to get balance: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"address": address,
		"balance": balance,
	}
	json.NewEncoder(w).Encode(response)
	log.Printf("Balance queried for address %s: %d", address, balance)
}

// Transfer handles requests to transfer tokens between addresses.
func (api *TokenAPI) Transfer(w http.ResponseWriter, r *http.Request) {
	var req struct {
		From   string  `json:"from"`
		To     string  `json:"to"`
		Amount float64 `json:"amount"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	err := api.Token.Transfer(req.From, req.To, req.Amount)
	if err != nil {
		http.Error(w, "Failed to transfer tokens: "+err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("Transfer from %s to %s of amount %f completed successfully", req.From, req.To, req.Amount)
	w.WriteHeader(http.StatusOK)
}

// SetAllowance handles requests to set allowances for a spender by an owner.
func (api *TokenAPI) SetAllowance(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Owner   string  `json:"owner"`
		Spender string  `json:"spender"`
		Amount  float64 `json:"amount"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	err := api.Token.SetAllowance(req.Owner, req.Spender, req.Amount)
	if err != nil {
		http.Error(w, "Failed to set allowance: "+err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("Allowance set by %s for %s of amount %f", req.Owner, req.Spender, req.Amount)
	w.WriteHeader(http.StatusOK)
}
