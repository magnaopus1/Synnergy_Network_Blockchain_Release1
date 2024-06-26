package syn1000

import (
	"encoding/json"
	"net/http"
	"strconv"
	"log"
	"synthron-blockchain/pkg/common"
)

// StablecoinHandler provides HTTP API endpoints for managing stablecoins.
type StablecoinHandler struct {
	Storage *TokenStorage
}

// NewStablecoinHandler creates a new handler with the necessary storage.
func NewStablecoinHandler(storage *TokenStorage) *StablecoinHandler {
	return &StablecoinHandler{Storage: storage}
}

// HandleMint processes requests to mint new stablecoins.
func (h *StablecoinHandler) HandleMint(w http.ResponseWriter, r *http.Request) {
	amount, err := strconv.ParseFloat(r.FormValue("amount"), 64)
	if err != nil || amount <= 0 {
		http.Error(w, "Invalid amount", http.StatusBadRequest)
		log.Printf("Invalid mint amount provided: %v", err)
		return
	}

	owner := r.FormValue("owner")
	if owner == "" {
		http.Error(w, "Owner required", http.StatusBadRequest)
		return
	}

	peg := r.FormValue("peg")
	if peg == "" {
		http.Error(w, "Peg required", http.StatusBadRequest)
		return
	}

	tokenID := GenerateTokenID(peg, owner)
	token := NewStablecoin(tokenID, owner, peg)
	token.Mint(amount)
	if err := h.Storage.StoreToken(token); err != nil {
		http.Error(w, "Failed to mint stablecoin", http.StatusInternalServerError)
		log.Printf("Failed to mint stablecoin: %v", err)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(token)
	log.Printf("Minted %f stablecoins to %s", amount, owner)
}

// HandleBurn processes requests to burn stablecoins.
func (h *StablecoinHandler) HandleBurn(w http.ResponseWriter, r *http.Request) {
	amount, err := strconv.ParseFloat(r.FormValue("amount"), 64)
	if err != nil || amount <= 0 {
		http.Error(w, "Invalid amount", http.StatusBadRequest)
		return
	}

	tokenID := r.FormValue("token_id")
	token, err := h.Storage.RetrieveToken(tokenID)
	if err != nil {
		http.Error(w, "Token not found", http.StatusNotFound)
		return
	}

	token.Burn(amount)
	if err := h.Storage.UpdateToken(token); err != nil {
		http.Error(w, "Failed to burn stablecoins", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(token)
	log.Printf("Burned %f stablecoins from %s", amount, tokenID)
}

// HandleAudit processes audit requests for stablecoins.
func (h *StablecoinHandler) HandleAudit(w http.ResponseWriter, r *http.Request) {
	tokenID := r.FormValue("token_id")
	outcome := r.FormValue("outcome")

	token, err := h.Storage.RetrieveToken(tokenID)
	if err != nil {
		http.Error(w, "Token not found", http.StatusNotFound)
		return
	}

	token.ConductAudit(outcome)
	if err := h.Storage.UpdateToken(token); err != nil {
		http.Error(w, "Failed to update audit", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(token)
	log.Printf("Audit conducted for token %s with outcome %s", tokenID, outcome)
}

// RegisterRoutes sets up the routing for stablecoin operations.
func (h *StablecoinHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/stablecoin/mint", h.HandleMint)
	mux.HandleFunc("/stablecoin/burn", h.HandleBurn)
	mux.HandleFunc("/stablecoin/audit", h.HandleAudit)
}
