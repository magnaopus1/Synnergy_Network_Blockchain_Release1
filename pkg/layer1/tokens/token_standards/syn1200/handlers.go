package syn1200

import (
	"encoding/json"
	"net/http"
	"time"
	"log"
	"synthron-blockchain/pkg/common"
)

// TokenHandler manages HTTP endpoints for token operations.
type TokenHandler struct {
	Storage *TokenStorage
}

// NewTokenHandler initializes a new handler with the necessary storage.
func NewTokenHandler(storage *TokenStorage) *TokenHandler {
	return &TokenHandler{
		Storage: storage,
	}
}

// HandleCreateToken processes requests to create a new interoperable token.
func (h *TokenHandler) HandleCreateToken(w http.ResponseWriter, r *http.Request) {
	var request struct {
		ID            string   `json:"id"`
		Owner         string   `json:"owner"`
		InitialSupply uint64   `json:"initial_supply"`
		LinkedChains  []string `json:"linked_chains"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	token := NewInteroperableToken(request.ID, request.Owner, request.InitialSupply, request.LinkedChains)
	if err := h.Storage.SaveToken(token); err != nil {
		http.Error(w, "Failed to save token", http.StatusInternalServerError)
		log.Printf("Error saving token: %v", err)
		return
	}

	response, _ := json.Marshal(token)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write(response)
	log.Printf("New token created: %s by %s", token.ID, token.Owner)
}

// HandleLinkBlockchain processes requests to link a new blockchain to an existing token.
func (h *TokenHandler) HandleLinkBlockchain(w http.ResponseWriter, r *http.Request) {
	var request struct {
		TokenID     string `json:"token_id"`
		ChainName   string `json:"chain_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	token, err := h.Storage.GetToken(request.TokenID)
	if err != nil {
		http.Error(w, "Token not found", http.StatusNotFound)
		return
	}

	if err := token.LinkBlockchain(request.ChainName); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := h.Storage.SaveToken(token); err != nil {
		http.Error(w, "Failed to update token", http.StatusInternalServerError)
		return
	}

	log.Printf("Blockchain %s linked to token %s", request.ChainName, request.TokenID)
	w.WriteHeader(http.StatusOK)
}

// HandleInitiateSwap processes requests to initiate an atomic swap.
func (h *TokenHandler) HandleInitiateSwap(w http.ResponseWriter, r *http.Request) {
	var request struct {
		TokenID     string `json:"token_id"`
		PartnerChain string `json:"partner_chain"`
		SwapID      string `json:"swap_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	token, err := h.Storage.GetToken(request.TokenID)
	if err != nil {
		http.Error(w, "Token not found", http.StatusNotFound)
		return
	}

	if err := token.InitiateAtomicSwap(request.PartnerChain, request.SwapID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := h.Storage.SaveToken(token); err != nil {
		http.Error(w, "Failed to update token", http.StatusInternalServerError)
		return
	}

	log.Printf("Atomic swap initiated for token %s with swap ID %s on chain %s", request.TokenID, request.SwapID, request.PartnerChain)
	w.WriteHeader(http.StatusOK)
}

// SetupRoutes sets up the routes for the HTTP server.
func (h *TokenHandler) SetupRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/create_token", h.HandleCreateToken)
	mux.HandleFunc("/link_blockchain", h.HandleLinkBlockchain)
	mux.HandleFunc("/initiate_swap", h.HandleInitiateSwap)
}

// Example of setting up and using the HTTP handlers.
func ExampleHTTPSetup() {
	db := common.SetupDatabase() // Placeholder for database setup
	storage := NewTokenStorage(db)
	handler := NewTokenHandler(storage)

	mux := http.NewServeMux()
	handler.SetupRoutes(mux)

	log.Println("Server starting...")
	http.ListenAndServe(":8080", mux)
}
