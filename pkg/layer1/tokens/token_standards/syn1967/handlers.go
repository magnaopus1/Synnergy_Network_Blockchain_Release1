package syn1967

import (
	"encoding/json"
	"net/http"
	"github.com/gorilla/mux"
)

// Handlers struct encapsulates dependencies for request handlers.
type Handlers struct {
	Ledger  *CommodityLedger
	Storage *Storage
}

// NewHandlers initializes a new Handlers struct.
func NewHandlers(ledger *CommodityLedger, storage *Storage) *Handlers {
	return &Handlers{
		Ledger:  ledger,
		Storage: storage,
	}
}

// RegisterRoutes registers the HTTP routes with the router.
func (h *Handlers) RegisterRoutes(router *mux.Router) {
	router.HandleFunc("/api/tokens", h.CreateToken).Methods("POST")
	router.HandleFunc("/api/tokens/{tokenID}", h.GetToken).Methods("GET")
	router.HandleFunc("/api/tokens/{tokenID}", h.DeleteToken).Methods("DELETE")
	router.HandleFunc("/api/tokens/{tokenID}/transfer", h.TransferToken).Methods("POST")
	router.HandleFunc("/api/tokens", h.ListAllTokens).Methods("GET")
}

// CreateToken handles the creation of new commodity tokens.
func (h *Handlers) CreateToken(w http.ResponseWriter, r *http.Request) {
	var token Token
	if err := json.NewDecoder(r.Body).Decode(&token); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.Ledger.IssueToken(token); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := h.Storage.AddToken(token); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(token)
}

// GetToken handles retrieval of a specific token.
func (h *Handlers) GetToken(w http.ResponseWriter, r *http.Request) {
	tokenID := mux.Vars(r)["tokenID"]
	token, err := h.Storage.GetToken(tokenID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(token)
}

// DeleteToken handles the deletion of a token.
func (h *Handlers) DeleteToken(w http.ResponseWriter, r *http.Request) {
	tokenID := mux.Vars(r)["tokenID"]
	if err := h.Storage.DeleteToken(tokenID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// TransferToken handles the transfer of ownership of a token.
func (h *Handlers) TransferToken(w http.ResponseWriter, r *http.Request) {
	tokenID := mux.Vars(r)["tokenID"]
	var transferData struct {
		NewOwner string `json:"newOwner"`
	}
	if err := json.NewDecoder(r.Body).Decode(&transferData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.Ledger.TransferToken(tokenID, transferData.NewOwner); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// ListAllTokens lists all tokens in the ledger.
func (h *Handlers) ListAllTokens(w http.ResponseWriter, r *http.Request) {
	tokens := h.Storage.Tokens
	json.NewEncoder(w).Encode(tokens)
}

