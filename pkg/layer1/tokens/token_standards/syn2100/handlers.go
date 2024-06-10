package syn2100

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
)

// Handlers struct encapsulates dependencies for request handlers.
type Handlers struct {
	Ledger *SupplyChainLedger
}

// NewHandlers creates an instance of Handlers.
func NewHandlers(ledger *SupplyChainLedger) *Handlers {
	return &Handlers{Ledger: ledger}
}

// RegisterRoutes registers the API routes with the provided router.
func (h *Handlers) RegisterRoutes(router *mux.Router) {
	router.HandleFunc("/api/tokens/issue", h.IssueTokenHandler).Methods("POST")
	router.HandleFunc("/api/tokens/{tokenID}", h.GetTokenHandler).Methods("GET")
	router.HandleFunc("/api/tokens/{tokenID}/transfer", h.TransferTokenHandler).Methods("POST")
	router.HandleFunc("/api/tokens/{tokenID}/redeem", h.RedeemTokenHandler).Methods("POST")
	router.HandleFunc("/api/owners/{ownerID}/tokens", h.ListTokensByOwnerHandler).Methods("GET")
}

// IssueTokenHandler handles requests for issuing a new token.
func (h *Handlers) IssueTokenHandler(w http.ResponseWriter, r *http.Request) {
	var doc FinancialDocument
	if err := json.NewDecoder(r.Body).Decode(&doc); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	token, err := h.Ledger.IssueToken(doc, doc.Recipient)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(token)
}

// GetTokenHandler retrieves a specific token by its ID.
func (h *Handlers) GetTokenHandler(w http.ResponseWriter, r *http.Request) {
	tokenID := mux.Vars(r)["tokenID"]
	token, err := h.Ledger.GetToken(tokenID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(token)
}

// TransferTokenHandler handles the transfer of a token from one owner to another.
func (h *Handlers) TransferTokenHandler(w http.ResponseWriter, r *http.Request) {
	tokenID := mux.Vars(r)["tokenID"]
	var transfer struct {
		NewOwner string `json:"newOwner"`
	}
	if err := json.NewDecoder(r.Body).Decode(&transfer); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.Ledger.TransferToken(tokenID, transfer.NewOwner); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// RedeemTokenHandler handles the redemption of a token.
func (h *Handlers) RedeemTokenHandler(w http.ResponseWriter, r *http.Request) {
	tokenID := mux.Vars(r)["tokenID"]
	if err := h.Ledger.RedeemToken(tokenID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// ListTokensByOwnerHandler lists all tokens owned by a specific owner.
func (h *Handlers) ListTokensByOwnerHandler(w http.ResponseWriter, r *http.Request) {
	ownerID := mux.Vars(r)["ownerID"]
	tokens, err := h.Ledger.ListTokensByOwner(ownerID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(tokens)
}
