package syn1155

import (
	"errors"
	"fmt"
	"log"
	"net/http"
)

// Handler manages the HTTP handlers for token operations.
type Handler struct {
	storage *TokenStorage
}

// NewHandler creates a new handler with a reference to token storage.
func NewHandler(storage *TokenStorage) *Handler {
	return &Handler{storage: storage}
}

// BatchTransferHandler handles the HTTP request for batch transferring tokens.
func (h *Handler) BatchTransferHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Example payload handling
	from := r.FormValue("from")
	to := r.FormValue("to")
	ids := []string{r.FormValue("tokenIDs")} // Simplified; would actually need to parse a list of IDs
	amounts := []uint64{100} // Simplified; would need to parse amounts corresponding to token IDs

	err := h.storage.BatchTransfer(from, to, ids, amounts)
	if err != nil {
		log.Printf("Error in batch transfer: %v", err)
		http.Error(w, fmt.Sprintf("Failed to transfer: %v", err), http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "Batch transfer successful")
	log.Println("Batch transfer processed successfully")
}

// BatchBalanceHandler provides the balance of multiple tokens for a user.
func (h *Handler) BatchBalanceHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	owner := r.URL.Query().Get("owner")
	ids := []string{r.URL.Query().Get("tokenIDs")} // Simplified parsing

	balances := h.storage.BatchBalance(owner, ids)
	balanceStr, err := json.Marshal(balances)
	if err != nil {
		log.Printf("Error marshaling balances: %v", err)
		http.Error(w, "Failed to retrieve balances", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(balanceStr)
	log.Printf("Returned balances for %s", owner)
}

// ApproveAllHandler handles requests to set or revoke approval for all tokens.
func (h *Handler) ApproveAllHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	operator := r.FormValue("operator")
	approved := r.FormValue("approved") == "true"

	h.storage.SetApprovalForAll(operator, approved)

	log.Printf("Approval for all tokens set to %v for operator %s", approved, operator)
	fmt.Fprintf(w, "Set approval for all: %v", approved)
}

// RegisterRoutes sets up the routing for the token handlers.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/token/batchTransfer", h.BatchTransferHandler)
	mux.HandleFunc("/api/token/batchBalance", h.BatchBalanceHandler)
	mux.HandleFunc("/api/token/approveAll", h.ApproveAllHandler)
	log.Println("Token routes registered successfully")
}
