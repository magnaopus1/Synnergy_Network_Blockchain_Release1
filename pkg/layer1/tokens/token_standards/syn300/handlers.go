package syn300

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"log"
)

// TokenHandler encapsulates methods for handling web requests related to governance tokens.
type TokenHandler struct {
	Storage *TokenStorage
}

// NewTokenHandler creates a new instance of TokenHandler.
func NewTokenHandler(storage *TokenStorage) *TokenHandler {
	return &TokenHandler{Storage: storage}
}

// RegisterRoutes registers the HTTP routes for token operations.
func (h *TokenHandler) RegisterRoutes(router *mux.Router) {
	router.HandleFunc("/token/balance/{address}", h.GetBalance).Methods("GET")
	router.HandleFunc("/token/transfer", h.TransferToken).Methods("POST")
	router.HandleFunc("/token/vote", h.CastVote).Methods("POST")
	log.Println("Token API routes registered.")
}

// GetBalance handles requests for retrieving a token balance.
func (h *TokenHandler) GetBalance(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	address := vars["address"]
	
	balance, err := h.Storage.RetrieveTokenBalance(address)
	if err != nil {
		http.Error(w, "Error retrieving balance: "+err.Error(), http.StatusInternalServerError)
		log.Printf("Failed to retrieve balance for %s: %v", address, err)
		return
	}

	response := map[string]interface{}{
		"address": address,
		"balance": balance,
	}
	json.NewEncoder(w).Encode(response)
	log.Printf("Balance retrieved for %s: %d", address, balance)
}

// TransferToken handles requests for transferring tokens between addresses.
func (h *TokenHandler) TransferToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		From    string `json:"from"`
		To      string `json:"to"`
		Amount  uint64 `json:"amount"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		log.Println("Invalid token transfer request:", err)
		return
	}

	if err := h.Storage.TransferToken(req.From, req.To, req.Amount); err != nil {
		http.Error(w, "Error transferring tokens: "+err.Error(), http.StatusInternalServerError)
		log.Printf("Failed to transfer %d tokens from %s to %s: %v", req.Amount, req.From, req.To, err)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
	log.Printf("Transferred %d tokens from %s to %s successfully", req.Amount, req.From, req.To)
}

// CastVote handles requests for casting votes in governance decisions.
func (h *TokenHandler) CastVote(w http.ResponseWriter, r *http.Request) {
	var vote struct {
		VoterID string `json:"voter_id"`
		ProposalID int `json:"proposal_id"`
		Vote bool `json:"vote"`
	}
	if err := json.NewDecoder(r.Body).Decode(&vote); err != nil {
		http.Error(w, "Invalid vote request", http.StatusBadRequest)
		log.Println("Invalid vote request:", err)
		return
	}

	if err := h.Storage.RecordVote(vote.VoterID, vote.ProposalID, vote.Vote); err != nil {
		http.Error(w, "Error recording vote: "+err.Error(), http.StatusInternalServerError)
		log.Printf("Failed to record vote for proposal %d by voter %s: %v", vote.ProposalID, vote.VoterID, err)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "vote recorded"})
	log.Printf("Vote by %s on proposal %d recorded successfully", vote.VoterID, vote.ProposalID)
}
