package syn2500

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
)

// Handler holds dependencies for the HTTP server handlers
type Handler struct {
	Storage *Storage
}

// NewHandler initializes a new handler with the given storage
func NewHandler(storage *Storage) *Handler {
	return &Handler{
		Storage: storage,
	}
}

// RegisterRoutes registers the API routes with the provided router
func (h *Handler) RegisterRoutes(router *mux.Router) {
	router.HandleFunc("/tokens/{daoID}", h.ListDAOTokens).Methods("GET")
	router.HandleFunc("/token/{tokenID}", h.GetToken).Methods("GET")
	router.HandleFunc("/token", h.IssueToken).Methods("POST")
	router.HandleFunc("/token/{tokenID}", h.TransferToken).Methods("PUT")
	router.HandleFunc("/token/{tokenID}/deactivate", h.DeactivateToken).Methods("POST")
}

// ListDAOTokens handles requests to list all tokens for a specific DAO
func (h *Handler) ListDAOTokens(w http.ResponseWriter, r *http.Request) {
	daoID := mux.Vars(r)["daoID"]
	tokens, err := h.Storage.GetAllTokens(daoID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(tokens)
}

// GetToken handles requests to retrieve a specific token
func (h *Handler) GetToken(w http.ResponseWriter, r *http.Request) {
	tokenID := mux.Vars(r)["tokenID"]
	token, err := h.Storage.GetToken(tokenID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(token)
}

// IssueToken handles requests to issue a new token
func (h *Handler) IssueToken(w http.ResponseWriter, r *http.Request) {
	var token DAOToken
	if err := json.NewDecoder(r.Body).Decode(&token); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if err := h.Storage.AddToken(token); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(token)
}

// TransferToken handles requests to transfer a token to a new owner
func (h *Handler) TransferToken(w http.ResponseWriter, r *http.Request) {
	tokenID := mux.Vars(r)["tokenID"]
	newOwner := r.URL.Query().Get("newOwner")
	if newOwner == "" {
		http.Error(w, "New owner must be specified", http.StatusBadRequest)
		return
	}
	if err := h.Storage.TransferOwnership(tokenID, newOwner); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// DeactivateToken handles requests to deactivate a token
func (h *Handler) DeactivateToken(w http.ResponseWriter, r *http.Request) {
	tokenID := mux.Vars(r)["tokenID"]
	if err := h.Storage.DeactivateToken(tokenID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

