package syn2600

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
)

// Handler handles the HTTP API interface for investor tokens.
type Handler struct {
	Storage *Storage
}

// NewHandler creates a new Handler with the given storage.
func NewHandler(storage *Storage) *Handler {
	return &Handler{
		Storage: storage,
	}
}

// RegisterRoutes registers the API routes to a mux.Router.
func (h *Handler) RegisterRoutes(router *mux.Router) {
	router.HandleFunc("/tokens", h.CreateToken).Methods("POST")
	router.HandleFunc("/tokens/{tokenID}", h.GetToken).Methods("GET")
	router.HandleFunc("/tokens/{tokenID}", h.DeleteToken).Methods("DELETE")
	router.HandleFunc("/tokens/{tokenID}", h.UpdateToken).Methods("PUT")
	router.HandleFunc("/tokens/transfer/{tokenID}", h.TransferToken).Methods("POST")
	router.HandleFunc("/tokens/owner/{owner}", h.ListTokensByOwner).Methods("GET")
}

// CreateToken handles the creation of a new token.
func (h *Handler) CreateToken(w http.ResponseWriter, r *http.Request) {
	var token InvestorToken
	if err := json.NewDecoder(r.Body).Decode(&token); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.Storage.SaveToken(token); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(token)
}

// GetToken handles the retrieval of a token.
func (h *Handler) GetToken(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tokenID := vars["tokenID"]

	token, err := h.Storage.GetToken(tokenID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(token)
}

// DeleteToken handles the deletion of a token.
func (h *Handler) DeleteToken(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tokenID := vars["tokenID"]

	if err := h.Storage.DeleteToken(tokenID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// UpdateToken handles updates to an existing token.
func (h *Handler) UpdateToken(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tokenID := vars["tokenID"]
	var updates map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.Storage.UpdateToken(tokenID, updates); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// TransferToken handles the transfer of token ownership.
func (h *Handler) TransferToken(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tokenID := vars["tokenID"]
	var transfer struct {
		NewOwner string `json:"newOwner"`
	}
	if err := json.NewDecoder(r.Body).Decode(&transfer); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.Storage.TransferOwnership(tokenID, transfer.NewOwner); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// ListTokensByOwner handles listing all tokens owned by a specific owner.
func (h *Handler) ListTokensByOwner(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	owner := vars["owner"]

	tokens, err := h.Storage.ListTokensByOwner(owner)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(tokens)
}

