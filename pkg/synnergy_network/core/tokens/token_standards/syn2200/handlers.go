package syn2200

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
)

// Handlers holds dependencies for handling requests.
type Handlers struct {
	Storage Storage
}

// NewHandlers initializes a new set of handlers with the given storage.
func NewHandlers(storage Storage) *Handlers {
	return &Handlers{Storage: storage}
}

// RegisterRoutes registers the HTTP routes for various token operations.
func (h *Handlers) RegisterRoutes(router *mux.Router) {
	router.HandleFunc("/tokens", h.CreateToken).Methods("POST")
	router.HandleFunc("/tokens/{tokenID}", h.GetToken).Methods("GET")
	router.HandleFunc("/tokens/{tokenID}/transfer", h.TransferToken).Methods("POST")
	router.HandleFunc("/tokens/owner/{ownerID}", h.ListTokensByOwner).Methods("GET")
}

// CreateToken handles the creation of a new payment token.
func (h *Handlers) CreateToken(w http.ResponseWriter, r *http.Request) {
	var token PaymentToken
	if err := json.NewDecoder(r.Body).Decode(&token); err != nil {
		http.Error(w, "Invalid token data", http.StatusBadRequest)
		return
	}

	if err := h.Storage.SaveToken(&token); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(token)
}

// GetToken retrieves a token by its ID.
func (h *Handlers) GetToken(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tokenID := vars["tokenID"]

	token, err := h.Storage.LoadToken(tokenID)
	if err != nil {
		http.Error(w, "Token not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(token)
}

// TransferToken handles the transfer of ownership of a token.
func (h *Handlers) TransferToken(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tokenID := vars["tokenID"]
	var transferReq struct {
		NewOwner string `json:"newOwner"`
	}
	if err := json.NewDecoder(r.Body).Decode(&transferReq); err != nil {
		http.Error(w, "Invalid request data", http.StatusBadRequest)
		return
	}

	if err := h.Storage.TransferToken(tokenID, transferReq.NewOwner); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// ListTokensByOwner lists all tokens owned by a specific owner.
func (h *Handlers) ListTokensByOwner(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	ownerID := vars["ownerID"]

	tokens, err := h.Storage.ListTokensByOwner(ownerID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(tokens)
}
