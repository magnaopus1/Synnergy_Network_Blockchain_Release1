package syn600

import (
    "encoding/json"
    "net/http"
    "strconv"

    "github.com/gorilla/mux"
    "synthron-blockchain/pkg/common"
)

// TokenHandler manages the HTTP interface for reward token interactions.
type TokenHandler struct {
    TokenService *TokenService
}

// NewTokenHandler creates a handler that will manage token-related requests.
func NewTokenHandler(tokenService *TokenService) *TokenHandler {
    return &TokenHandler{
        TokenService: tokenService,
    }
}

// RegisterRoutes registers the routes for token management on the given router.
func (h *TokenHandler) RegisterRoutes(router *mux.Router) {
    router.HandleFunc("/tokens/{tokenID}", h.GetToken).Methods("GET")
    router.HandleFunc("/tokens", h.CreateToken).Methods("POST")
    router.HandleFunc("/tokens/{tokenID}", h.TransferToken).Methods("PUT")
    router.HandleFunc("/tokens/{tokenID}", h.DeleteToken).Methods("DELETE")
}

// GetToken handles the retrieval of a token.
func (h *TokenHandler) GetToken(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    tokenID := vars["tokenID"]

    token, err := h.TokenService.GetToken(tokenID)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    response, err := json.Marshal(token)
    if err != nil {
        http.Error(w, "Failed to encode response", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    w.Write(response)
}

// CreateToken handles creating a new token.
func (h *TokenHandler) CreateToken(w http.ResponseWriter, r *http.Request) {
    var token Token
    if err := json.NewDecoder(r.Body).Decode(&token); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    err := h.TokenService.CreateToken(&token)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusCreated)
}

// TransferToken handles the transfer of a token from one user to another.
func (h *TokenHandler) TransferToken(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    tokenID := vars["tokenID"]
    var req struct {
        To     string  `json:"to"`
        Amount float64 `json:"amount"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    err := h.TokenService.TransferToken(tokenID, req.To, req.Amount)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
}

// DeleteToken handles the deletion of a token.
func (h *TokenHandler) DeleteToken(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    tokenID := vars["tokenID"]

    err := h.TokenService.DeleteToken(tokenID)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusNoContent)
}
