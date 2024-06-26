package syn900

import (
    "encoding/json"
    "log"
    "net/http"
)

// TokenHandler manages HTTP requests related to identity tokens.
type TokenHandler struct {
    Storage *Storage
}

// NewTokenHandler creates a new handler with the necessary dependencies.
func NewTokenHandler(storage *Storage) *TokenHandler {
    return &TokenHandler{
        Storage: storage,
    }
}

// CreateToken handles the creation of identity tokens.
func (h *TokenHandler) CreateToken(w http.ResponseWriter, r *http.Request) {
    var request struct {
        Owner string `json:"owner"`
        IdentityDetails
    }
    if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        log.Printf("Failed to decode request: %v", err)
        return
    }

    token := NewToken(request.Owner, request.IdentityDetails)
    if err := h.Storage.SaveToken(token); err != nil {
        http.Error(w, "Failed to save token", http.StatusInternalServerError)
        log.Printf("Failed to save token: %v", err)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(token)
    log.Printf("Token created: %s", token.ID)
}

// VerifyIdentity handles the verification of identity tokens.
func (h *TokenHandler) VerifyIdentity(w http.ResponseWriter, r *http.Request) {
    tokenID := r.URL.Query().Get("token_id")
    if tokenID == "" {
        http.Error(w, "Token ID is required", http.StatusBadRequest)
        return
    }

    status := r.URL.Query().Get("status")
    if status == "" {
        http.Error(w, "Verification status is required", http.StatusBadRequest)
        return
    }

    token, err := h.Storage.GetToken(tokenID)
    if err != nil {
        http.Error(w, "Token not found", http.StatusNotFound)
        log.Printf("Token not found: %s", tokenID)
        return
    }

    token.VerifyIdentity(status)
    log.Printf("Token %s verified with status: %s", token.ID, status)
    w.WriteHeader(http.StatusOK)
}

// GetTokenDetails handles requests to retrieve detailed information about a token.
func (h *TokenHandler) GetTokenDetails(w http.ResponseWriter, r *http.Request) {
    tokenID := r.URL.Query().Get("token_id")
    if tokenID == "" {
        http.Error(w, "Token ID is required", http.StatusBadRequest)
        return
    }

    token, err := h.Storage.GetToken(tokenID)
    if err != nil {
        http.Error(w, "Token not found", http.StatusNotFound)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(token)
    log.Printf("Retrieved details for token %s", token.ID)
}

// RegisterRoutes sets up the routing for token-related operations.
func (h *TokenHandler) RegisterRoutes(mux *http.ServeMux) {
    mux.HandleFunc("/tokens/create", h.CreateToken)
    mux.HandleFunc("/tokens/verify", h.VerifyIdentity)
    mux.HandleFunc("/tokens/details", h.GetTokenDetails)
    log.Println("Identity token routes registered successfully.")
}
