package syn721

import (
    "encoding/json"
    "net/http"
    "log"
)

type TokenHandler struct {
    Registry *TokenRegistry
}

func NewTokenHandler(registry *TokenRegistry) *TokenHandler {
    return &TokenHandler{Registry: registry}
}

// CreateTokenHandler handles the HTTP request to create a new SYN721 token.
func (h *TokenHandler) CreateTokenHandler(w http.ResponseWriter, r *http.Request) {
    var params struct {
        Owner    string            `json:"owner"`
        Metadata map[string]string `json:"metadata"`
    }
    if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        log.Printf("Failed to decode creation parameters: %v", err)
        return
    }

    token := h.Registry.CreateToken(params.Owner, params.Metadata)
    response, err := json.Marshal(token)
    if err != nil {
        http.Error(w, "Failed to encode response", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusCreated)
    w.Write(response)
    log.Printf("Created new SYN721 Token: %s for owner %s", token.ID, token.Owner)
}

// TransferTokenHandler handles the HTTP request to transfer a token from one owner to another.
func (h *TokenHandler) TransferTokenHandler(w http.ResponseWriter, r *http.Request) {
    var params struct {
        TokenID  string `json:"token_id"`
        NewOwner string `json:"new_owner"`
    }
    if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        log.Printf("Failed to decode transfer parameters: %v", err)
        return
    }

    err := h.Registry.TransferToken(params.TokenID, params.NewOwner)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
    log.Printf("Token %s transferred to new owner %s", params.TokenID, params.NewOwner)
}

// GetTokenHandler handles the HTTP request to retrieve a token by its ID.
func (h *TokenHandler) GetTokenHandler(w http.ResponseWriter, r *http.Request) {
    tokenID := r.URL.Query().Get("token_id")
    if tokenID == "" {
        http.Error(w, "Token ID is required", http.StatusBadRequest)
        return
    }

    token, err := h.Registry.GetToken(tokenID)
    if err != nil {
        http.Error(w, "Token not found", http.StatusNotFound)
        log.Printf("Failed to retrieve token: %v", err)
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
    log.Printf("Retrieved SYN721 Token: %s", tokenID)
}

// RegisterRoutes registers the handlers to the HTTP router.
func (h *TokenHandler) RegisterRoutes(router *http.ServeMux) {
    router.HandleFunc("/tokens/create", h.CreateTokenHandler)
    router.HandleFunc("/tokens/transfer", h.TransferTokenHandler)
    router.HandleFunc("/tokens/get", h.GetTokenHandler)
    log.Println("SYN721 token routes registered")
}

