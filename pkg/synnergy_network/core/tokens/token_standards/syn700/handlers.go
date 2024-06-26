package syn700

import (
    "encoding/json"
    "net/http"
    "time"
)

// Handlers struct binds storage and provides HTTP handlers.
type Handlers struct {
    Storage *Storage
}

// RegisterRoutes sets up the routes for token interactions.
func (h *Handlers) RegisterRoutes(router *http.ServeMux) {
    router.HandleFunc("/tokens/create", h.CreateToken)
    router.HandleFunc("/tokens/{id}", h.GetToken)
    router.HandleFunc("/tokens/{id}/transfer", h.TransferToken)
    router.HandleFunc("/tokens/{id}/update", h.UpdateToken)
    router.HandleFunc("/tokens/{id}/delete", h.DeleteToken)
}

// CreateToken handles the creation of a new token.
func (h *Handlers) CreateToken(w http.ResponseWriter, r *http.Request) {
    var req struct {
        ID          string `json:"id"`
        Owner       string `json:"owner"`
        Title       string `json:"title"`
        Description string `json:"description"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    ipAsset := IPAsset{
        Title:       req.Title,
        Description: req.Description,
        Creator:     req.Owner,
        Registered:  time.Now(), 
    }

    token := NewToken(req.ID, req.Owner, ipAsset)
    if err := h.Storage.CreateToken(token); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    response, _ := json.Marshal(token)
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusCreated)
    w.Write(response)
}

// GetToken handles the fetching of a token by its ID.
func (h *Handlers) GetToken(w http.ResponseWriter, r *http.Request) {
    tokenID := r.URL.Query().Get("id")
    token, err := h.Storage.FetchToken(tokenID)
    if err != nil {
        http.Error(w, "Token not found", http.StatusNotFound)
        return
    }

    response, _ := json.Marshal(token)
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    w.Write(response)
}

// TransferToken handles transferring ownership of a token.
func (h *Handlers) TransferToken(w http.ResponseWriter, r *http.Request) {
    tokenID := r.URL.Query().Get("id")
    var req struct {
        NewOwner string `json:"new_owner"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    if err := h.Storage.TransferOwnership(tokenID, req.NewOwner); err != nil {
        http.Error(w, "Failed to transfer token", http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Token transferred successfully"))
}

// UpdateToken handles updates to a token's sale price or details.
func (h *Handlers) UpdateToken(w http.ResponseWriter, r *http.Request) {
    tokenID := r.URL.Query().Get("id")
    var req struct {
        NewSalePrice float64 `json:"new_sale_price"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    if err := h.Storage.UpdateSalePrice(tokenID, req.NewSalePrice); err != nil {
        http.Error(w, "Failed to update token", http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Token updated successfully"))
}

// DeleteToken handles the deletion of a token.
func (h *Handlers) DeleteToken(w http.ResponseWriter, r *http.Request) {
    tokenID := r.URL.Query().Get("id")

    if err := h.Storage.DeleteToken(tokenID); err != nil {
        http.Error(w, "Failed to delete token", http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Token deleted successfully"))
}
