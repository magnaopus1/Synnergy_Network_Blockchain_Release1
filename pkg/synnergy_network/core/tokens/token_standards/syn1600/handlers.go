package syn1600

import (
    "encoding/json"
    "net/http"
    "sync"

    "github.com/gorilla/mux"
)

// TokenHandler is responsible for handling HTTP requests related to Royalty Tokens.
type TokenHandler struct {
    Storage StorageManager
    mutex   sync.Mutex
}

// NewTokenHandler returns a new instance of TokenHandler.
func NewTokenHandler(storage StorageManager) *TokenHandler {
    return &TokenHandler{
        Storage: storage,
    }
}

// RegisterRoutes adds the routes for token operations to a router.
func (th *TokenHandler) RegisterRoutes(router *mux.Router) {
    router.HandleFunc("/tokens/create", th.CreateToken).Methods("POST")
    router.HandleFunc("/tokens/{id}", th.GetToken).Methods("GET")
    router.HandleFunc("/tokens/{id}/transfer", th.TransferToken).Methods("POST")
    router.HandleFunc("/tokens/{id}/revenue", th.RecordRevenue).Methods("POST")
}

// CreateToken handles the creation of new royalty tokens.
func (th *TokenHandler) CreateToken(w http.ResponseWriter, r *http.Request) {
    var requestData struct {
        Owner     string `json:"owner"`
        MusicTitle string `json:"music_title"`
    }
    if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    tokenID := GenerateTokenID(requestData.MusicTitle, requestData.Owner)
    token := NewRoyaltyToken(tokenID, requestData.Owner, requestData.MusicTitle)
    if err := th.Storage.SaveToken(token); err != nil {
        http.Error(w, "Failed to save token", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(token)
}

// GetToken retrieves details for a specific token.
func (th *TokenHandler) GetToken(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    tokenID := vars["id"]

    token, err := th.Storage.LoadToken(tokenID)
    if err != nil {
        http.Error(w, "Token not found", http.StatusNotFound)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(token.GetTokenDetails())
}

// TransferToken handles the transfer of ownership of a token.
func (th *TokenHandler) TransferToken(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    tokenID := vars["id"]

    var requestData struct {
        NewOwner string `json:"new_owner"`
    }
    if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    token, err := th.Storage.LoadToken(tokenID)
    if err != nil {
        http.Error(w, "Token not found", http.StatusNotFound)
        return
    }

    token.TransferOwnership(requestData.NewOwner)
    if err := th.Storage.SaveToken(token); err != nil {
        http.Error(w, "Failed to update token", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(token.GetTokenDetails())
}

// RecordRevenue handles recording revenue for a token.
func (th *TokenHandler) RecordRevenue(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    tokenID := vars["id"]

    var requestData struct {
        StreamType string  `json:"stream_type"`
        Amount     float64 `json:"amount"`
    }
    if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    token, err := th.Storage.LoadToken(tokenID)
    if err != nil {
        http.Error(w, "Token not found", http.StatusNotFound)
        return
    }

    token.RecordRevenue(requestData.StreamType, requestData.Amount)
    if err := th.Storage.SaveToken(token); err != nil {
        http.Error(w, "Failed to update revenue", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(token.GetTokenDetails())
}
