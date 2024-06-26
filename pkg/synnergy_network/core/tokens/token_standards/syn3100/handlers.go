package syn3100

import (
    "encoding/json"
    "net/http"

    "github.com/gorilla/mux"
)

// Handler holds the storage and provides HTTP API functionality.
type Handler struct {
    Storage *Storage
}

// NewHandler initializes a new Handler with the given storage.
func NewHandler(storage *Storage) *Handler {
    return &Handler{Storage: storage}
}

// RegisterRoutes sets up the routes for HTTP server.
func (h *Handler) RegisterRoutes(router *mux.Router) {
    router.HandleFunc("/api/employmenttokens/new", h.CreateToken).Methods("POST")
    router.HandleFunc("/api/employmenttokens/{tokenID}", h.GetToken).Methods("GET")
    router.HandleFunc("/api/employmenttokens/{tokenID}/update", h.UpdateToken).Methods("POST")
    router.HandleFunc("/api/employmenttokens/{tokenID}/deactivate", h.DeactivateToken).Methods("POST")
    router.HandleFunc("/api/employmenttokens", h.ListActiveTokens).Methods("GET")
}

// CreateToken handles the creation of new employment tokens.
func (h *Handler) CreateToken(w http.ResponseWriter, r *http.Request) {
    var contract EmploymentContract
    if err := json.NewDecoder(r.Body).Decode(&contract); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    token, err := h.Storage.IssueToken(contract)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(token)
}

// GetToken retrieves an employment token by its ID.
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

// UpdateToken handles updates to an existing employment contract.
func (h *Handler) UpdateToken(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    tokenID := vars["tokenID"]

    var updates map[string]interface{}
    if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    err := h.Storage.UpdateContract(tokenID, updates)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
}

// DeactivateToken handles the deactivation (termination) of an employment contract.
func (h *Handler) DeactivateToken(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    tokenID := vars["tokenID"]

    if err := h.Storage.DeactivateContract(tokenID); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
}

// ListActiveTokens lists all active employment tokens.
func (h *Handler) ListActiveTokens(w http.ResponseWriter, r *http.Request) {
    tokens, err := h.Storage.ListActiveTokens()
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    json.NewEncoder(w).Encode(tokens)
}
