package syn2400

import (
    "encoding/json"
    "net/http"
    "github.com/gorilla/mux"
)

type StorageClient interface {
    InsertToken(token DataToken) error
    UpdateToken(token DataToken) error
    DeleteToken(tokenID string) error
    GetToken(tokenID string) (DataToken, error)
    TransferOwnership(tokenID, newOwner string) error
}

type Handler struct {
    Storage StorageClient
}

func (h *Handler) RegisterRoutes(router *mux.Router) {
    router.HandleFunc("/tokens", h.CreateToken).Methods("POST")
    router.HandleFunc("/tokens/{tokenID}", h.GetToken).Methods("GET")
    router.HandleFunc("/tokens/{tokenID}", h.UpdateToken).Methods("PUT")
    router.HandleFunc("/tokens/{tokenID}", h.DeleteToken).Methods("DELETE")
    router.HandleFunc("/tokens/{tokenID}/transfer", h.TransferToken).Methods("POST")
}

func (h *Handler) CreateToken(w http.ResponseWriter, r *http.Request) {
    var token DataToken
    if err := json.NewDecoder(r.Body).Decode(&token); err {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }
    if err := h.Storage.InsertToken(token); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(token)
}

func (h *Handler) GetToken(w http.ResponseWriter, r *http.Request) {
    tokenID := mux.Vars(r)["tokenID"]
    token, err := h.Storage.GetToken(tokenID)
    if err != nil {
        http.Error(w, err.Error(), http.StatusNotFound)
        return
    }
    json.NewEncoder(w).Encode(token)
}

func (h *Handler) UpdateToken(w http.ResponseWriter, r *http.Request) {
    tokenID := mux.Vars(r)["tokenID"]
    var token DataToken
    if err := json.NewDecoder(r.Body).Decode(&token); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }
    if err := h.Storage.UpdateToken(token); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    json.NewEncoder(w).Encode(token)
}

func (h *Handler) DeleteToken(w http.ResponseWriter, r *http.Request) {
    tokenID := mux.Vars(r)["tokenID"]
    if err := h.Storage.DeleteToken(tokenID); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    w.WriteHeader(http.StatusOK)
}

func (h *Handler) TransferToken(w http.ResponseWriter, r *http.Request) {
    tokenID := mux.Vars(r)["tokenID"]
    var transferDetails struct {
        NewOwner string `json:"newOwner"`
    }
    if err := json.NewDecoder(r.Body).Decode(&transferDetails); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }
    if err := h.Storage.TransferOwnership(tokenID, transferDetails.NewOwner); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Ownership transferred successfully"))
}

