package syn2369

import (
    "encoding/json"
    "net/http"
    "github.com/gorilla/mux"
)

// Handler struct holds dependencies for the HTTP handlers such as the ledger and storage.
type Handler struct {
    Ledger  *ItemLedger
    Storage *Storage
}

// NewHandler creates a new handler with dependencies.
func NewHandler(ledger *ItemLedger, storage *Storage) *Handler {
    return &Handler{
        Ledger:  ledger,
        Storage: storage,
    }
}

// RegisterRoutes registers the routes for item management in the router.
func (h *Handler) RegisterRoutes(router *mux.Router) {
    router.HandleFunc("/items", h.CreateItem).Methods("POST")
    router.HandleFunc("/items/{itemId}", h.GetItem).Methods("GET")
    router.HandleFunc("/items/{itemId}", h.UpdateItem).Methods("PUT")
    router.HandleFunc("/items/{itemId}", h.DeleteItem).Methods("DELETE")
    router.HandleFunc("/items/transfer/{itemId}", h.TransferItem).Methods("POST")
}

// CreateItem handles the creation of a new virtual item.
func (h *Handler) CreateItem(w http.ResponseWriter, r *http.Request) {
    var item VirtualItem
    if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    if err := h.Ledger.CreateItem(item); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    h.Storage.SaveItems(h.Ledger) // Persist changes
    json.NewEncoder(w).Encode(item)
}

// GetItem handles retrieving a virtual item by its ID.
func (h *Handler) GetItem(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    itemID := vars["itemId"]
    item, err := h.Ledger.GetItem(itemID)
    if err != nil {
        http.Error(w, err.Error(), http.StatusNotFound)
        return
    }
    json.NewEncoder(w).Encode(item)
}

// UpdateItem handles updating properties of an existing virtual item.
func (h *Handler) UpdateItem(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    itemID := vars["itemId"]

    var updates map[string]interface{}
    if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    if err := h.Ledger.UpdateItem(itemID, updates); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    h.Storage.SaveItems(h.Ledger) // Persist changes
    w.WriteHeader(http.StatusOK)
}

// DeleteItem handles the deletion of a virtual item.
func (h *Handler) DeleteItem(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    itemID := vars["itemId"]

    if err := h.Ledger.DeleteItem(itemID); err != nil {
        http.Error(w, err.Error(), http.StatusNotFound)
        return
    }

    h.Storage.SaveItems(h.Ledger) // Persist changes
    w.WriteHeader(http.StatusOK)
}

// TransferItem handles transferring ownership of a virtual item to a new owner.
func (h *Handler) TransferItem(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    itemID := vars["itemId"]

    var transfer struct {
        NewOwner string `json:"newOwner"`
    }
    if err := json.NewDecoder(r.Body).Decode(&transfer); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    if err := h.Ledger.TransferOwnership(itemID, transfer.NewOwner); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    h.Storage.SaveItems(h.Ledger) // Persist changes
    w.WriteHeader(http.StatusOK)
}
