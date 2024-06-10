package syn3700

import (
    "log"
)

// IndexTokenHandler manages operations related to index tokens.
type IndexTokenHandler struct {
    Registry *IndexRegistry
    Store    DataStore
}

// NewIndexTokenHandler initializes a new handler with a given registry and storage system.
func NewIndexTokenHandler(registry *IndexRegistry, store DataStore) *IndexTokenHandler {
    return &IndexTokenHandler{
        Registry: registry,
        Store:    store,
    }
}

// CreateIndexToken facilitates the creation of a new index token and saves it to the registry.
func (h *IndexTokenHandler) CreateIndexToken(indexName string, components []Component, holder string) (string, error) {
    tokenID, err := h.Registry.CreateIndexToken(indexName, components, holder)
    if err != nil {
        log.Printf("Error creating index token: %v", err)
        return "", err
    }

    // Save changes to storage
    if err := h.Store.SaveIndexRegistry(h.Registry); err != nil {
        log.Printf("Failed to save index registry after creating token: %v", err)
        return "", err
    }

    log.Printf("Index token successfully created: %s", tokenID)
    return tokenID, nil
}

// UpdateIndexToken facilitates updating an existing index token's components.
func (h *IndexTokenHandler) UpdateIndexToken(tokenID string, components []Component) error {
    if err := h.Registry.UpdateIndexToken(tokenID, components); err != nil {
        log.Printf("Error updating index token: %v", err)
        return err
    }

    // Save changes to storage
    if err := h.Store.SaveIndexRegistry(h.Registry); err != nil {
        log.Printf("Failed to save index registry after updating token: %v", err)
        return err
    }

    log.Println("Index token successfully updated")
    return nil
}

// GetIndexDetails retrieves details for a specified index token.
func (h *IndexTokenHandler) GetIndexDetails(tokenID string) (*IndexToken, error) {
    indexToken, err := h.Registry.GetIndexDetails(tokenID)
    if err != nil {
        log.Printf("Error retrieving index token details: %v", err)
        return nil, err
    }

    return indexToken, nil
}
