package syn1300

import (
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "log"
    "sync"
    "time"

    "synthron-blockchain/pkg/common"
)

// SupplyChainAsset defines the structure for assets within the supply chain.
type SupplyChainAsset struct {
    AssetID      string
    Description  string
    Location     string
    Timestamp    time.Time
    Status       string
}

// Token encapsulates the supply chain token with enhanced security and logging features.
type Token struct {
    ID           string
    Owner        string
    Assets       map[string]SupplyChainAsset
    History      []EventLog
    mutex        sync.Mutex
}

// EventLog captures detailed logs for asset movements and updates.
type EventLog struct {
    AssetID      string
    Timestamp    time.Time
    Description  string
}

// NewToken creates a new token with a unique identifier and ownership details.
func NewToken(id, owner string) *Token {
    return &Token{
        ID:     id,
        Owner:  owner,
        Assets: make(map[string]SupplyChainAsset),
        History: []EventLog{},
    }
}

// AddAsset adds an asset to the token's management system.
func (t *Token) AddAsset(assetID, description, location string) error {
    t.mutex.Lock()
    defer t.mutex.Unlock()

    if _, exists := t.Assets[assetID]; exists {
        return errors.New("asset already exists")
    }

    asset := SupplyChainAsset{
        AssetID:     assetID,
        Description: description,
        Location:    location,
        Timestamp:   time.Now(),
        Status:      "Active",
    }
    t.Assets[assetID] = asset
    t.logEvent(assetID, "Asset registered in the system")
    return nil
}

// UpdateAsset modifies details for an existing asset within the system.
func (t *Token) UpdateAsset(assetID, newLocation, newStatus string) error {
    t.mutex.Lock()
    defer t.mutex.Unlock()

    asset, exists := t.Assets[assetID];
    if !exists {
        return errors.New("asset does not exist")
    }

    asset.Location = newLocation
    asset.Status = newStatus
    asset.Timestamp = time.Now()
    t.Assets[assetID] = asset
    t.logEvent(assetID, "Asset details updated")
    return nil
}

// logEvent creates a log entry for asset operations.
func (t *Token) logEvent(assetID, description string) {
    event := EventLog{
        AssetID:     assetID,
        Timestamp:   time.Now(),
        Description: description,
    }
    t.History = append(t.History, event)
    log.Printf("Logged event for asset %s: %s", assetID, description)
}

// GetAssetDetails fetches and returns details of a specific asset.
func (t *Token) GetAssetDetails(assetID string) (SupplyChainAsset, error) {
    t.mutex.Lock()
    defer t.mutex.Unlock()

    asset, exists := t.Assets[assetID]
    if !exists {
        return SupplyChainAsset{}, errors.New("asset not found")
    }
    return asset, nil
}

// GetTokenDetails returns all the details associated with the token.
func (t *Token) GetTokenDetails() map[string]interface{} {
    t.mutex.Lock()
    defer t.mutex.Unlock()

    details := map[string]interface{}{
        "ID":     t.ID,
        "Owner":  t.Owner,
        "Assets": t.Assets,
        "History": t.History,
    }
    log.Printf("Retrieved details for token %s", t.ID)
    return details
}

// GenerateTokenID generates a unique ID for the token using the owner's details and timestamp.
func GenerateTokenID(owner string) string {
    data := fmt.Sprintf("SYN1300:%s:%d", owner, time.Now().UnixNano())
    hash := sha256.Sum256([]byte(data))
    return hex.EncodeToString(hash[:])
}

// Example usage demonstrates how to use this module.
func ExampleUsage() {
    token := NewToken(GenerateTokenID("user123"), "user123")
    if err := token.AddAsset("asset001", "High-value Component", "Warehouse 12"); err != nil {
        log.Println("Error adding asset:", err)
    }

    if err := token.UpdateAsset("asset001", "Warehouse 13", "In Transit"); err != nil {
        log.Println("Error updating asset:", err)
    }

    fmt.Println(token.GetTokenDetails())
}
