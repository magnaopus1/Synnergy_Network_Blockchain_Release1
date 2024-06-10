package syn800

import (
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "log"
    "sync"
    "time"
)

// AssetDetails holds information about the real-world asset being tokenized.
type AssetDetails struct {
    Description string
    Value       float64 // Current valuation of the asset
    Location    string  // Geographical location or physical address
    AssetType   string  // Type of the asset, e.g., Real Estate, Gold, Art
}

// Token represents an asset-backed token on the Synthron Blockchain.
type Token struct {
    ID                string
    Owner             string
    Shares            map[string]float64 // Fractional ownership percentages
    Asset             AssetDetails
    CreatedAt         time.Time
    LastUpdatedAt     time.Time
    mutex             sync.Mutex
    TransactionHistory []string // Records of all token transactions for auditing
}

// NewToken initializes a new asset-backed token with the given details.
func NewToken(id, owner string, asset AssetDetails) *Token {
    token := &Token{
        ID:                id,
        Owner:             owner,
        Shares:            make(map[string]float64),
        Asset:             asset,
        CreatedAt:         time.Now(),
        LastUpdatedAt:     time.Now(),
        TransactionHistory: []string{},
    }
    token.Shares[owner] = 100.0 // Initially, the creator owns 100% of the asset
    token.logTransaction(fmt.Sprintf("Token created with ID %s for asset %s", token.ID, asset.Description))
    return token
}

// TransferShares transfers a portion of the shares from one owner to another.
func (t *Token) TransferShares(from, to string, percentage float64) error {
    t.mutex.Lock()
    defer t.mutex.Unlock()

    if t.Shares[from] < percentage {
        return fmt.Errorf("insufficient shares to transfer: %s has %f%%, attempted to transfer %f%%", from, t.Shares[from], percentage)
    }

    t.Shares[from] -= percentage
    if t.Shares[to] == 0 {
        t.Shares[to] = percentage // Initialize if new owner
    } else {
        t.Shares[to] += percentage
    }
    t.LastUpdatedAt = time.Now()
    t.logTransaction(fmt.Sprintf("Transferred %f%% shares of token %s from %s to %s", percentage, t.ID, from, to))
    return nil
}

// UpdateAssetValue updates the valuation of the asset.
func (t *Token) UpdateAssetValue(newValue float64) {
    t.mutex.Lock()
    defer t.mutex.Unlock()

    t.Asset.Value = newValue
    t.LastUpdatedAt = time.Now()
    t.logTransaction(fmt.Sprintf("Updated asset value of token %s to %f", t.ID, newValue))
}

// GetTokenDetails provides a detailed view of the token's data, useful for audits and record-keeping.
func (t *Token) GetTokenDetails() map[string]interface{} {
    t.mutex.Lock()
    defer t.mutex.Unlock()

    details := map[string]interface{}{
        "ID":                t.ID,
        "Owner":             t.Owner,
        "Shares":            t.Shares,
        "Asset":             t.Asset,
        "CreatedAt":         t.CreatedAt,
        "LastUpdatedAt":     t.LastUpdatedAt,
        "TransactionHistory": t.TransactionHistory,
    }
    return details
}

// logTransaction adds a transaction record to the log.
func (t *Token) logTransaction(entry string) {
    t.TransactionHistory = append(t.TransactionHistory, entry)
    log.Println(entry)
}

// GenerateTokenID creates a unique identifier for a new token based on asset details.
func GenerateTokenID(asset AssetDetails) string {
    data := fmt.Sprintf("%s:%f:%s:%s:%s", asset.Description, asset.Value, asset.Location, asset.AssetType, time.Now().String())
    hash := sha256.Sum256([]byte(data))
    return hex.EncodeToString(hash[:])
}
