package syn1600

import (
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "log"
    "sync"
    "time"

    "synthron-blockchain/pkg/common"
)

// RoyaltyToken represents a music royalty token, encapsulating all details necessary for a robust system.
type RoyaltyToken struct {
    ID              string
    Owner           string
    MusicTitle      string
    RevenueStreams  map[string]float64
    TotalRevenue    float64
    CreationDate    time.Time
    Mutex           sync.RWMutex
    EventLogs       []string
}

// NewRoyaltyToken initializes a new music royalty token with secure defaults.
func NewRoyaltyToken(id, owner, musicTitle string) *RoyaltyToken {
    token := &RoyaltyToken{
        ID:             id,
        Owner:          owner,
        MusicTitle:     musicTitle,
        RevenueStreams: make(map[string]float64),
        TotalRevenue:   0,
        CreationDate:   time.Now(),
        EventLogs:      make([]string, 0),
    }
    token.logEvent("Token created")
    return token
}

// RecordRevenue securely adds or updates revenue streams for the token.
func (rt *RoyaltyToken) RecordRevenue(streamType string, amount float64) {
    rt.Mutex.Lock()
    defer rt.Mutex.Unlock()

    if amount < 0 {
        rt.logEvent(fmt.Sprintf("Invalid revenue attempt: negative amount for %s", streamType))
        return
    }

    rt.RevenueStreams[streamType] += amount
    rt.TotalRevenue += amount
    rt.logEvent(fmt.Sprintf("Revenue recorded for %s: %s adds %.2f, total %.2f", rt.MusicTitle, streamType, amount, rt.TotalRevenue))
}

// TransferOwnership changes the owner of the royalty token with proper logging.
func (rt *RoyaltyToken) TransferOwnership(newOwner string) {
    rt.Mutex.Lock()
    defer rt.Mutex.Unlock()

    previousOwner := rt.Owner
    rt.Owner = newOwner
    rt.logEvent(fmt.Sprintf("Ownership transferred from %s to %s", previousOwner, newOwner))
}

// logEvent appends a new log entry to the token's event history.
func (rt *RoyaltyToken) logEvent(description string) {
    logEntry := fmt.Sprintf("%s: %s", time.Now().Format(time.RFC3339), description)
    rt.EventLogs = append(rt.EventLogs, logEntry)
    log.Println(logEntry)
}

// GetTokenDetails provides a snapshot of the current state of the royalty token.
func (rt *RoyaltyToken) GetTokenDetails() map[string]interface{} {
    rt.Mutex.RLock()
    defer rt.Mutex.RUnlock()

    details := map[string]interface{}{
        "ID":             rt.ID,
        "Owner":          rt.Owner,
        "MusicTitle":     rt.MusicTitle,
        "RevenueStreams": rt.RevenueStreams,
        "TotalRevenue":   rt.TotalRevenue,
        "CreationDate":   rt.CreationDate,
        "EventLogs":      rt.EventLogs,
    }
    return details
}

// GenerateTokenID creates a unique identifier for a new royalty token based on the music title and owner.
func GenerateTokenID(musicTitle, owner string) string {
    data := fmt.Sprintf("%s:%s:%s", musicTitle, owner, time.Now().String())
    hash := sha256.Sum256([]byte(data))
    return hex.EncodeToString(hash[:])
}

// ExampleUsage illustrates how to create and manipulate a music royalty token.
func ExampleUsage() {
    token := NewRoyaltyToken(GenerateTokenID("Symphony No.5", "ComposerA"), "ComposerA", "Symphony No.5")
    token.RecordRevenue("Streaming", 5000)
    token.RecordRevenue("Live Performance", 3000)
    token.TransferOwnership("PublisherB")
    fmt.Println("Token Details:", token.GetTokenDetails())
}
