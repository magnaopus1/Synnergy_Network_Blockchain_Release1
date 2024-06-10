package syn1500

import (
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "log"
    "sync"
    "time"

    "synthron-blockchain/pkg/common"
)

// ReputationToken represents a user's reputation within the ecosystem.
type ReputationToken struct {
    ID              string
    Owner           string
    ReputationScore int
    TrustLevel      string
    Events          []ReputationEvent
    mutex           sync.Mutex
}

// ReputationEvent logs changes in reputation or ownership.
type ReputationEvent struct {
    Date        time.Time
    Description string
}

// NewReputationToken creates a new reputation token with an initial score and trust level.
func NewReputationToken(id, owner string, initialScore int, trustLevel string) *ReputationToken {
    return &ReputationToken{
        ID:              id,
        Owner:           owner,
        ReputationScore: initialScore,
        TrustLevel:      trustLevel,
        Events:          make([]ReputationEvent, 0),
    }
}

// UpdateReputation modifies the reputation score and updates the trust level.
func (rt *ReputationToken) UpdateReputation(newScore int) {
    rt.mutex.Lock()
    defer rt.mutex.Unlock()

    rt.ReputationScore = newScore
    rt.updateTrustLevel()
    rt.Events = append(rt.Events, ReputationEvent{
        Date:        time.Now(),
        Description: fmt.Sprintf("Updated reputation score to %d", newScore),
    })
    log.Printf("Reputation updated for %s: %d", rt.Owner, newScore)
}

// updateTrustLevel adjusts the trust level based on the new reputation score.
func (rt *ReputationToken) updateTrustLevel() {
    if rt.ReputationScore > 80 {
        rt.TrustLevel = "High"
    } else if rt.ReputationScore > 50 {
        rt.TrustLevel = "Medium"
    } else {
        rt.TrustLevel = "Low"
    }
}

// TransferOwnership changes the owner of the reputation token.
func (rt *ReputationToken) TransferOwnership(newOwner string) {
    rt.mutex.Lock()
    defer rt.mutex.Unlock()

    rt.Owner = newOwner
    rt.Events = append(rt.Events, ReputationEvent{
        Date:        time.Now(),
        Description: "Ownership transferred",
    })
    log.Printf("Reputation token ownership transferred to %s", newOwner)
}

// GetDetails provides current details about the reputation token.
func (rt *ReputationToken) GetDetails() map[string]interface{} {
    rt.mutex.Lock()
    defer rt.mutex.Unlock()

    return map[string]interface{}{
        "ID":              rt.ID,
        "Owner":           rt.Owner,
        "ReputationScore": rt.ReputationScore,
        "TrustLevel":      rt.TrustLevel,
        "Events":          rt.Events,
    }
}

// GenerateTokenID creates a unique identifier for a reputation token.
func GenerateTokenID(owner string) string {
    data := fmt.Sprintf("%s:%s", owner, time.Now().String())
    hash := sha256.Sum256([]byte(data))
    return hex.EncodeToString(hash[:])
}

// Example of creating and managing a reputation token.
func ExampleUsage() {
    token := NewReputationToken(GenerateTokenID("user123"), "user123", 50, "Medium")
    token.UpdateReputation(85)
    token.TransferOwnership("user456")
    fmt.Println("Token Details:", token.GetDetails())
}
