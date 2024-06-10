package syn500

import (
    "database/sql"
    "fmt"
    "log"
    "time"

    "synthron-blockchain/pkg/common"
)

// Token represents a utility token within the Synthron platform.
type Token struct {
    ID            string
    Owner         string
    Access        string        // Describes the access rights or service linked to the token.
    CreatedAt     time.Time
    ExpiresAt     time.Time     // Token expiry time to enforce access limitations over time.
    UsageCount    int           // Tracks the number of times the token has been used.
    MaxUsage      int           // Maximum allowable uses of the token.
    Tier          string        // Access tier (e.g., Basic, Premium).
    RewardPoints  int           // Points earned for using services linked to the token.
    DB            *sql.DB
}

// NewToken creates a new utility token with initial settings.
func NewToken(id, owner, access, tier string, maxUsage int, db *sql.DB) *Token {
    return &Token{
        ID:        id,
        Owner:     owner,
        Access:    access,
        Tier:      tier,
        CreatedAt: time.Now(),
        ExpiresAt: time.Now().Add(365 * 24 * time.Hour), // Default one year from creation.
        MaxUsage:  maxUsage,
        DB:        db,
    }
}

// Save stores the token details in the database.
func (t *Token) Save() error {
    query := `INSERT INTO utility_tokens (id, owner, access, tier, created_at, expires_at, max_usage) VALUES (?, ?, ?, ?, ?, ?, ?)`
    _, err := t.DB.Exec(query, t.ID, t.Owner, t.Access, t.Tier, t.CreatedAt, t.ExpiresAt, t.MaxUsage)
    if err != nil {
        log.Printf("Failed to save utility token %s: %v", t.ID, err)
        return fmt.Errorf("failed to save utility token: %w", err)
    }
    log.Printf("Utility token %s created for owner %s with access to %s", t.ID, t.Owner, t.Access)
    return nil
}

// CheckAccess verifies if the token provides access to a specified service.
func (t *Token) CheckAccess(service string) bool {
    return t.Access == service && time.Now().Before(t.ExpiresAt) && t.UsageCount < t.MaxUsage
}

// UpdateOwner changes the owner of the token.
func (t *Token) UpdateOwner(newOwner string) error {
    query := `UPDATE utility_tokens SET owner = ? WHERE id = ?`
    _, err := t.DB.Exec(query, newOwner, t.ID)
    if err != nil {
        log.Printf("Failed to update owner for token %s: %v", t.ID, err)
        return fmt.Errorf("failed to update token owner: %w", err)
    }
    t.Owner = newOwner
    log.Printf("Updated token %s to new owner %s", t.ID, newOwner)
    return nil
}

// UseToken records the use of the token and adjusts reward points based on the tier.
func (t *Token) UseToken() error {
    if !t.CheckAccess(t.Access) {
        return fmt.Errorf("token %s is either expired or has reached its usage limit", t.ID)
    }
    t.UsageCount++
    rewardIncrement := 10 // Basic increment for reward points
    if t.Tier == "Premium" {
        rewardIncrement = 20
    }
    t.RewardPoints += rewardIncrement
    log.Printf("Token %s used, reward points increased by %d", t.ID, rewardIncrement)
    return nil
}

// LogTokenActivities provides a detailed log of token properties and activities.
func (t *Token) LogTokenActivities() {
    log.Printf("Token ID: %s, Owner: %s, Access: %s, Tier: %s, CreatedAt: %s, ExpiresAt: %s, UsageCount: %d, MaxUsage: %d, RewardPoints: %d",
        t.ID, t.Owner, t.Access, t.Tier, t.CreatedAt.Format(time.RFC3339), t.ExpiresAt.Format(time.RFC3339), t.UsageCount, t.MaxUsage, t.RewardPoints)
}
