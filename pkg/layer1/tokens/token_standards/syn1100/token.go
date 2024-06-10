package syn1100

import (
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "log"
    "sync"
    "time"

    "synthron-blockchain/pkg/common"
)

// HealthcareData represents structured healthcare information encrypted for privacy.
type HealthcareData struct {
    PatientID string
    Records   string // Encrypted data to ensure privacy
}

// Token encapsulates the identity and access management for healthcare data.
type Token struct {
    ID           string
    Owner        string
    Data         HealthcareData
    AccessRights map[string]bool // Tracks who has access to view the data
    CreatedAt    time.Time
    UpdatedAt    time.Time
    mutex        sync.Mutex
    AuditLog     []string // Logs all actions taken on this token for auditing
}

// NewToken creates a new healthcare data token.
func NewToken(id, owner string, data HealthcareData) *Token {
    token := &Token{
        ID:           id,
        Owner:        owner,
        Data:         data,
        AccessRights: map[string]bool{},
        CreatedAt:    time.Now(),
        AuditLog:     []string{},
    }
    token.logAction("Created")
    return token
}

// GrantAccess authorizes a user to access the healthcare data.
func (t *Token) GrantAccess(userAddress string) {
    t.mutex.Lock()
    defer t.mutex.Unlock()

    t.AccessRights[userAddress] = true
    t.UpdatedAt = time.Now()
    t.logAction(fmt.Sprintf("Access granted to %s", userAddress))
}

// RevokeAccess revokes a user's access to the healthcare data.
func (t *Token) RevokeAccess(userAddress string) {
    t.mutex.Lock()
    defer t.mutex.Unlock()

    delete(t.AccessRights, userAddress)
    t.UpdatedAt = time.Now()
    t.logAction(fmt.Sprintf("Access revoked from %s", userAddress))
}

// CheckAccess checks if a user has access to view the data.
func (t *Token) CheckAccess(userAddress string) bool {
    t.mutex.Lock()
    defer t.mutex.Unlock()

    access, exists := t.AccessRights[userAddress]
    return exists && access
}

// GenerateTokenID creates a unique identifier for a token based on healthcare data.
func GenerateTokenID(data HealthcareData) string {
    input := fmt.Sprintf("%s:%s", data.PatientID, data.Records)
    hash := sha256.Sum256([]byte(input))
    return hex.EncodeToString(hash[:])
}

// logAction adds an entry to the token's audit log.
func (t *Token) logAction(action string) {
    entry := fmt.Sprintf("%s: %s", time.Now().Format(time.RFC3339), action)
    t.AuditLog = append(t.AuditLog, entry)
    log.Println(entry)
}

// GetDetails returns structured information about the token for auditing or management.
func (t *Token) GetDetails() map[string]interface{} {
    t.mutex.Lock()
    defer t.mutex.Unlock()

    return map[string]interface{}{
        "ID":           t.ID,
        "Owner":        t.Owner,
        "CreatedAt":    t.CreatedAt,
        "UpdatedAt":    t.UpdatedAt,
        "AccessRights": t.AccessRights,
        "AuditLog":     t.AuditLog,
    }
}

// ExampleUsage demonstrates how to instantiate and interact with the healthcare token.
func ExampleUsage() {
    identity := HealthcareData{
        PatientID: "12345",
        Records:   "EncryptedDataHere",
    }
    token := NewToken("token123", "clinicA", identity)
    token.GrantAccess("doctorB")
    token.RevokeAccess("doctorB")
    fmt.Println("Token Details:", token.GetDetails())
}
