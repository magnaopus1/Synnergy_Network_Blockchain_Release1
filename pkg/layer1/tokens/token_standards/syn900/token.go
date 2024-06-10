package syn900

import (
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "log"
    "sync"
    "time"
)

// IdentityDetails encapsulates comprehensive personal information for identity verification.
type IdentityDetails struct {
    FullName    string    `json:"full_name"`
    DateOfBirth time.Time `json:"date_of_birth"`
    Nationality string    `json:"nationality"`
    ImageHash   string    `json:"image_hash"` // Hash of the user's photograph for visual verification
    Address     string    `json:"address"`    // Physical or mailing address
}

// Token represents an identity token in the SYN900 standard.
type Token struct {
	ID       string
    Owner    string
    Identity IdentityDetails
    CreatedAt time.Time
    VerificationLog []Verification    `json:"verification_log"`
    mutex           sync.Mutex
}

// Verification records when and how the identity was verified.
type Verification struct {
    Timestamp time.Time `json:"timestamp"`
    Status    string    `json:"status"`
}

// NewToken initializes a new identity token with the specified details.
func NewToken(owner string, identity IdentityDetails) *Token {
    tokenID := generateTokenID(identity)
    return &Token{
        ID:              tokenID,
        Owner:           owner,
        Identity:        identity,
        CreatedAt:       time.Now(),
        VerificationLog: []Verification{},
    }
}

// GenerateTokenID creates a unique identifier based on detailed identity information.
func generateTokenID(identity IdentityDetails) string {
    data := fmt.Sprintf("%s:%s:%s:%s", identity.FullName, identity.DateOfBirth.Format("20060102"), identity.Nationality, identity.Address)
    hash := sha256.Sum256([]byte(data))
    return hex.EncodeToString(hash[:])
}

// VerifyIdentity marks the token as verified and logs the event.
func (t *Token) VerifyIdentity(status string) error {
    t.mutex.Lock()
    defer t.mutex.Unlock()

    if status != "Verified" && status != "Rejected" {
        return errors.New("invalid status provided")
    }

    verification := Verification{
        Timestamp: time.Now(),
        Status:    status,
    }
    t.VerificationLog = append(t.VerificationLog, verification)
    log.Printf("Identity for token %s verified with status: %s", t.ID, status)
    return nil
}

// GetVerificationHistory retrieves the verification log for auditing purposes.
func (t *Token) GetVerificationHistory() []Verification {
    t.mutex.Lock()
    defer t.mutex.Unlock()

    return t.VerificationLog
}

// UpdateIdentityDetails allows for the modification of the identity details post-verification.
func (t *Token) UpdateIdentityDetails(newDetails IdentityDetails) error {
    t.mutex.Lock()
    defer t.mutex.Unlock()

    // Ensure changes are tracked properly
    if t.Identity.FullName != newDetails.FullName || t.Identity.Address != newDetails.Address {
        log.Printf("Identity details updated for token %s", t.ID)
    }

    t.Identity = newDetails
    t.VerificationLog = append(t.VerificationLog, Verification{
        Timestamp: time.Now(),
        Status:    "Updated",
    })

    return nil
}

// Example usage shows how to handle the identity token lifecycle.
func ExampleUsage() {
    identity := IdentityDetails{
        FullName:    "Jane Doe",
        DateOfBirth: time.Date(1985, 12, 15, 0, 0, 0, 0, time.UTC),
        Nationality: "Utopia",
        ImageHash:   "abc123hashXYZ",
        Address:     "123 Real St, Utopia City, Utopia",
    }
    token := NewToken("user456", identity)
    if err := token.VerifyIdentity("Verified"); err != nil {
        log.Println("Verification failed:", err)
    }
    fmt.Println(token.GetVerificationHistory())
}
