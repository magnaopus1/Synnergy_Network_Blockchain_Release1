package syn1700

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "errors"
    "fmt"
    "time"

    "golang.org/x/crypto/argon2"
    "golang.org/x/crypto/scrypt"
)

// EventMetadata represents the metadata for an event
type EventMetadata struct {
    EventID      string
    Name         string
    Description  string
    Location     string
    StartTime    time.Time
    EndTime      time.Time
    TicketSupply int
}

// TicketMetadata represents the metadata for a ticket
type TicketMetadata struct {
    EventID           string
    TicketID          string
    EventName         string
    Date              time.Time
    TicketPrice       float64
    TicketClass       string
    TicketType        string
    SpecialConditions string
}

// OwnershipRecord represents the ownership record of a ticket
type OwnershipRecord struct {
    TicketID  string
    OwnerID   string
    Timestamp time.Time
}

// EventLog represents a log of event-related activities
type EventLog struct {
    EventID   string
    Activity  string
    Timestamp time.Time
}

// ComplianceRecord represents compliance documentation for regulatory requirements
type ComplianceRecord struct {
    EventID           string
    ComplianceDetails string
    Timestamp         time.Time
}

// Syn1700Token represents the SYN1700 token structure
type Syn1700Token struct {
    EventMetadata     EventMetadata
    TicketMetadata    TicketMetadata
    OwnershipRecords  []OwnershipRecord
    EventLogs         []EventLog
    ComplianceRecords []ComplianceRecord
}

// SecureRandomString generates a secure random string for IDs
func SecureRandomString(length int) (string, error) {
    bytes := make([]byte, length)
    _, err := rand.Read(bytes)
    if err != nil {
        return "", err
    }
    return base64.URLEncoding.EncodeToString(bytes), nil
}

// HashData hashes the given data using SHA-256
func HashData(data string) string {
    hash := sha256.Sum256([]byte(data))
    return base64.URLEncoding.EncodeToString(hash[:])
}

// GenerateArgon2Hash generates a hash using Argon2
func GenerateArgon2Hash(password, salt string) (string, error) {
    hash := argon2.IDKey([]byte(password), []byte(salt), 1, 64*1024, 4, 32)
    return base64.URLEncoding.EncodeToString(hash), nil
}

// GenerateScryptHash generates a hash using Scrypt
func GenerateScryptHash(password, salt string) (string, error) {
    hash, err := scrypt.Key([]byte(password), []byte(salt), 16384, 8, 1, 32)
    if err != nil {
        return "", err
    }
    return base64.URLEncoding.EncodeToString(hash), nil
}

// EncryptData encrypts the data using AES
func EncryptData(key, data []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    nonce := make([]byte, gcm.NonceSize())
    if _, err := rand.Read(nonce); err != nil {
        return nil, err
    }
    return gcm.Seal(nonce, nonce, data, nil), nil
}

// DecryptData decrypts the data using AES
func DecryptData(key, ciphertext []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    nonceSize := gcm.NonceSize()
    if len(ciphertext) < nonceSize {
        return nil, errors.New("ciphertext too short")
    }
    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    return gcm.Open(nil, nonce, ciphertext, nil)
}

// CreateTicket creates a new ticket with the provided metadata
func CreateTicket(eventMetadata EventMetadata, ticketMetadata TicketMetadata) (*Syn1700Token, error) {
    eventID, err := SecureRandomString(16)
    if err != nil {
        return nil, err
    }
    ticketID, err := SecureRandomString(16)
    if err != nil {
        return nil, err
    }
    eventMetadata.EventID = eventID
    ticketMetadata.EventID = eventID
    ticketMetadata.TicketID = ticketID

    return &Syn1700Token{
        EventMetadata:     eventMetadata,
        TicketMetadata:    ticketMetadata,
        OwnershipRecords:  []OwnershipRecord{},
        EventLogs:         []EventLog{},
        ComplianceRecords: []ComplianceRecord{},
    }, nil
}

// TransferTicket transfers the ownership of a ticket to a new owner
func (token *Syn1700Token) TransferTicket(newOwnerID string) error {
    currentOwnerID := ""
    if len(token.OwnershipRecords) > 0 {
        currentOwnerID = token.OwnershipRecords[len(token.OwnershipRecords)-1].OwnerID
    }
    if currentOwnerID == newOwnerID {
        return errors.New("new owner is the same as the current owner")
    }

    token.OwnershipRecords = append(token.OwnershipRecords, OwnershipRecord{
        TicketID:  token.TicketMetadata.TicketID,
        OwnerID:   newOwnerID,
        Timestamp: time.Now(),
    })

    token.EventLogs = append(token.EventLogs, EventLog{
        EventID:   token.TicketMetadata.EventID,
        Activity:  fmt.Sprintf("Transferred ticket %s from %s to %s", token.TicketMetadata.TicketID, currentOwnerID, newOwnerID),
        Timestamp: time.Now(),
    })

    return nil
}

// VerifyOwnership verifies the ownership of a ticket
func (token *Syn1700Token) VerifyOwnership(ownerID string) bool {
    if len(token.OwnershipRecords) == 0 {
        return false
    }
    return token.OwnershipRecords[len(token.OwnershipRecords)-1].OwnerID == ownerID
}

// LogCompliance logs a compliance record for an event
func (token *Syn1700Token) LogCompliance(complianceDetails string) {
    token.ComplianceRecords = append(token.ComplianceRecords, ComplianceRecord{
        EventID:           token.TicketMetadata.EventID,
        ComplianceDetails: complianceDetails,
        Timestamp:         time.Now(),
    })
}

// ToJSON serializes the token to JSON
func (token *Syn1700Token) ToJSON() (string, error) {
    data, err := json.Marshal(token)
    if err != nil {
        return "", err
    }
    return string(data), nil
}

// FromJSON deserializes the token from JSON
func FromJSON(data string) (*Syn1700Token, error) {
    var token Syn1700Token
    err := json.Unmarshal([]byte(data), &token)
    if err != nil {
        return nil, err
    }
    return &token, nil
}

// Additional Functions for Enhanced Functionality

// RevokeTicket revokes a ticket, making it invalid for future use
func (token *Syn1700Token) RevokeTicket(reason string) error {
    token.EventLogs = append(token.EventLogs, EventLog{
        EventID:   token.TicketMetadata.EventID,
        Activity:  fmt.Sprintf("Revoked ticket %s for reason: %s", token.TicketMetadata.TicketID, reason),
        Timestamp: time.Now(),
    })

    token.TicketMetadata.SpecialConditions = "revoked"
    return nil
}

// DelegateAccess delegates the access rights of a ticket to another user
func (token *Syn1700Token) DelegateAccess(delegateID string) error {
    if token.TicketMetadata.SpecialConditions == "revoked" {
        return errors.New("cannot delegate access for a revoked ticket")
    }

    token.EventLogs = append(token.EventLogs, EventLog{
        EventID:   token.TicketMetadata.EventID,
        Activity:  fmt.Sprintf("Delegated access of ticket %s to %s", token.TicketMetadata.TicketID, delegateID),
        Timestamp: time.Now(),
    })

    token.TicketMetadata.SpecialConditions = fmt.Sprintf("delegated to %s", delegateID)
    return nil
}

// ValidateTicket verifies if a ticket is valid for entry
func (token *Syn1700Token) ValidateTicket() bool {
    if token.TicketMetadata.SpecialConditions == "revoked" {
        return false
    }

    // Additional validation logic can be added here
    return true
}

// UpdateEventDetails updates the details of an event
func (token *Syn1700Token) UpdateEventDetails(newDetails EventMetadata) error {
    if token.EventMetadata.EventID != newDetails.EventID {
        return errors.New("event ID mismatch")
    }

    token.EventMetadata = newDetails

    token.EventLogs = append(token.EventLogs, EventLog{
        EventID:   token.EventMetadata.EventID,
        Activity:  "Updated event details",
        Timestamp: time.Now(),
    })

    return nil
}
