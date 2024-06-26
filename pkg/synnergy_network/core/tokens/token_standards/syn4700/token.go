package syn4700

import (
    "crypto/rand"
    "encoding/hex"
    "errors"
    "fmt"
    "sync"
    "time"
)

// LegalToken represents legal documents or contracts on the blockchain.
type LegalToken struct {
    TokenID       string    `json:"tokenId"`
    DocumentType  string    `json:"documentType"`  // Type of document (e.g., contract, agreement, resolution)
    Parties       []string  `json:"parties"`       // Parties involved in the document
    ContentHash   string    `json:"contentHash"`   // Hash of the document content for integrity
    CreationDate  time.Time `json:"creationDate"`
    ExpiryDate    time.Time `json:"expiryDate"`    // When the document or agreement expires
    Status        string    `json:"status"`        // Current status (active, expired, disputed)
    Signatures    map[string]string `json:"signatures"`  // Signatures from all parties involved
    Metadata      map[string]string `json:"metadata"`    // Additional information (e.g., jurisdiction)
}

// LegalRegistry manages all legal tokens.
type LegalRegistry struct {
    Tokens map[string]*LegalToken
    mutex  sync.Mutex
}

// NewLegalRegistry initializes a new registry for managing legal tokens.
func NewLegalRegistry() *LegalRegistry {
    return &LegalRegistry{
        Tokens: make(map[string]*LegalToken),
    }
}

// GenerateTokenID creates a secure, unique token ID.
func GenerateTokenID() (string, error) {
    b := make([]byte, 16) // 128-bit
    _, err := rand.Read(b)
    if err != nil {
        return "", fmt.Errorf("error generating token ID: %v", err)
    }
    return hex.EncodeToString(b), nil
}

// CreateLegalToken issues a new legal token for a document.
func (r *LegalRegistry) CreateLegalToken(documentType string, parties []string, contentHash string, expiryDate time.Time, metadata map[string]string) (string, error) {
    r.mutex.Lock()
    defer r.mutex.Unlock()

    tokenID, err := GenerateTokenID()
    if err != nil {
        return "", err
    }

    legalToken := &LegalToken{
        TokenID:      tokenID,
        DocumentType: documentType,
        Parties:      parties,
        ContentHash:  contentHash,
        CreationDate: time.Now(),
        ExpiryDate:   expiryDate,
        Status:       "active",
        Signatures:   make(map[string]string),
        Metadata:     metadata,
    }

    r.Tokens[tokenID] = legalToken
    return tokenID, nil
}

// UpdateLegalTokenStatus updates the status of a legal token.
func (r *LegalRegistry) UpdateLegalTokenStatus(tokenID, status string) error {
    r.mutex.Lock()
    defer r.mutex.Unlock()

    token, exists := r.Tokens[tokenID]
    if !exists {
        return errors.New("legal token not found")
    }

    token.Status = status
    return nil
}

// SignLegalToken allows a party to sign the legal token.
func (r *LegalRegistry) SignLegalToken(tokenID, party, signature string) error {
    r.mutex.Lock()
    defer r.mutex.Unlock()

    token, exists := r.Tokens[tokenID]
    if !exists {
        return errors.New("legal token not found")
    }

    token.Signatures[party] = signature
    return nil
}

// GetLegalTokenDetails retrieves details for a specific legal token.
func (r *LegalRegistry) GetLegalTokenDetails(tokenID string) (*LegalToken, error) {
    r.mutex.Lock()
    defer r.mutex.Unlock()

    token, exists := r.Tokens[tokenID]
    if !exists {
        return nil, fmt.Errorf("legal token not found: %s", tokenID)
    }

    return token, nil
}
