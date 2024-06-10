package syn721

import (
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "sync"
    "time"
)

type Token struct {
    ID          string
    Owner       string
    Metadata    map[string]string
    MetadataLog []MetadataEntry
    CreatedAt   time.Time
    UpdatedAt   time.Time
}

type MetadataEntry struct {
    Key       string
    Value     string
    Timestamp time.Time
}

type TokenRegistry struct {
    Tokens map[string]*Token
    mutex  sync.RWMutex
    events chan<- Event
}

type Event struct {
    Type    string
    Details string
}

func NewTokenRegistry(eventChannel chan<- Event) *TokenRegistry {
    return &TokenRegistry{
        Tokens: make(map[string]*Token),
        events: eventChannel,
    }
}

func (tr *TokenRegistry) CreateToken(owner string, metadata map[string]string) *Token {
    tr.mutex.Lock()
    defer tr.mutex.Unlock()

    tokenID := generateTokenID(metadata)
    token := &Token{
        ID:          tokenID,
        Owner:       owner,
        Metadata:    metadata,
        CreatedAt:   time.Now(),
        UpdatedAt:   time.Now(),
        MetadataLog: []MetadataEntry{},
    }
    tr.Tokens[tokenID] = token
    tr.events <- Event{"Create", fmt.Sprintf("New NFT created: %s by %s", tokenID, owner)}
    return token
}

func (tr *TokenRegistry) TransferToken(tokenID, newOwner string) error {
    tr.mutex.Lock()
    defer tr.mutex.Unlock()

    token, exists := tr.Tokens[tokenID]
    if !exists {
        return fmt.Errorf("token with ID %s does not exist", tokenID)
    }
    token.Owner = newOwner
    token.UpdatedAt = time.Now()
    token.MetadataLog = append(token.MetadataLog, MetadataEntry{"Owner", newOwner, time.Now()})
    tr.events <- Event{"Transfer", fmt.Sprintf("Token %s transferred to %s", tokenID, newOwner)}
    return nil
}

func (tr *TokenRegistry) GetToken(tokenID string) (*Token, error) {
    tr.mutex.RLock()
    defer tr.mutex.RUnlock()

    token, exists := tr.Tokens[tokenID]
    if !exists {
        return nil, fmt.Errorf("token with ID %s not found", tokenID)
    }
    return token, nil
}

func generateTokenID(metadata map[string]string) string {
    data := fmt.Sprint(metadata)
    hash := sha256.Sum256([]byte(data))
    return hex.EncodeToString(hash[:])
}
