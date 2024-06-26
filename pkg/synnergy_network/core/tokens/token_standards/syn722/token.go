package syn722

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
)

// Mode defines the type of token: Fungible or NonFungible.
type Mode int

const (
	Fungible Mode = iota
	NonFungible
)

// Token represents the SYN722 token which can switch between fungible and non-fungible states.
type Token struct {
	ID        string
	Owner     string
	Mode      Mode
	Quantity  uint64 // Used when in fungible mode
	Metadata  map[string]string // Metadata when in non-fungible mode
	CreatedAt time.Time
	UpdatedAt time.Time
	mutex     sync.Mutex
}

// NewToken initializes a new SYN722 token in either fungible or non-fungible mode.
func NewToken(id, owner string, mode Mode, quantity uint64, metadata map[string]string) *Token {
	token := &Token{
		ID:        id,
		Owner:     owner,
		Mode:      mode,
		Quantity:  quantity,
		Metadata:  metadata,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	log.Printf("New token created: %s, Owner: %s, Mode: %d, Quantity: %d", id, owner, mode, quantity)
	return token
}

// ChangeMode switches the token's mode between fungible and non-fungible, preserving the original metadata.
func (t *Token) ChangeMode(newMode Mode) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if newMode == t.Mode {
		return errors.New("new mode is the same as the current mode")
	}

	t.Mode = newMode
	t.UpdatedAt = time.Now()
	log.Printf("Token %s mode changed to %v", t.ID, newMode)
	return nil
}

// UpdateMetadata updates the metadata associated with a non-fungible token.
func (t *Token) UpdateMetadata(key, value string) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if t.Mode != NonFungible {
		return errors.New("cannot update metadata for a fungible token")
	}

	if t.Metadata == nil {
		t.Metadata = make(map[string]string)
	}
	t.Metadata[key] = value
	t.UpdatedAt = time.Now()
	log.Printf("Metadata for token %s updated: %s = %s", t.ID, key, value)
	return nil
}

// Transfer adjusts the ownership of the token, respecting its current mode and updates token state accordingly.
func (t *Token) Transfer(newOwner string, quantity uint64) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if t.Mode == Fungible && quantity > t.Quantity {
		return fmt.Errorf("attempted to transfer %d units, but only %d available", quantity, t.Quantity)
	}

	if t.Mode == Fungible {
		t.Quantity -= quantity
		log.Printf("Transferred %d units of token %s to %s", quantity, t.ID, newOwner)
	} else {
		t.Owner = newOwner
		log.Printf("Transferred ownership of token %s to %s", t.ID, newOwner)
	}

	t.UpdatedAt = time.Now()
	return nil
}

// LogTokenState logs the current state of the token for audit and monitoring purposes.
func (t *Token) LogTokenState() {
	log.Printf("Token ID: %s, Owner: %s, Mode: %d, Quantity: %d, Metadata: %v, CreatedAt: %s, UpdatedAt: %s",
		t.ID, t.Owner, t.Mode, t.Quantity, t.Metadata, t.CreatedAt.Format(time.RFC3339), t.UpdatedAt.Format(time.RFC3339))
}

// GenerateTokenID generates a unique identifier based on owner and mode with a timestamp.
func GenerateTokenID(owner string, mode Mode) string {
	data := fmt.Sprintf("%s:%d:%s", owner, mode, time.Now().String())
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}
