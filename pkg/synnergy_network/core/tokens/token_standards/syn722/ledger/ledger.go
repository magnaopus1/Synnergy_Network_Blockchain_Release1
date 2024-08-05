package ledger

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn722/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn722/security"
)

// SYN722 represents the structure of a SYN722 token in the ledger.
type SYN722 struct {
	ID        string            `json:"id"`
	Owner     string            `json:"owner"`
	Mode      string            `json:"mode"`
	Quantity  int               `json:"quantity"`
	Metadata  map[string]string `json:"metadata"`
	History   []HistoryEntry    `json:"history"`
	Encrypted bool              `json:"encrypted"`
}

// HistoryEntry represents a log entry for the token history.
type HistoryEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	Details   string    `json:"details"`
}

// Ledger represents the ledger that tracks all SYN722 tokens.
type Ledger struct {
	mu     sync.Mutex
	Tokens map[string]*SYN722
}

// NewLedger creates a new instance of the Ledger.
func NewLedger() *Ledger {
	return &Ledger{
		Tokens: make(map[string]*SYN722),
	}
}

// AddToken adds a new SYN722 token to the ledger.
func (l *Ledger) AddToken(tokenID, owner string, quantity int) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if _, exists := l.Tokens[tokenID]; exists {
		return errors.New("token already exists")
	}

	l.Tokens[tokenID] = &SYN722{
		ID:       tokenID,
		Owner:    owner,
		Quantity: quantity,
		Mode:     "fungible",
		Metadata: make(map[string]string),
		History: []HistoryEntry{
			{
				Timestamp: time.Now(),
				Action:    "created",
				Details:   "Token created",
			},
		},
		Encrypted: false,
	}
	return nil
}

// GetToken retrieves a SYN722 token from the ledger by its ID.
func (l *Ledger) GetToken(tokenID string) (*SYN722, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	token, exists := l.Tokens[tokenID]
	if !exists {
		return nil, errors.New("token not found")
	}
	return token, nil
}

// UpdateToken updates the SYN722 token details in the ledger.
func (l *Ledger) UpdateToken(tokenID, owner string, quantity int) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	token, exists := l.Tokens[tokenID]
	if !exists {
		return errors.New("token not found")
	}

	token.Owner = owner
	token.Quantity = quantity
	token.History = append(token.History, HistoryEntry{
		Timestamp: time.Now(),
		Action:    "updated",
		Details:   "Token updated",
	})
	return nil
}

// EncryptToken encrypts the SYN722 token details using AES encryption.
func (l *Ledger) EncryptToken(tokenID, key string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	token, exists := l.Tokens[tokenID]
	if !exists {
		return errors.New("token not found")
	}

	if token.Encrypted {
		return errors.New("token details are already encrypted")
	}

	plaintext, err := json.Marshal(token)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	token.History = append(token.History, HistoryEntry{
		Timestamp: time.Now(),
		Action:    "encrypted",
		Details:   base64.StdEncoding.EncodeToString(ciphertext),
	})
	token.Encrypted = true

	return nil
}

// DecryptToken decrypts the SYN722 token details using AES decryption.
func (l *Ledger) DecryptToken(tokenID, key string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	token, exists := l.Tokens[tokenID]
	if !exists {
		return errors.New("token not found")
	}

	if !token.Encrypted {
		return errors.New("token details are not encrypted")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(token.History[len(token.History)-1].Details)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}

	err = json.Unmarshal(plaintext, token)
	if err != nil {
		return err
	}

	token.Encrypted = false
	return nil
}

// LogEvent logs a significant event in the SYN722 token's history.
func (l *Ledger) LogEvent(tokenID, action, details string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	token, exists := l.Tokens[tokenID]
	if !exists {
		return errors.New("token not found")
	}

	entry := HistoryEntry{
		Timestamp: time.Now(),
		Action:    action,
		Details:   details,
	}
	token.History = append(token.History, entry)
	return nil
}
