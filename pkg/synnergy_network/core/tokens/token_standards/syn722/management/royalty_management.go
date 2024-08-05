package management

import (
	"errors"
	"sync"
	"time"
)

// Royalty represents the royalty details for a SYN722 token.
type Royalty struct {
	TokenID        string    `json:"token_id"`
	OriginalCreator string   `json:"original_creator"`
	RoyaltyRate    float64   `json:"royalty_rate"` // as a percentage
	Payments       []Payment `json:"payments"`
	Encrypted      bool      `json:"encrypted"`
}

// Payment represents a royalty payment record.
type Payment struct {
	Timestamp time.Time `json:"timestamp"`
	Amount    float64   `json:"amount"`
	Payer     string    `json:"payer"`
}

// RoyaltyManager manages the royalties for SYN722 tokens.
type RoyaltyManager struct {
	mu       sync.Mutex
	Royalties map[string]*Royalty
}

// NewRoyaltyManager creates a new instance of RoyaltyManager.
func NewRoyaltyManager() *RoyaltyManager {
	return &RoyaltyManager{
		Royalties: make(map[string]*Royalty),
	}
}

// SetRoyalty sets the royalty details for a SYN722 token.
func (rm *RoyaltyManager) SetRoyalty(tokenID, creator string, rate float64) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if _, exists := rm.Royalties[tokenID]; exists {
		return errors.New("royalty already set for this token")
	}

	rm.Royalties[tokenID] = &Royalty{
		TokenID:        tokenID,
		OriginalCreator: creator,
		RoyaltyRate:    rate,
		Payments:       []Payment{},
		Encrypted:      false,
	}
	return nil
}

// UpdateRoyalty updates the royalty rate for a SYN722 token.
func (rm *RoyaltyManager) UpdateRoyalty(tokenID string, newRate float64) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	royalty, exists := rm.Royalties[tokenID]
	if !exists {
		return errors.New("royalty not found for this token")
	}

	if royalty.Encrypted {
		return errors.New("cannot update encrypted royalty")
	}

	royalty.RoyaltyRate = newRate
	return nil
}

// RecordPayment records a royalty payment for a SYN722 token.
func (rm *RoyaltyManager) RecordPayment(tokenID, payer string, amount float64) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	royalty, exists := rm.Royalties[tokenID]
	if !exists {
		return errors.New("royalty not found for this token")
	}

	payment := Payment{
		Timestamp: time.Now(),
		Amount:    amount,
		Payer:     payer,
	}

	royalty.Payments = append(royalty.Payments, payment)
	return nil
}

// GetRoyalty retrieves the royalty details for a SYN722 token.
func (rm *RoyaltyManager) GetRoyalty(tokenID string) (*Royalty, error) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	royalty, exists := rm.Royalties[tokenID]
	if !exists {
		return nil, errors.New("royalty not found for this token")
	}

	return royalty, nil
}

// EncryptRoyalty encrypts the royalty details using AES encryption.
func (rm *RoyaltyManager) EncryptRoyalty(tokenID, key string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	royalty, exists := rm.Royalties[tokenID]
	if !exists {
		return errors.New("royalty not found for this token")
	}

	if royalty.Encrypted {
		return errors.New("royalty details are already encrypted")
	}

	plaintext, err := json.Marshal(royalty)
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
	royalty.Payments = []Payment{{
		Timestamp: time.Now(),
		Amount:    0,
		Payer:     base64.StdEncoding.EncodeToString(ciphertext),
	}}
	royalty.Encrypted = true

	return nil
}

// DecryptRoyalty decrypts the royalty details using AES decryption.
func (rm *RoyaltyManager) DecryptRoyalty(tokenID, key string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	royalty, exists := rm.Royalties[tokenID]
	if !exists {
		return errors.New("royalty not found for this token")
	}

	if !royalty.Encrypted {
		return errors.New("royalty details are not encrypted")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(royalty.Payments[0].Payer)
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

	err = json.Unmarshal(plaintext, royalty)
	if err != nil {
		return err
	}

	royalty.Encrypted = false
	return nil
}

// DisplayRoyalty provides a JSON representation of the royalty details for easy viewing.
func (rm *RoyaltyManager) DisplayRoyalty(tokenID string) (string, error) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	royalty, exists := rm.Royalties[tokenID]
	if !exists {
		return "", errors.New("royalty not found for this token")
	}

	data, err := json.MarshalIndent(royalty, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data), nil
}
