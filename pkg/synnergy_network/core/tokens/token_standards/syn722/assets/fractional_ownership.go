package assets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// FractionalOwnership represents the details of fractional ownership of an asset.
type FractionalOwnership struct {
	TokenID          string               `json:"token_id"`
	TotalShares      int                  `json:"total_shares"`
	OwnershipRecords map[string]int       `json:"ownership_records"` // map of owner addresses to number of shares
	History          []OwnershipChangeLog `json:"history"`
	Encrypted        bool                 `json:"encrypted"`
}

// OwnershipChangeLog represents a log entry for changes in ownership.
type OwnershipChangeLog struct {
	Timestamp   time.Time `json:"timestamp"`
	Action      string    `json:"action"`
	Details     string    `json:"details"`
}

// EncryptOwnership encrypts the ownership details using AES encryption.
func (fo *FractionalOwnership) EncryptOwnership(key string) error {
	if fo.Encrypted {
		return errors.New("ownership details are already encrypted")
	}

	plaintext, err := json.Marshal(fo)
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
	fo.History = []OwnershipChangeLog{{
		Timestamp: time.Now(),
		Action:    "encrypted",
		Details:   base64.StdEncoding.EncodeToString(ciphertext),
	}}
	fo.Encrypted = true

	return nil
}

// DecryptOwnership decrypts the ownership details using AES decryption.
func (fo *FractionalOwnership) DecryptOwnership(key string) error {
	if !fo.Encrypted {
		return errors.New("ownership details are not encrypted")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(fo.History[0].Details)
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

	err = json.Unmarshal(plaintext, fo)
	if err != nil {
		return err
	}

	fo.Encrypted = false

	return nil
}

// NewFractionalOwnership creates a new FractionalOwnership instance.
func NewFractionalOwnership(tokenID string, totalShares int) *FractionalOwnership {
	return &FractionalOwnership{
		TokenID:          tokenID,
		TotalShares:      totalShares,
		OwnershipRecords: make(map[string]int),
		History: []OwnershipChangeLog{
			{
				Timestamp: time.Now(),
				Action:    "created",
				Details:   fmt.Sprintf("Token %s created with %d total shares", tokenID, totalShares),
			},
		},
		Encrypted: false,
	}
}

// TransferShares transfers shares from one owner to another.
func (fo *FractionalOwnership) TransferShares(from, to string, shares int) error {
	if fo.Encrypted {
		return errors.New("cannot transfer shares of encrypted ownership details")
	}

	if shares <= 0 {
		return errors.New("shares to transfer should be positive")
	}

	if fo.OwnershipRecords[from] < shares {
		return errors.New("insufficient shares to transfer")
	}

	fo.OwnershipRecords[from] -= shares
	if fo.OwnershipRecords[to] == 0 {
		fo.OwnershipRecords[to] = shares
	} else {
		fo.OwnershipRecords[to] += shares
	}

	entry := OwnershipChangeLog{
		Timestamp: time.Now(),
		Action:    "transfer",
		Details:   fmt.Sprintf("Transferred %d shares from %s to %s", shares, from, to),
	}

	fo.History = append(fo.History, entry)
	return nil
}

// AddOwnershipRecord adds a new ownership record or updates an existing one.
func (fo *FractionalOwnership) AddOwnershipRecord(owner string, shares int) error {
	if fo.Encrypted {
		return errors.New("cannot add ownership record to encrypted ownership details")
	}

	if shares <= 0 {
		return errors.New("shares should be positive")
	}

	if fo.OwnershipRecords[owner] == 0 {
		fo.OwnershipRecords[owner] = shares
	} else {
		fo.OwnershipRecords[owner] += shares
	}

	entry := OwnershipChangeLog{
		Timestamp: time.Now(),
		Action:    "add_record",
		Details:   fmt.Sprintf("Added/Updated %d shares for owner %s", shares, owner),
	}

	fo.History = append(fo.History, entry)
	return nil
}

// RemoveOwnershipRecord removes an ownership record for an owner.
func (fo *FractionalOwnership) RemoveOwnershipRecord(owner string) error {
	if fo.Encrypted {
		return errors.New("cannot remove ownership record from encrypted ownership details")
	}

	if _, exists := fo.OwnershipRecords[owner]; !exists {
		return errors.New("ownership record not found")
	}

	delete(fo.OwnershipRecords, owner)

	entry := OwnershipChangeLog{
		Timestamp: time.Now(),
		Action:    "remove_record",
		Details:   fmt.Sprintf("Removed ownership record for owner %s", owner),
	}

	fo.History = append(fo.History, entry)
	return nil
}

// DisplayOwnershipDetails provides a JSON representation of the ownership details for easy viewing.
func (fo *FractionalOwnership) DisplayOwnershipDetails() (string, error) {
	if fo.Encrypted {
		return "", errors.New("ownership details are encrypted")
	}

	data, err := json.MarshalIndent(fo, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// ValidateOwnership ensures that the ownership details follow the SYN722 standard.
func (fo *FractionalOwnership) ValidateOwnership() error {
	if fo.TokenID == "" {
		return errors.New("ownership details missing required token ID")
	}

	if fo.TotalShares <= 0 {
		return errors.New("total shares should be positive")
	}

	if len(fo.History) == 0 {
		return errors.New("ownership details must have at least one history entry")
	}

	return nil
}

// LogOwnershipEvent logs a significant event in the ownership history.
func (fo *FractionalOwnership) LogOwnershipEvent(action, details string) {
	entry := OwnershipChangeLog{
		Timestamp: time.Now(),
		Action:    action,
		Details:   details,
	}
	fo.History = append(fo.History, entry)
}
