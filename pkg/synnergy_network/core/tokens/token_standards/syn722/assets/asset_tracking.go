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

// AssetHistoryEntry represents an entry in the asset's history log.
type AssetHistoryEntry struct {
	Timestamp   time.Time `json:"timestamp"`
	Action      string    `json:"action"`
	Details     string    `json:"details"`
}

// AssetTracking represents the tracking details and history of an asset.
type AssetTracking struct {
	TokenID        string               `json:"token_id"`
	CurrentOwner   string               `json:"current_owner"`
	PreviousOwners []string             `json:"previous_owners"`
	History        []AssetHistoryEntry  `json:"history"`
	Encrypted      bool                 `json:"encrypted"`
}

// EncryptTracking encrypts the tracking details using AES encryption.
func (at *AssetTracking) EncryptTracking(key string) error {
	if at.Encrypted {
		return errors.New("tracking details are already encrypted")
	}

	plaintext, err := json.Marshal(at)
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
	at.History = []AssetHistoryEntry{{
		Timestamp: time.Now(),
		Action:    "encrypted",
		Details:   base64.StdEncoding.EncodeToString(ciphertext),
	}}
	at.Encrypted = true

	return nil
}

// DecryptTracking decrypts the tracking details using AES decryption.
func (at *AssetTracking) DecryptTracking(key string) error {
	if !at.Encrypted {
		return errors.New("tracking details are not encrypted")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(at.History[0].Details)
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

	err = json.Unmarshal(plaintext, at)
	if err != nil {
		return err
	}

	at.Encrypted = false

	return nil
}

// NewAssetTracking creates a new AssetTracking instance.
func NewAssetTracking(tokenID, owner string) *AssetTracking {
	return &AssetTracking{
		TokenID:      tokenID,
		CurrentOwner: owner,
		History: []AssetHistoryEntry{
			{
				Timestamp: time.Now(),
				Action:    "created",
				Details:   fmt.Sprintf("Token %s created with owner %s", tokenID, owner),
			},
		},
		Encrypted: false,
	}
}

// TransferOwnership transfers the ownership of the asset to a new owner.
func (at *AssetTracking) TransferOwnership(newOwner string) error {
	if at.Encrypted {
		return errors.New("cannot transfer ownership of encrypted tracking details")
	}

	at.PreviousOwners = append(at.PreviousOwners, at.CurrentOwner)
	at.CurrentOwner = newOwner

	entry := AssetHistoryEntry{
		Timestamp: time.Now(),
		Action:    "ownership_transfer",
		Details:   fmt.Sprintf("Ownership transferred to %s", newOwner),
	}

	at.History = append(at.History, entry)
	return nil
}

// AddHistoryEntry adds a new entry to the asset's history.
func (at *AssetTracking) AddHistoryEntry(action, details string) error {
	if at.Encrypted {
		return errors.New("cannot add history entry to encrypted tracking details")
	}

	entry := AssetHistoryEntry{
		Timestamp: time.Now(),
		Action:    action,
		Details:   details,
	}

	at.History = append(at.History, entry)
	return nil
}

// DisplayTrackingDetails provides a JSON representation of the tracking details for easy viewing.
func (at *AssetTracking) DisplayTrackingDetails() (string, error) {
	if at.Encrypted {
		return "", errors.New("tracking details are encrypted")
	}

	data, err := json.MarshalIndent(at, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// ValidateTracking ensures that the tracking details follow the SYN722 standard.
func (at *AssetTracking) ValidateTracking() error {
	if at.TokenID == "" || at.CurrentOwner == "" {
		return errors.New("tracking details missing required fields")
	}

	if len(at.History) == 0 {
		return errors.New("tracking details must have at least one history entry")
	}

	return nil
}

// LogEvent logs a significant event in the asset's history.
func (at *AssetTracking) LogEvent(action, details string) {
	entry := AssetHistoryEntry{
		Timestamp: time.Now(),
		Action:    action,
		Details:   details,
	}
	at.History = append(at.History, entry)
}
