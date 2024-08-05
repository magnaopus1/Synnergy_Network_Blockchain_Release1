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

// AssetValuation represents the valuation details of an asset.
type AssetValuation struct {
	TokenID       string            `json:"token_id"`
	CurrentValue  float64           `json:"current_value"`
	ValuationDate time.Time         `json:"valuation_date"`
	History       []ValuationRecord `json:"history"`
	Encrypted     bool              `json:"encrypted"`
}

// ValuationRecord represents a record of valuation changes for an asset.
type ValuationRecord struct {
	Date     time.Time `json:"date"`
	Value    float64   `json:"value"`
	Comments string    `json:"comments"`
}

// EncryptValuation encrypts the valuation details using AES encryption.
func (av *AssetValuation) EncryptValuation(key string) error {
	if av.Encrypted {
		return errors.New("valuation details are already encrypted")
	}

	plaintext, err := json.Marshal(av)
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
	av.History = []ValuationRecord{{
		Date:     time.Now(),
		Value:    av.CurrentValue,
		Comments: base64.StdEncoding.EncodeToString(ciphertext),
	}}
	av.Encrypted = true

	return nil
}

// DecryptValuation decrypts the valuation details using AES decryption.
func (av *AssetValuation) DecryptValuation(key string) error {
	if !av.Encrypted {
		return errors.New("valuation details are not encrypted")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(av.History[0].Comments)
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

	err = json.Unmarshal(plaintext, av)
	if err != nil {
		return err
	}

	av.Encrypted = false

	return nil
}

// NewAssetValuation creates a new AssetValuation instance.
func NewAssetValuation(tokenID string, initialValue float64) *AssetValuation {
	return &AssetValuation{
		TokenID:      tokenID,
		CurrentValue: initialValue,
		ValuationDate: time.Now(),
		History: []ValuationRecord{
			{
				Date:  time.Now(),
				Value: initialValue,
				Comments: fmt.Sprintf("Initial valuation set at %f", initialValue),
			},
		},
		Encrypted: false,
	}
}

// UpdateValuation updates the current valuation of the asset.
func (av *AssetValuation) UpdateValuation(newValue float64, comments string) error {
	if av.Encrypted {
		return errors.New("cannot update valuation of encrypted details")
	}

	record := ValuationRecord{
		Date:     time.Now(),
		Value:    newValue,
		Comments: comments,
	}

	av.CurrentValue = newValue
	av.ValuationDate = time.Now()
	av.History = append(av.History, record)
	return nil
}

// DisplayValuationDetails provides a JSON representation of the valuation details for easy viewing.
func (av *AssetValuation) DisplayValuationDetails() (string, error) {
	if av.Encrypted {
		return "", errors.New("valuation details are encrypted")
	}

	data, err := json.MarshalIndent(av, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// ValidateValuation ensures that the valuation details follow the SYN722 standard.
func (av *AssetValuation) ValidateValuation() error {
	if av.TokenID == "" {
		return errors.New("valuation details missing required token ID")
	}

	if av.CurrentValue < 0 {
		return errors.New("current value cannot be negative")
	}

	if len(av.History) == 0 {
		return errors.New("valuation details must have at least one history entry")
	}

	return nil
}

// LogValuationEvent logs a significant event in the valuation history.
func (av *AssetValuation) LogValuationEvent(action, details string) {
	entry := ValuationRecord{
		Date:     time.Now(),
		Value:    av.CurrentValue,
		Comments: fmt.Sprintf("%s: %s", action, details),
	}
	av.History = append(av.History, entry)
}
