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
)

// Syn722Metadata represents the detailed information of a token in non-fungible mode.
type Syn722Metadata struct {
	ID         string            `json:"id"`
	Owner      string            `json:"owner"`
	Mode       string            `json:"mode"` // fungible or non-fungible
	Quantity   int               `json:"quantity"`
	Attributes map[string]string `json:"attributes"`
	Encrypted  bool              `json:"encrypted"`
}

// EncryptMetadata encrypts the metadata using AES encryption.
func (m *Metadata) EncryptMetadata(key string) error {
	if m.Encrypted {
		return errors.New("metadata is already encrypted")
	}

	plaintext, err := json.Marshal(m)
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
	m.Attributes["encrypted_data"] = base64.StdEncoding.EncodeToString(ciphertext)
	m.Encrypted = true

	return nil
}

// DecryptMetadata decrypts the metadata using AES decryption.
func (m *Metadata) DecryptMetadata(key string) error {
	if !m.Encrypted {
		return errors.New("metadata is not encrypted")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(m.Attributes["encrypted_data"])
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

	err = json.Unmarshal(plaintext, m)
	if err != nil {
		return err
	}

	delete(m.Attributes, "encrypted_data")
	m.Encrypted = false

	return nil
}

// NewMetadata creates a new Metadata instance.
func NewMetadata(id, owner, mode string, quantity int, attributes map[string]string) *Metadata {
	return &Metadata{
		ID:         id,
		Owner:      owner,
		Mode:       mode,
		Quantity:   quantity,
		Attributes: attributes,
		Encrypted:  false,
	}
}

// UpdateMetadata updates the attributes of the metadata.
func (m *Metadata) UpdateMetadata(attributes map[string]string) error {
	if m.Encrypted {
		return errors.New("cannot update encrypted metadata")
	}

	for k, v := range attributes {
		m.Attributes[k] = v
	}

	return nil
}

// DisplayMetadata provides a JSON representation of the metadata for easy viewing.
func (m *Metadata) DisplayMetadata() (string, error) {
	if m.Encrypted {
		return "", errors.New("metadata is encrypted")
	}

	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// ValidateMetadata ensures that the metadata follows the SYN722 standard.
func (m *Metadata) ValidateMetadata() error {
	if m.ID == "" || m.Owner == "" || m.Mode == "" {
		return errors.New("metadata missing required fields")
	}

	if m.Mode != "fungible" && m.Mode != "non-fungible" {
		return errors.New("invalid mode")
	}

	if m.Quantity < 0 {
		return errors.New("quantity cannot be negative")
	}

	return nil
}

// SwitchMode toggles the token mode between fungible and non-fungible.
func (m *Metadata) SwitchMode() error {
	if m.Mode == "fungible" {
		m.Mode = "non-fungible"
	} else if m.Mode == "non-fungible" {
		m.Mode = "fungible"
	} else {
		return errors.New("invalid mode")
	}
	return nil
}

// History of mode changes (simplified for example)
var modeHistory []string

// LogModeChange logs the mode change to the history.
func (m *Metadata) LogModeChange() {
	entry := fmt.Sprintf("Mode changed to %s at %s", m.Mode, m.ID)
	modeHistory = append(modeHistory, entry)
}

// GetModeHistory retrieves the mode change history.
func GetModeHistory() []string {
	return modeHistory
}
