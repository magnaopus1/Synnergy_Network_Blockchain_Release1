package predictive_maintenance

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log"
	"time"

	"golang.org/x/crypto/argon2"
)

// Define the structure for predictive maintenance models
type PredictiveModel struct {
	ID          string    `json:"id"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	ModelData   []byte    `json:"model_data"` // encrypted model data
}

// EncryptionKey stores the key used for encrypting model data
var EncryptionKey []byte

// Initialize the predictive model system with an encryption key
func Init(key []byte) {
	if len(key) != 32 {
		log.Fatal("Encryption key must be 32 bytes long")
	}
	EncryptionKey = key
}

// Create a new predictive model
func NewPredictiveModel(id, description string, modelData []byte) (*PredictiveModel, error) {
	encryptedData, err := encryptData(modelData, EncryptionKey)
	if err != nil {
		return nil, err
	}

	model := &PredictiveModel{
		ID:          id,
		Description: description,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		ModelData:   encryptedData,
	}
	return model, nil
}

// Update an existing predictive model
func (pm *PredictiveModel) Update(description string, modelData []byte) error {
	encryptedData, err := encryptData(modelData, EncryptionKey)
	if err != nil {
		return err
	}

	pm.Description = description
	pm.UpdatedAt = time.Now()
	pm.ModelData = encryptedData
	return nil
}

// Encrypt data using AES-256
func encryptData(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// Decrypt data using AES-256
func decryptData(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(data) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Serialize the predictive model to JSON
func (pm *PredictiveModel) ToJSON() ([]byte, error) {
	return json.Marshal(pm)
}

// Deserialize the predictive model from JSON
func FromJSON(data []byte) (*PredictiveModel, error) {
	var model PredictiveModel
	err := json.Unmarshal(data, &model)
	if err != nil {
		return nil, err
	}
	return &model, nil
}

// HashPassword hashes a password using Argon2
func HashPassword(password string, salt []byte) ([]byte, error) {
	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	return hash, nil
}

// GenerateSalt generates a random salt for hashing
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}
