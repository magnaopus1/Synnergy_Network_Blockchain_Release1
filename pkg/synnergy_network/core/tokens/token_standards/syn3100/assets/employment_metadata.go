package assets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"golang.org/x/crypto/argon2"
)

// EmploymentMetadata represents the metadata of an employment contract.
type EmploymentMetadata struct {
	ContractID    string
	EmployeeID    string
	EmployerID    string
	Position      string
	Salary        float64
	ContractType  string
	StartDate     time.Time
	EndDate       *time.Time
	Benefits      []string
	ContractTerms string
	ActiveStatus  bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// EmploymentMetadataStore stores employment metadata securely.
type EmploymentMetadataStore struct {
	data map[string]EmploymentMetadata
	salt []byte
}

// NewEmploymentMetadataStore initializes a new EmploymentMetadataStore.
func NewEmploymentMetadataStore() *EmploymentMetadataStore {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		panic(err)
	}
	return &EmploymentMetadataStore{
		data: make(map[string]EmploymentMetadata),
		salt: salt,
	}
}

// GenerateContractID generates a unique contract ID using SHA-256.
func GenerateContractID() (string, error) {
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(randomBytes)
	return hex.EncodeToString(hash[:]), nil
}

// AddContract adds a new employment contract to the store.
func (store *EmploymentMetadataStore) AddContract(metadata EmploymentMetadata) (string, error) {
	contractID, err := GenerateContractID()
	if err != nil {
		return "", err
	}
	metadata.ContractID = contractID
	metadata.CreatedAt = time.Now()
	metadata.UpdatedAt = time.Now()
	store.data[contractID] = metadata
	return contractID, nil
}

// GetContract retrieves the metadata of an employment contract by its ID.
func (store *EmploymentMetadataStore) GetContract(contractID string) (EmploymentMetadata, error) {
	metadata, exists := store.data[contractID]
	if !exists {
		return EmploymentMetadata{}, errors.New("contract not found")
	}
	return metadata, nil
}

// UpdateContract updates an existing employment contract.
func (store *EmploymentMetadataStore) UpdateContract(contractID string, updatedMetadata EmploymentMetadata) error {
	metadata, exists := store.data[contractID]
	if !exists {
		return errors.New("contract not found")
	}
	updatedMetadata.ContractID = contractID
	updatedMetadata.CreatedAt = metadata.CreatedAt
	updatedMetadata.UpdatedAt = time.Now()
	store.data[contractID] = updatedMetadata
	return nil
}

// DeleteContract removes an employment contract from the store.
func (store *EmploymentMetadataStore) DeleteContract(contractID string) error {
	_, exists := store.data[contractID]
	if !exists {
		return errors.New("contract not found")
	}
	delete(store.data, contractID)
	return nil
}

// EncryptContractMetadata encrypts the contract metadata using AES.
func EncryptContractMetadata(metadata EmploymentMetadata, password string) (string, error) {
	serializedData, err := serializeContractMetadata(metadata)
	if err != nil {
		return "", err
	}

	key := argon2.Key([]byte(password), []byte("somesalt"), 1, 64*1024, 4, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(serializedData))
	iv := ciphertext[:aes.BlockSize]
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], serializedData)

	return hex.EncodeToString(ciphertext), nil
}

// DecryptContractMetadata decrypts the contract metadata using AES.
func DecryptContractMetadata(encryptedData, password string) (EmploymentMetadata, error) {
	ciphertext, err := hex.DecodeString(encryptedData)
	if err != nil {
		return EmploymentMetadata{}, err
	}

	key := argon2.Key([]byte(password), []byte("somesalt"), 1, 64*1024, 4, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return EmploymentMetadata{}, err
	}

	if len(ciphertext) < aes.BlockSize {
		return EmploymentMetadata{}, errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	metadata, err := deserializeContractMetadata(ciphertext)
	if err != nil {
		return EmploymentMetadata{}, err
	}

	return metadata, nil
}

// serializeContractMetadata serializes contract metadata to a byte slice.
func serializeContractMetadata(metadata EmploymentMetadata) ([]byte, error) {
	// Implement the serialization logic (e.g., using JSON or Protocol Buffers)
	return nil, nil
}

// deserializeContractMetadata deserializes contract metadata from a byte slice.
func deserializeContractMetadata(data []byte) (EmploymentMetadata, error) {
	// Implement the deserialization logic (e.g., using JSON or Protocol Buffers)
	return EmploymentMetadata{}, nil
}

// ValidateContractMetadata validates the fields of the contract metadata.
func ValidateContractMetadata(metadata EmploymentMetadata) error {
	if metadata.ContractID == "" {
		return errors.New("contract ID cannot be empty")
	}
	if metadata.EmployeeID == "" {
		return errors.New("employee ID cannot be empty")
	}
	if metadata.EmployerID == "" {
		return errors.New("employer ID cannot be empty")
	}
	if metadata.Position == "" {
		return errors.New("position cannot be empty")
	}
	if metadata.Salary <= 0 {
		return errors.New("salary must be greater than zero")
	}
	if metadata.ContractType == "" {
		return errors.New("contract type cannot be empty")
	}
	if metadata.StartDate.IsZero() {
		return errors.New("start date cannot be empty")
	}
	if metadata.ContractTerms == "" {
		return errors.New("contract terms cannot be empty")
	}
	return nil
}
