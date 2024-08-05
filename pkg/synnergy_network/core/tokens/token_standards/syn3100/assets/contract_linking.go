package assets

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "io"
    "sync"
    "time"

    "golang.org/x/crypto/argon2"
)

// ContractMetadata represents the metadata of an employment contract.
type ContractMetadata struct {
    ContractID     string
    EmployeeID     string
    EmployerID     string
    Position       string
    Salary         float64
    ContractType   string
    StartDate      time.Time
    EndDate        *time.Time
    Benefits       []string
    ContractTerms  string
    ActiveStatus   bool
    CreatedAt      time.Time
    UpdatedAt      time.Time
}

// ContractLinking is responsible for linking employment tokens to specific contracts.
type ContractLinking struct {
    sync.RWMutex
    contracts map[string]ContractMetadata
    salt      []byte
}

// NewContractLinking initializes a new ContractLinking instance.
func NewContractLinking() *ContractLinking {
    salt := make([]byte, 16)
    _, err := rand.Read(salt)
    if err != nil {
        panic(err)
    }
    return &ContractLinking{
        contracts: make(map[string]ContractMetadata),
        salt:      salt,
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

// CreateContract creates a new contract and links it to an employment token.
func (cl *ContractLinking) CreateContract(metadata ContractMetadata) (string, error) {
    cl.Lock()
    defer cl.Unlock()

    contractID, err := GenerateContractID()
    if err != nil {
        return "", err
    }
    metadata.ContractID = contractID
    metadata.CreatedAt = time.Now()
    metadata.UpdatedAt = time.Now()
    cl.contracts[contractID] = metadata

    return contractID, nil
}

// GetContract retrieves the metadata of a contract by its ID.
func (cl *ContractLinking) GetContract(contractID string) (ContractMetadata, error) {
    cl.RLock()
    defer cl.RUnlock()

    metadata, exists := cl.contracts[contractID]
    if !exists {
        return ContractMetadata{}, errors.New("contract not found")
    }

    return metadata, nil
}

// UpdateContract updates the metadata of an existing contract.
func (cl *ContractLinking) UpdateContract(contractID string, updatedMetadata ContractMetadata) error {
    cl.Lock()
    defer cl.Unlock()

    metadata, exists := cl.contracts[contractID]
    if !exists {
        return errors.New("contract not found")
    }

    updatedMetadata.ContractID = contractID
    updatedMetadata.CreatedAt = metadata.CreatedAt
    updatedMetadata.UpdatedAt = time.Now()
    cl.contracts[contractID] = updatedMetadata

    return nil
}

// DeleteContract removes a contract from the linking system.
func (cl *ContractLinking) DeleteContract(contractID string) error {
    cl.Lock()
    defer cl.Unlock()

    _, exists := cl.contracts[contractID]
    if !exists {
        return errors.New("contract not found")
    }

    delete(cl.contracts, contractID)
    return nil
}

// VerifyOwnership verifies that the contract is linked to the specified employee.
func (cl *ContractLinking) VerifyOwnership(contractID, employeeID string) (bool, error) {
    cl.RLock()
    defer cl.RUnlock()

    metadata, exists := cl.contracts[contractID]
    if !exists {
        return false, errors.New("contract not found")
    }

    return metadata.EmployeeID == employeeID, nil
}

// EncryptContractMetadata encrypts the contract metadata using AES.
func EncryptContractMetadata(metadata ContractMetadata, password string) (string, error) {
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
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return "", err
    }

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ciphertext[aes.BlockSize:], serializedData)

    return hex.EncodeToString(ciphertext), nil
}

// DecryptContractMetadata decrypts the contract metadata using AES.
func DecryptContractMetadata(encryptedData, password string) (ContractMetadata, error) {
    ciphertext, err := hex.DecodeString(encryptedData)
    if err != nil {
        return ContractMetadata{}, err
    }

    key := argon2.Key([]byte(password), []byte("somesalt"), 1, 64*1024, 4, 32)
    block, err := aes.NewCipher(key)
    if err != nil {
        return ContractMetadata{}, err
    }

    if len(ciphertext) < aes.BlockSize {
        return ContractMetadata{}, errors.New("ciphertext too short")
    }

    iv := ciphertext[:aes.BlockSize]
    ciphertext = ciphertext[aes.BlockSize:]

    stream := cipher.NewCFBDecrypter(block, iv)
    stream.XORKeyStream(ciphertext, ciphertext)

    metadata, err := deserializeContractMetadata(ciphertext)
    if err != nil {
        return ContractMetadata{}, err
    }

    return metadata, nil
}

// serializeContractMetadata serializes contract metadata to a byte slice.
func serializeContractMetadata(metadata ContractMetadata) ([]byte, error) {
    // Implement the serialization logic (e.g., using JSON or Protocol Buffers)
    return nil, nil
}

// deserializeContractMetadata deserializes contract metadata from a byte slice.
func deserializeContractMetadata(data []byte) (ContractMetadata, error) {
    // Implement the deserialization logic (e.g., using JSON or Protocol Buffers)
    return ContractMetadata{}, nil
}
