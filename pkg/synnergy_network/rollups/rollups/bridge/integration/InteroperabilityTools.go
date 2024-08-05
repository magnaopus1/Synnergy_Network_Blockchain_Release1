package integration

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "io"
    "time"

    "github.com/google/uuid"
    "golang.org/x/crypto/argon2"
)

// InteropTool represents a tool for blockchain interoperability
type InteropTool struct {
    ID            string
    SourceChain   string
    DestinationChain string
    Action        string
    Timestamp     time.Time
    Status        string
    DataHash      string
    EncryptedData string
}

// InteroperabilityTools handles tools for blockchain interoperability
type InteroperabilityTools struct {
    Tools map[string]InteropTool
}

// NewInteroperabilityTools initializes a new InteroperabilityTools
func NewInteroperabilityTools() *InteroperabilityTools {
    return &InteroperabilityTools{
        Tools: make(map[string]InteropTool),
    }
}

// CreateInteropTool creates a new interoperability tool with encryption
func (it *InteroperabilityTools) CreateInteropTool(sourceChain, destinationChain, action, data, secret string) (string, error) {
    id := uuid.New().String()
    dataHash := createHash(data)
    encryptedData, err := encryptData(secret, data)
    if err != nil {
        return "", err
    }
    tool := InteropTool{
        ID:               id,
        SourceChain:      sourceChain,
        DestinationChain: destinationChain,
        Action:           action,
        Timestamp:        time.Now(),
        Status:           "pending",
        DataHash:         dataHash,
        EncryptedData:    encryptedData,
    }
    it.Tools[id] = tool
    return id, nil
}

// VerifyInteropTool verifies the integrity of an interoperability tool
func (it *InteroperabilityTools) VerifyInteropTool(id, data string) (bool, error) {
    tool, exists := it.Tools[id]
    if !exists {
        return false, errors.New("interoperability tool does not exist")
    }
    dataHash := createHash(data)
    return dataHash == tool.DataHash, nil
}

// CompleteInteropTool completes an interoperability tool
func (it *InteroperabilityTools) CompleteInteropTool(id string) error {
    tool, exists := it.Tools[id]
    if !exists {
        return errors.New("interoperability tool does not exist")
    }
    if tool.Status != "pending" {
        return errors.New("interoperability tool is not pending")
    }
    tool.Status = "completed"
    it.Tools[id] = tool
    return nil
}

// GetInteropTool retrieves an interoperability tool by ID and decrypts it
func (it *InteroperabilityTools) GetInteropTool(id, secret string) (InteropTool, error) {
    tool, exists := it.Tools[id]
    if !exists {
        return InteropTool{}, errors.New("interoperability tool does not exist")
    }
    decryptedData, err := decryptData(secret, tool.EncryptedData)
    if err != nil {
        return InteropTool{}, err
    }
    tool.EncryptedData = decryptedData
    return tool, nil
}

// ListInteropTools lists all interoperability tools
func (it *InteroperabilityTools) ListInteropTools() []InteropTool {
    tools := []InteropTool{}
    for _, tool := range it.Tools {
        tools = append(tools, tool)
    }
    return tools
}

// EncryptData encrypts the given data using AES
func encryptData(secret, data string) (string, error) {
    block, err := aes.NewCipher([]byte(createHash(secret)))
    if err != nil {
        return "", err
    }
    aesGCM, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }
    nonce := make([]byte, aesGCM.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        return "", err
    }
    encrypted := aesGCM.Seal(nonce, nonce, []byte(data), nil)
    return hex.EncodeToString(encrypted), nil
}

// DecryptData decrypts the given data using AES
func decryptData(secret, encryptedData string) (string, error) {
    data, err := hex.DecodeString(encryptedData)
    if err != nil {
        return "", err
    }
    block, err := aes.NewCipher([]byte(createHash(secret)))
    if err != nil {
        return "", err
    }
    aesGCM, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }
    nonceSize := aesGCM.NonceSize()
    if len(data) < nonceSize {
        return "", errors.New("ciphertext too short")
    }
    nonce, ciphertext := data[:nonceSize], data[nonceSize:]
    decrypted, err := aesGCM.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return "", err
    }
    return string(decrypted), nil
}

// CreateHash creates a hash from the secret key
func createHash(key string) string {
    hasher := sha256.New()
    hasher.Write([]byte(key))
    return hex.EncodeToString(hasher.Sum(nil))
}

// GenerateSignature generates a signature for the interoperability tool using Argon2
func generateSignature(data, secret string) string {
    salt := make([]byte, 16)
    _, _ = rand.Read(salt)
    hash := argon2.IDKey([]byte(data), salt, 1, 64*1024, 4, 32)
    return hex.EncodeToString(hash)
}
