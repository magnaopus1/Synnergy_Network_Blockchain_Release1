package integration

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "io"
    "sync"

    "golang.org/x/crypto/scrypt"
    "golang.org/x/crypto/argon2"
)

// BlockchainNetwork represents a generic blockchain network for interoperability.
type BlockchainNetwork struct {
    Name     string
    URL      string
    ApiKey   string
    NodeType string
}

// TokenDetails holds the information of a token.
type TokenDetails struct {
    ID          string
    Name        string
    Owner       string
    Value       float64
    Metadata    map[string]string
    History     []TransactionRecord
    Lock        sync.RWMutex
}

// TransactionRecord represents a transaction on the blockchain.
type TransactionRecord struct {
    From   string
    To     string
    Amount float64
    Date   string
}

// InteroperabilityManager handles the integration with multiple blockchain networks.
type InteroperabilityManager struct {
    Networks []BlockchainNetwork
}

// NewInteroperabilityManager creates a new instance of InteroperabilityManager.
func NewInteroperabilityManager() *InteroperabilityManager {
    return &InteroperabilityManager{
        Networks: make([]BlockchainNetwork, 0),
    }
}

// AddNetwork adds a new blockchain network for interoperability.
func (manager *InteroperabilityManager) AddNetwork(name, url, apiKey, nodeType string) {
    manager.Networks = append(manager.Networks, BlockchainNetwork{
        Name:     name,
        URL:      url,
        ApiKey:   apiKey,
        NodeType: nodeType,
    })
}

// EncryptData encrypts the given data using AES.
func EncryptData(data, passphrase string) (string, error) {
    salt := make([]byte, 16)
    if _, err := io.ReadFull(rand.Reader, salt); err != nil {
        return "", err
    }

    key, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
    if err != nil {
        return "", err
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return "", err
    }

    encryptedData := gcm.Seal(nonce, nonce, []byte(data), nil)
    return hex.EncodeToString(append(salt, encryptedData...)), nil
}

// DecryptData decrypts the given encrypted data using AES.
func DecryptData(encryptedData, passphrase string) (string, error) {
    data, err := hex.DecodeString(encryptedData)
    if err != nil {
        return "", err
    }

    salt := data[:16]
    ciphertext := data[16:]

    key, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
    if err != nil {
        return "", err
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    nonceSize := gcm.NonceSize()
    if len(ciphertext) < nonceSize {
        return "", errors.New("ciphertext too short")
    }

    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    decryptedData, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return "", err
    }

    return string(decryptedData), nil
}

// HashData hashes the given data using SHA-256.
func HashData(data string) string {
    hash := sha256.Sum256([]byte(data))
    return hex.EncodeToString(hash[:])
}

// DeriveKey derives a secure key using Argon2.
func DeriveKey(password, salt string) []byte {
    return argon2.IDKey([]byte(password), []byte(salt), 1, 64*1024, 4, 32)
}

// ValidateTransaction ensures the transaction data is valid.
func ValidateTransaction(from, to string, amount float64) error {
    if from == "" || to == "" {
        return errors.New("invalid from or to address")
    }
    if amount <= 0 {
        return errors.New("amount must be greater than zero")
    }
    return nil
}

// TransferOwnership transfers the ownership of a token.
func (token *TokenDetails) TransferOwnership(newOwner string, amount float64, date string) error {
    token.Lock.Lock()
    defer token.Lock.Unlock()

    err := ValidateTransaction(token.Owner, newOwner, amount)
    if err != nil {
        return err
    }

    token.History = append(token.History, TransactionRecord{
        From:   token.Owner,
        To:     newOwner,
        Amount: amount,
        Date:   date,
    })
    token.Owner = newOwner
    return nil
}

// AddMetadata adds metadata to the token.
func (token *TokenDetails) AddMetadata(key, value string) {
    token.Lock.Lock()
    defer token.Lock.Unlock()

    if token.Metadata == nil {
        token.Metadata = make(map[string]string)
    }
    token.Metadata[key] = value
}

// VerifyOwnership verifies if the given user is the owner of the token.
func (token *TokenDetails) VerifyOwnership(user string) bool {
    token.Lock.RLock()
    defer token.Lock.RUnlock()

    return token.Owner == user
}

// GetTransactionHistory returns the transaction history of the token.
func (token *TokenDetails) GetTransactionHistory() []TransactionRecord {
    token.Lock.RLock()
    defer token.Lock.RUnlock()

    return token.History
}
