package contracts

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

// BridgeTransaction represents a transaction across the bridge
type BridgeTransaction struct {
    ID            string
    SourceChain   string
    DestinationChain string
    Amount        float64
    Sender        string
    Receiver      string
    Timestamp     time.Time
    Status        string
    EncryptedData string
}

// SecureBridges handles secure transactions between blockchains
type SecureBridges struct {
    Transactions map[string]BridgeTransaction
}

// NewSecureBridges initializes a new SecureBridges
func NewSecureBridges() *SecureBridges {
    return &SecureBridges{
        Transactions: make(map[string]BridgeTransaction),
    }
}

// CreateBridgeTransaction creates a new bridge transaction with encryption
func (sb *SecureBridges) CreateBridgeTransaction(sourceChain, destinationChain, sender, receiver string, amount float64, secret string) (string, error) {
    id := uuid.New().String()
    encryptedData, err := encryptData(secret, fmt.Sprintf("%s:%s:%f", sender, receiver, amount))
    if err != nil {
        return "", err
    }
    transaction := BridgeTransaction{
        ID:               id,
        SourceChain:      sourceChain,
        DestinationChain: destinationChain,
        Amount:           amount,
        Sender:           sender,
        Receiver:         receiver,
        Timestamp:        time.Now(),
        Status:           "pending",
        EncryptedData:    encryptedData,
    }
    sb.Transactions[id] = transaction
    return id, nil
}

// ConfirmBridgeTransaction confirms a bridge transaction
func (sb *SecureBridges) ConfirmBridgeTransaction(id, secret string) error {
    transaction, exists := sb.Transactions[id]
    if !exists {
        return errors.New("transaction does not exist")
    }
    if transaction.Status != "pending" {
        return errors.New("transaction is not pending")
    }
    decryptedData, err := decryptData(secret, transaction.EncryptedData)
    if err != nil {
        return err
    }
    transaction.Status = "confirmed"
    transaction.EncryptedData = decryptedData
    sb.Transactions[id] = transaction
    return nil
}

// RevokeBridgeTransaction revokes a bridge transaction
func (sb *SecureBridges) RevokeBridgeTransaction(id, secret string) error {
    transaction, exists := sb.Transactions[id]
    if !exists {
        return errors.New("transaction does not exist")
    }
    if transaction.Status != "pending" {
        return errors.New("transaction is not pending")
    }
    decryptedData, err := decryptData(secret, transaction.EncryptedData)
    if err != nil {
        return err
    }
    transaction.Status = "revoked"
    transaction.EncryptedData = decryptedData
    sb.Transactions[id] = transaction
    return nil
}

// GetBridgeTransaction retrieves a bridge transaction by ID and decrypts it
func (sb *SecureBridges) GetBridgeTransaction(id, secret string) (BridgeTransaction, error) {
    transaction, exists := sb.Transactions[id]
    if !exists {
        return BridgeTransaction{}, errors.New("transaction does not exist")
    }
    decryptedData, err := decryptData(secret, transaction.EncryptedData)
    if err != nil {
        return BridgeTransaction{}, err
    }
    transaction.EncryptedData = decryptedData
    return transaction, nil
}

// ListBridgeTransactions lists all bridge transactions
func (sb *SecureBridges) ListBridgeTransactions() []BridgeTransaction {
    transactions := []BridgeTransaction{}
    for _, transaction := range sb.Transactions {
        transactions = append(transactions, transaction)
    }
    return transactions
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

// GenerateSignature generates a signature for the bridge transaction using Argon2
func generateSignature(data, secret string) string {
    salt := make([]byte, 16)
    _, _ = rand.Read(salt)
    hash := argon2.IDKey([]byte(data), salt, 1, 64*1024, 4, 32)
    return hex.EncodeToString(hash)
}
