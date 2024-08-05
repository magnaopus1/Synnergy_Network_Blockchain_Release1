package compliance

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "errors"
    "fmt"
    "io"
    "log"
    "time"

    "golang.org/x/crypto/scrypt"
)

// Constants for scrypt key derivation
const (
    KeyLen   = 32
    SaltSize = 16
    N        = 1 << 15
    R        = 8
    P        = 1
)

// UserKYC contains KYC information for a user
type UserKYC struct {
    UserID        string    `json:"user_id"`
    FullName      string    `json:"full_name"`
    DocumentType  string    `json:"document_type"`
    DocumentID    string    `json:"document_id"`
    DateOfBirth   time.Time `json:"date_of_birth"`
    Address       string    `json:"address"`
    Verification  bool      `json:"verification"`
    LastUpdated   time.Time `json:"last_updated"`
    EncryptedData string    `json:"encrypted_data"`
}

// AMLTransaction represents a transaction for AML checking
type AMLTransaction struct {
    TransactionID string    `json:"transaction_id"`
    UserID        string    `json:"user_id"`
    Amount        float64   `json:"amount"`
    Currency      string    `json:"currency"`
    Timestamp     time.Time `json:"timestamp"`
    Status        string    `json:"status"`
}

// KYCManager handles KYC processes
type KYCManager struct {
    users map[string]UserKYC
}

// AMLManager handles AML processes
type AMLManager struct {
    transactions map[string]AMLTransaction
}

// NewKYCManager creates a new KYCManager
func NewKYCManager() *KYCManager {
    return &KYCManager{
        users: make(map[string]UserKYC),
    }
}

// NewAMLManager creates a new AMLManager
func NewAMLManager() *AMLManager {
    return &AMLManager{
        transactions: make(map[string]AMLTransaction),
    }
}

// AddUserKYC adds or updates a user's KYC information
func (k *KYCManager) AddUserKYC(user UserKYC, passphrase string) error {
    encryptedData, err := encryptData(user, passphrase)
    if err != nil {
        return err
    }
    user.EncryptedData = encryptedData
    user.Verification = true
    user.LastUpdated = time.Now()
    k.users[user.UserID] = user
    return nil
}

// VerifyUserKYC verifies the KYC information for a user
func (k *KYCManager) VerifyUserKYC(userID string) (bool, error) {
    user, exists := k.users[userID]
    if !exists {
        return false, errors.New("user not found")
    }
    return user.Verification, nil
}

// GetUserKYC retrieves a user's KYC information
func (k *KYCManager) GetUserKYC(userID, passphrase string) (*UserKYC, error) {
    user, exists := k.users[userID]
    if !exists {
        return nil, errors.New("user not found")
    }

    decryptedUser, err := decryptData(user.EncryptedData, passphrase)
    if err != nil {
        return nil, err
    }

    return decryptedUser, nil
}

// AddTransaction adds a new transaction for AML checking
func (a *AMLManager) AddTransaction(tx AMLTransaction) error {
    if _, exists := a.transactions[tx.TransactionID]; exists {
        return errors.New("transaction already exists")
    }
    tx.Status = "pending"
    tx.Timestamp = time.Now()
    a.transactions[tx.TransactionID] = tx
    return nil
}

// ValidateTransaction validates a transaction based on AML rules
func (a *AMLManager) ValidateTransaction(txID string) error {
    tx, exists := a.transactions[txID]
    if !exists {
        return errors.New("transaction not found")
    }

    // Example AML rule: transactions above a certain threshold require additional checks
    threshold := 10000.0
    if tx.Amount > threshold {
        tx.Status = "requires_review"
    } else {
        tx.Status = "approved"
    }

    a.transactions[txID] = tx
    return nil
}

// encryptData encrypts the user's KYC data
func encryptData(user UserKYC, passphrase string) (string, error) {
    salt := make([]byte, SaltSize)
    if _, err := io.ReadFull(rand.Reader, salt); err != nil {
        return "", err
    }

    key, err := scrypt.Key([]byte(passphrase), salt, N, R, P, KeyLen)
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

    data, err := json.Marshal(user)
    if err != nil {
        return "", err
    }

    ciphertext := gcm.Seal(nonce, nonce, data, nil)
    encryptedData := append(salt, ciphertext...)
    return base64.StdEncoding.EncodeToString(encryptedData), nil
}

// decryptData decrypts the user's KYC data
func decryptData(encryptedData, passphrase string) (*UserKYC, error) {
    data, err := base64.StdEncoding.DecodeString(encryptedData)
    if err != nil {
        return nil, err
    }

    salt := data[:SaltSize]
    ciphertext := data[SaltSize:]

    key, err := scrypt.Key([]byte(passphrase), salt, N, R, P, KeyLen)
    if err != nil {
        return nil, err
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    nonceSize := gcm.NonceSize()
    if len(ciphertext) < nonceSize {
        return nil, fmt.Errorf("ciphertext too short")
    }

    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return nil, err
    }

    var user UserKYC
    if err := json.Unmarshal(plaintext, &user); err != nil {
        return nil, err
    }

    return &user, nil
}

// AML/KYC Compliance Example Usage
func main() {
    // Initialize managers
    kycManager := NewKYCManager()
    amlManager := NewAMLManager()

    // Example user KYC data
    user := UserKYC{
        UserID:       "user123",
        FullName:     "John Doe",
        DocumentType: "Passport",
        DocumentID:   "123456789",
        DateOfBirth:  time.Date(1990, time.January, 1, 0, 0, 0, 0, time.UTC),
        Address:      "123 Main St, Anytown, USA",
    }

    passphrase := "securepassphrase"

    // Add user KYC data
    err := kycManager.AddUserKYC(user, passphrase)
    if err != nil {
        log.Fatalf("Failed to add user KYC: %v", err)
    }

    // Verify user KYC data
    verified, err := kycManager.VerifyUserKYC("user123")
    if err != nil {
        log.Fatalf("Failed to verify user KYC: %v", err)
    }
    fmt.Printf("User KYC verified: %v\n", verified)

    // Retrieve user KYC data
    retrievedUser, err := kycManager.GetUserKYC("user123", passphrase)
    if err != nil {
        log.Fatalf("Failed to retrieve user KYC: %v", err)
    }
    fmt.Printf("Retrieved User KYC: %+v\n", retrievedUser)

    // Add a new transaction for AML checking
    tx := AMLTransaction{
        TransactionID: "tx123",
        UserID:        "user123",
        Amount:        5000.0,
        Currency:      "USD",
    }

    err = amlManager.AddTransaction(tx)
    if err != nil {
        log.Fatalf("Failed to add transaction: %v", err)
    }

    // Validate the transaction
    err = amlManager.ValidateTransaction("tx123")
    if err != nil {
        log.Fatalf("Failed to validate transaction: %v", err)
    }

    validatedTx := amlManager.transactions["tx123"]
    fmt.Printf("Validated Transaction: %+v\n", validatedTx)
}
