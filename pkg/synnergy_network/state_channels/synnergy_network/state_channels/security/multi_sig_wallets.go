package security

import (
    "errors"
    "sync"
    "time"

    "golang.org/x/crypto/argon2"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "encoding/hex"
    "io"
    "fmt"
    "crypto/sha256"
    "github.com/synnergy_network/utils"
)

// MultiSigWallet represents a multi-signature wallet in the security module
type MultiSigWallet struct {
    WalletID     string
    Owners       []string
    RequiredSigs int
    Transactions []*Transaction
    lock         sync.RWMutex
}

// Transaction represents a transaction in the multi-signature wallet
type Transaction struct {
    TxID       string
    Amount     float64
    To         string
    Signatures map[string]bool
    Status     string
    Timestamp  time.Time
}

const (
    TxPending   = "PENDING"
    TxApproved  = "APPROVED"
    TxRejected  = "REJECTED"
)

// NewMultiSigWallet initializes a new MultiSigWallet instance
func NewMultiSigWallet(walletID string, owners []string, requiredSigs int) *MultiSigWallet {
    return &MultiSigWallet{
        WalletID:     walletID,
        Owners:       owners,
        RequiredSigs: requiredSigs,
        Transactions: []*Transaction{},
    }
}

// CreateTransaction creates a new transaction
func (msw *MultiSigWallet) CreateTransaction(txID string, amount float64, to string) *Transaction {
    tx := &Transaction{
        TxID:       txID,
        Amount:     amount,
        To:         to,
        Signatures: make(map[string]bool),
        Status:     TxPending,
        Timestamp:  time.Now(),
    }
    msw.lock.Lock()
    msw.Transactions = append(msw.Transactions, tx)
    msw.lock.Unlock()
    return tx
}

// SignTransaction signs a transaction by an owner
func (msw *MultiSigWallet) SignTransaction(txID, owner string) error {
    msw.lock.Lock()
    defer msw.lock.Unlock()

    for _, tx := range msw.Transactions {
        if tx.TxID == txID {
            if _, exists := tx.Signatures[owner]; exists {
                return errors.New("owner already signed the transaction")
            }
            tx.Signatures[owner] = true
            if len(tx.Signatures) >= msw.RequiredSigs {
                tx.Status = TxApproved
            }
            return nil
        }
    }
    return errors.New("transaction not found")
}

// RejectTransaction rejects a transaction by an owner
func (msw *MultiSigWallet) RejectTransaction(txID, owner string) error {
    msw.lock.Lock()
    defer msw.lock.Unlock()

    for _, tx := range msw.Transactions {
        if tx.TxID == txID {
            if _, exists := tx.Signatures[owner]; exists {
                return errors.New("owner already signed the transaction")
            }
            tx.Status = TxRejected
            return nil
        }
    }
    return errors.New("transaction not found")
}

// EncryptTransaction encrypts the transaction details
func (tx *Transaction) EncryptTransaction(key []byte) (string, error) {
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

    data := fmt.Sprintf("%s|%f|%s|%v|%s|%s",
        tx.TxID, tx.Amount, tx.To, tx.Signatures, tx.Status, tx.Timestamp)
    ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
    return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptTransaction decrypts the transaction details
func (tx *Transaction) DecryptTransaction(encryptedData string, key []byte) error {
    ciphertext, err := base64.StdEncoding.DecodeString(encryptedData)
    if err != nil {
        return err
    }

    block, err := aes.NewCipher(key)
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
    data, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return err
    }

    parts := utils.Split(string(data), '|')
    if len(parts) != 6 {
        return errors.New("invalid encrypted data format")
    }

    tx.TxID = parts[0]
    tx.Amount = utils.ParseFloat(parts[1])
    tx.To = parts[2]
    tx.Signatures = utils.ParseSignatures(parts[3])
    tx.Status = parts[4]
    tx.Timestamp = utils.ParseTime(parts[5])
    return nil
}

// GenerateKey generates a cryptographic key using Argon2
func GenerateKey(password, salt []byte) []byte {
    return argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
}

// GenerateSalt generates a cryptographic salt
func GenerateSalt() ([]byte, error) {
    salt := make([]byte, 16)
    if _, err := io.ReadFull(rand.Reader, salt); err != nil {
        return nil, err
    }
    return salt, nil
}

// HashData hashes the data using SHA-256
func HashData(data []byte) []byte {
    hash := sha256.Sum256(data)
    return hash[:]
}

func (tx *Transaction) String() string {
    return fmt.Sprintf("TxID: %s, Amount: %f, To: %s, Signatures: %v, Status: %s, Timestamp: %s",
        tx.TxID, tx.Amount, tx.To, tx.Signatures, tx.Status, tx.Timestamp)
}
