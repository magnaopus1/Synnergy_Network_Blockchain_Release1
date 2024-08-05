package bridge

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "io"
    "log"
    "sync"
    "time"

    "golang.org/x/crypto/scrypt"
)

// TransferStatus represents the status of a transfer
type TransferStatus int

const (
    Pending TransferStatus = iota
    Confirmed
    Failed
)

// Transfer represents a blockchain transfer
type Transfer struct {
    ID        string
    Amount    float64
    From      string
    To        string
    Timestamp time.Time
    Status    TransferStatus
    Error     string
}

// TransferMonitor handles monitoring of transfers
type TransferMonitor struct {
    mu        sync.Mutex
    transfers map[string]*Transfer
    aesKey    []byte
}

// NewTransferMonitor creates a new TransferMonitor
func NewTransferMonitor(password string, salt []byte) (*TransferMonitor, error) {
    key, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
    if err != nil {
        return nil, err
    }

    return &TransferMonitor{
        transfers: make(map[string]*Transfer),
        aesKey:    key,
    }, nil
}

// AddTransfer adds a new transfer to the monitor
func (tm *TransferMonitor) AddTransfer(id string, amount float64, from, to string) {
    tm.mu.Lock()
    defer tm.mu.Unlock()

    tm.transfers[id] = &Transfer{
        ID:        id,
        Amount:    amount,
        From:      from,
        To:        to,
        Timestamp: time.Now(),
        Status:    Pending,
    }
}

// UpdateTransferStatus updates the status of a transfer
func (tm *TransferMonitor) UpdateTransferStatus(id string, status TransferStatus, errMsg string) error {
    tm.mu.Lock()
    defer tm.mu.Unlock()

    transfer, exists := tm.transfers[id]
    if !exists {
        return errors.New("transfer not found")
    }

    transfer.Status = status
    transfer.Error = errMsg
    return nil
}

// GetTransfer returns the details of a transfer
func (tm *TransferMonitor) GetTransfer(id string) (*Transfer, error) {
    tm.mu.Lock()
    defer tm.mu.Unlock()

    transfer, exists := tm.transfers[id]
    if !exists {
        return nil, errors.New("transfer not found")
    }

    return transfer, nil
}

// Encrypt encrypts the given plaintext using AES
func (tm *TransferMonitor) Encrypt(plaintext string) (string, error) {
    block, err := aes.NewCipher(tm.aesKey)
    if err != nil {
        return "", err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        return "", err
    }

    ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
    return hex.EncodeToString(ciphertext), nil
}

// Decrypt decrypts the given ciphertext using AES
func (tm *TransferMonitor) Decrypt(ciphertext string) (string, error) {
    block, err := aes.NewCipher(tm.aesKey)
    if err != nil {
        return "", err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    data, err := hex.DecodeString(ciphertext)
    if err != nil {
        return "", err
    }

    nonceSize := gcm.NonceSize()
    if len(data) < nonceSize {
        return "", errors.New("invalid ciphertext")
    }

    nonce, ciphertext := data[:nonceSize], data[nonceSize:]
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return "", err
    }

    return string(plaintext), nil
}

// LogTransfer logs the details of a transfer
func (tm *TransferMonitor) LogTransfer(id string) error {
    tm.mu.Lock()
    defer tm.mu.Unlock()

    transfer, exists := tm.transfers[id]
    if !exists {
        return errors.New("transfer not found")
    }

    log.Printf("Transfer ID: %s\nAmount: %.2f\nFrom: %s\nTo: %s\nTimestamp: %s\nStatus: %s\nError: %s\n",
        transfer.ID, transfer.Amount, transfer.From, transfer.To, transfer.Timestamp, transferStatusToString(transfer.Status), transfer.Error)
    return nil
}

// transferStatusToString converts a TransferStatus to its string representation
func transferStatusToString(status TransferStatus) string {
    switch status {
    case Pending:
        return "Pending"
    case Confirmed:
        return "Confirmed"
    case Failed:
        return "Failed"
    default:
        return "Unknown"
    }
}

func main() {
    salt := sha256.Sum256([]byte("some_random_salt"))
    monitor, err := NewTransferMonitor("securepassword", salt[:])
    if err != nil {
        fmt.Println("Error creating transfer monitor:", err)
        return
    }

    monitor.AddTransfer("tx123", 100.0, "Alice", "Bob")
    err = monitor.UpdateTransferStatus("tx123", Confirmed, "")
    if err != nil {
        fmt.Println("Error updating transfer status:", err)
        return
    }

    err = monitor.LogTransfer("tx123")
    if err != nil {
        fmt.Println("Error logging transfer:", err)
    }
}
