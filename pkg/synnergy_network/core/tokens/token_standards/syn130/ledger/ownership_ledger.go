package ledger

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

    "github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn130/utils"
)

type OwnershipRecord struct {
    AssetID       string
    OwnerID       string
    OwnershipHash string
    Timestamp     time.Time
}

type OwnershipLedger struct {
    records map[string]OwnershipRecord
    cipher  cipher.Block
}

// NewOwnershipLedger creates a new OwnershipLedger instance with AES encryption
func NewOwnershipLedger(encryptionKey string) (*OwnershipLedger, error) {
    keyHash := sha256.Sum256([]byte(encryptionKey))
    cipherBlock, err := aes.NewCipher(keyHash[:])
    if err != nil {
        return nil, fmt.Errorf("failed to create cipher block: %v", err)
    }

    return &OwnershipLedger{
        records: make(map[string]OwnershipRecord),
        cipher:  cipherBlock,
    }, nil
}

// AddOwnershipRecord adds a new ownership record to the ledger
func (ol *OwnershipLedger) AddOwnershipRecord(assetID, ownerID string) error {
    timestamp := time.Now()
    ownershipHash, err := ol.generateOwnershipHash(assetID, ownerID, timestamp)
    if err != nil {
        return err
    }

    record := OwnershipRecord{
        AssetID:       assetID,
        OwnerID:       ownerID,
        OwnershipHash: ownershipHash,
        Timestamp:     timestamp,
    }

    ol.records[assetID] = record
    return nil
}

// GetOwnershipRecord retrieves the ownership record for a given assetID
func (ol *OwnershipLedger) GetOwnershipRecord(assetID string) (OwnershipRecord, error) {
    record, exists := ol.records[assetID]
    if !exists {
        return OwnershipRecord{}, errors.New("ownership record not found")
    }
    return record, nil
}

// TransferOwnership transfers ownership of an asset to a new owner
func (ol *OwnershipLedger) TransferOwnership(assetID, newOwnerID string) error {
    record, err := ol.GetOwnershipRecord(assetID)
    if err != nil {
        return err
    }

    return ol.AddOwnershipRecord(assetID, newOwnerID)
}

// generateOwnershipHash generates a secure hash for an ownership record
func (ol *OwnershipLedger) generateOwnershipHash(assetID, ownerID string, timestamp time.Time) (string, error) {
    data := fmt.Sprintf("%s:%s:%d", assetID, ownerID, timestamp.Unix())
    encryptedData, err := ol.encrypt([]byte(data))
    if err != nil {
        return "", err
    }
    return hex.EncodeToString(encryptedData), nil
}

// encrypt encrypts data using AES encryption
func (ol *OwnershipLedger) encrypt(data []byte) ([]byte, error) {
    gcm, err := cipher.NewGCM(ol.cipher)
    if err != nil {
        return nil, fmt.Errorf("failed to create GCM: %v", err)
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, fmt.Errorf("failed to generate nonce: %v", err)
    }

    encryptedData := gcm.Seal(nonce, nonce, data, nil)
    return encryptedData, nil
}

// decrypt decrypts data using AES encryption
func (ol *OwnershipLedger) decrypt(data []byte) ([]byte, error) {
    gcm, err := cipher.NewGCM(ol.cipher)
    if err != nil {
        return nil, fmt.Errorf("failed to create GCM: %v", err)
    }

    nonceSize := gcm.NonceSize()
    if len(data) < nonceSize {
        return nil, errors.New("ciphertext too short")
    }

    nonce, ciphertext := data[:nonceSize], data[nonceSize:]
    decryptedData, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return nil, fmt.Errorf("failed to decrypt data: %v", err)
    }

    return decryptedData, nil
}

// ValidateOwnership validates the ownership of an asset
func (ol *OwnershipLedger) ValidateOwnership(assetID, ownerID string) (bool, error) {
    record, err := ol.GetOwnershipRecord(assetID)
    if err != nil {
        return false, err
    }

    generatedHash, err := ol.generateOwnershipHash(assetID, ownerID, record.Timestamp)
    if err != nil {
        return false, err
    }

    return generatedHash == record.OwnershipHash, nil
}

