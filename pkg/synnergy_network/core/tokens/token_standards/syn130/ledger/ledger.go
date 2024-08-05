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
    "github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn130/storage"
)

type Asset struct {
    ID             string
    OwnerID        string
    Valuation      float64
    Metadata       map[string]string
    TransactionHistory []TransactionRecord
    OwnershipHash  string
    Timestamp      time.Time
}

type TransactionRecord struct {
    AssetID    string
    FromOwner  string
    ToOwner    string
    Timestamp  time.Time
    TransactionHash string
}

type Ledger struct {
    assets map[string]Asset
    cipher cipher.Block
    storage storage.Storage
}

// NewLedger creates a new Ledger instance with AES encryption
func NewLedger(encryptionKey string, storage storage.Storage) (*Ledger, error) {
    keyHash := sha256.Sum256([]byte(encryptionKey))
    cipherBlock, err := aes.NewCipher(keyHash[:])
    if err != nil {
        return nil, fmt.Errorf("failed to create cipher block: %v", err)
    }

    return &Ledger{
        assets:  make(map[string]Asset),
        cipher:  cipherBlock,
        storage: storage,
    }, nil
}

// AddAsset adds a new asset to the ledger
func (l *Ledger) AddAsset(assetID, ownerID string, valuation float64, metadata map[string]string) error {
    timestamp := time.Now()
    ownershipHash, err := l.generateOwnershipHash(assetID, ownerID, timestamp)
    if err != nil {
        return err
    }

    asset := Asset{
        ID:             assetID,
        OwnerID:        ownerID,
        Valuation:      valuation,
        Metadata:       metadata,
        TransactionHistory: []TransactionRecord{},
        OwnershipHash:  ownershipHash,
        Timestamp:      timestamp,
    }

    l.assets[assetID] = asset
    return l.saveToStorage(asset)
}

// GetAsset retrieves the asset record for a given assetID
func (l *Ledger) GetAsset(assetID string) (Asset, error) {
    asset, exists := l.assets[assetID]
    if !exists {
        return Asset{}, errors.New("asset not found")
    }
    return asset, nil
}

// UpdateValuation updates the valuation of an asset
func (l *Ledger) UpdateValuation(assetID string, newValuation float64) error {
    asset, err := l.GetAsset(assetID)
    if err != nil {
        return err
    }

    asset.Valuation = newValuation
    asset.Timestamp = time.Now()
    l.assets[assetID] = asset
    return l.saveToStorage(asset)
}

// TransferOwnership transfers ownership of an asset to a new owner
func (l *Ledger) TransferOwnership(assetID, newOwnerID string) error {
    asset, err := l.GetAsset(assetID)
    if err != nil {
        return err
    }

    timestamp := time.Now()
    ownershipHash, err := l.generateOwnershipHash(assetID, newOwnerID, timestamp)
    if err != nil {
        return err
    }

    transaction := TransactionRecord{
        AssetID:        assetID,
        FromOwner:      asset.OwnerID,
        ToOwner:        newOwnerID,
        Timestamp:      timestamp,
        TransactionHash: ownershipHash,
    }

    asset.OwnerID = newOwnerID
    asset.OwnershipHash = ownershipHash
    asset.TransactionHistory = append(asset.TransactionHistory, transaction)
    asset.Timestamp = timestamp

    l.assets[assetID] = asset
    return l.saveToStorage(asset)
}

// generateOwnershipHash generates a secure hash for an ownership record
func (l *Ledger) generateOwnershipHash(assetID, ownerID string, timestamp time.Time) (string, error) {
    data := fmt.Sprintf("%s:%s:%d", assetID, ownerID, timestamp.Unix())
    encryptedData, err := l.encrypt([]byte(data))
    if err != nil {
        return "", err
    }
    return hex.EncodeToString(encryptedData), nil
}

// encrypt encrypts data using AES encryption
func (l *Ledger) encrypt(data []byte) ([]byte, error) {
    gcm, err := cipher.NewGCM(l.cipher)
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
func (l *Ledger) decrypt(data []byte) ([]byte, error) {
    gcm, err := cipher.NewGCM(l.cipher)
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

// saveToStorage saves the asset to persistent storage
func (l *Ledger) saveToStorage(asset Asset) error {
    data, err := utils.MarshalJSON(asset)
    if err != nil {
        return err
    }

    encryptedData, err := l.encrypt(data)
    if err != nil {
        return err
    }

    return l.storage.Save(asset.ID, encryptedData)
}

// loadFromStorage loads an asset from persistent storage
func (l *Ledger) loadFromStorage(assetID string) (Asset, error) {
    encryptedData, err := l.storage.Load(assetID)
    if err != nil {
        return Asset{}, err
    }

    data, err := l.decrypt(encryptedData)
    if err != nil {
        return Asset{}, err
    }

    var asset Asset
    if err := utils.UnmarshalJSON(data, &asset); err != nil {
        return Asset{}, err
    }

    l.assets[assetID] = asset
    return asset, nil
}

// ValidateOwnership validates the ownership of an asset
func (l *Ledger) ValidateOwnership(assetID, ownerID string) (bool, error) {
    asset, err := l.GetAsset(assetID)
    if err != nil {
        return false, err
    }

    generatedHash, err := l.generateOwnershipHash(assetID, ownerID, asset.Timestamp)
    if err != nil {
        return false, err
    }

    return generatedHash == asset.OwnershipHash, nil
}
