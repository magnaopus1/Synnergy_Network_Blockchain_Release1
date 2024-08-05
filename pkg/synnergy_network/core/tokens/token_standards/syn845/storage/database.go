package storage

import (
    "crypto/rand"
    "crypto/aes"
    "crypto/cipher"
    "crypto/sha256"
    "encoding/base64"
    "errors"
    "log"
    "sync"
    "time"
)

// Data structure definitions

type DebtMetadata struct {
    ID            string
    Owner         string
    OriginalAmount float64
    InterestRate  float64
    RepaymentPeriod time.Duration
    PenaltyRate   float64
}

type PaymentRecord struct {
    Date      time.Time
    Amount    float64
    Interest  float64
    Principal float64
    Balance   float64
}

type StatusLog struct {
    Status   string
    Date     time.Time
}

type CollateralRecord struct {
    AssetID string
    Value   float64
}

type EventLog struct {
    EventType string
    Date      time.Time
    Details   string
}

// Database struct with mutex for thread safety
type Database struct {
    debtMetadata    map[string]DebtMetadata
    paymentRecords  map[string][]PaymentRecord
    statusLogs      map[string][]StatusLog
    collateralRecords map[string]CollateralRecord
    eventLogs       map[string][]EventLog
    mu              sync.RWMutex
    encryptionKey   []byte
}

// NewDatabase initializes a new database instance
func NewDatabase(encryptionKey string) *Database {
    return &Database{
        debtMetadata:    make(map[string]DebtMetadata),
        paymentRecords:  make(map[string][]PaymentRecord),
        statusLogs:      make(map[string][]StatusLog),
        collateralRecords: make(map[string]CollateralRecord),
        eventLogs:       make(map[string][]EventLog),
        encryptionKey:   sha256.Sum256([]byte(encryptionKey)),
    }
}

// Encryption and decryption methods
func (db *Database) encrypt(data []byte) (string, error) {
    block, err := aes.NewCipher(db.encryptionKey)
    if err != nil {
        return "", err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err := rand.Read(nonce); err != nil {
        return "", err
    }

    encrypted := gcm.Seal(nonce, nonce, data, nil)
    return base64.StdEncoding.EncodeToString(encrypted), nil
}

func (db *Database) decrypt(encryptedData string) ([]byte, error) {
    data, err := base64.StdEncoding.DecodeString(encryptedData)
    if err != nil {
        return nil, err
    }

    block, err := aes.NewCipher(db.encryptionKey)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    nonceSize := gcm.NonceSize()
    if len(data) < nonceSize {
        return nil, errors.New("ciphertext too short")
    }

    nonce, ciphertext := data[:nonceSize], data[nonceSize:]
    return gcm.Open(nil, nonce, ciphertext, nil)
}

// Methods to store and retrieve debt metadata
func (db *Database) StoreDebtMetadata(metadata DebtMetadata) error {
    db.mu.Lock()
    defer db.mu.Unlock()

    data, err := json.Marshal(metadata)
    if err != nil {
        return err
    }

    encryptedData, err := db.encrypt(data)
    if err != nil {
        return err
    }

    db.debtMetadata[metadata.ID] = encryptedData
    return nil
}

func (db *Database) RetrieveDebtMetadata(debtID string) (*DebtMetadata, error) {
    db.mu.RLock()
    defer db.mu.RUnlock()

    encryptedData, exists := db.debtMetadata[debtID]
    if !exists {
        return nil, errors.New("debt metadata not found")
    }

    data, err := db.decrypt(encryptedData)
    if err != nil {
        return nil, err
    }

    var metadata DebtMetadata
    if err := json.Unmarshal(data, &metadata); err != nil {
        return nil, err
    }

    return &metadata, nil
}

// Methods to store and retrieve payment records
func (db *Database) StorePaymentRecord(debtID string, record PaymentRecord) error {
    db.mu.Lock()
    defer db.mu.Unlock()

    data, err := json.Marshal(record)
    if err != nil {
        return err
    }

    encryptedData, err := db.encrypt(data)
    if err != nil {
        return err
    }

    db.paymentRecords[debtID] = append(db.paymentRecords[debtID], encryptedData)
    return nil
}

func (db *Database) RetrievePaymentRecords(debtID string) ([]PaymentRecord, error) {
    db.mu.RLock()
    defer db.mu.RUnlock()

    encryptedRecords, exists := db.paymentRecords[debtID]
    if !exists {
        return nil, errors.New("payment records not found")
    }

    var records []PaymentRecord
    for _, encryptedData := range encryptedRecords {
        data, err := db.decrypt(encryptedData)
        if err != nil {
            return nil, err
        }

        var record PaymentRecord
        if err := json.Unmarshal(data, &record); err != nil {
            return nil, err
        }

        records = append(records, record)
    }

    return records, nil
}

// Methods to store and retrieve status logs
func (db *Database) StoreStatusLog(debtID string, log StatusLog) error {
    db.mu.Lock()
    defer db.mu.Unlock()

    data, err := json.Marshal(log)
    if err != nil {
        return err
    }

    encryptedData, err := db.encrypt(data)
    if err != nil {
        return err
    }

    db.statusLogs[debtID] = append(db.statusLogs[debtID], encryptedData)
    return nil
}

func (db *Database) RetrieveStatusLogs(debtID string) ([]StatusLog, error) {
    db.mu.RLock()
    defer db.mu.RUnlock()

    encryptedLogs, exists := db.statusLogs[debtID]
    if !exists {
        return nil, errors.New("status logs not found")
    }

    var logs []StatusLog
    for _, encryptedData := range encryptedLogs {
        data, err := db.decrypt(encryptedData)
        if err != nil {
            return nil, err
        }

        var log StatusLog
        if err := json.Unmarshal(data, &log); err != nil {
            return nil, err
        }

        logs = append(logs, log)
    }

    return logs, nil
}

// Methods to store and retrieve collateral records
func (db *Database) StoreCollateralRecord(record CollateralRecord) error {
    db.mu.Lock()
    defer db.mu.Unlock()

    data, err := json.Marshal(record)
    if err != nil {
        return err
    }

    encryptedData, err := db.encrypt(data)
    if err != nil {
        return err
    }

    db.collateralRecords[record.AssetID] = encryptedData
    return nil
}

func (db *Database) RetrieveCollateralRecord(assetID string) (*CollateralRecord, error) {
    db.mu.RLock()
    defer db.mu.RUnlock()

    encryptedData, exists := db.collateralRecords[assetID]
    if !exists {
        return nil, errors.New("collateral record not found")
    }

    data, err := db.decrypt(encryptedData)
    if err != nil {
        return nil, err
    }

    var record CollateralRecord
    if err := json.Unmarshal(data, &record); err != nil {
        return nil, err
    }

    return &record, nil
}

// Methods to store and retrieve event logs
func (db *Database) StoreEventLog(debtID string, log EventLog) error {
    db.mu.Lock()
    defer db.mu.Unlock()

    data, err := json.Marshal(log)
    if err != nil {
        return err
    }

    encryptedData, err := db.encrypt(data)
    if err != nil {
        return err
    }

    db.eventLogs[debtID] = append(db.eventLogs[debtID], encryptedData)
    return nil
}

func (db *Database) RetrieveEventLogs(debtID string) ([]EventLog, error) {
    db.mu.RLock()
    defer db.mu.RUnlock()

    encryptedLogs, exists := db.eventLogs[debtID]
    if !exists {
        return nil, errors.New("event logs not found")
    }

    var logs []EventLog
    for _, encryptedData := range encryptedLogs {
        data, err := db.decrypt(encryptedData)
        if err != nil {
            return nil, err
        }

        var log EventLog
        if err := json.Unmarshal(data, &log); err != nil {
            return nil, err
        }

        logs = append(logs, log)
    }

    return logs, nil
}
