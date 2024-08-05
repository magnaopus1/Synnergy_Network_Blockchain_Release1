package historical_data_analysis

import (
    "time"
    "sync"
    "errors"
    "os"
    "log"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/hex"
    "io"
)

// RetentionPolicy represents a policy for retaining data in the blockchain.
type RetentionPolicy struct {
    DataCategory string
    RetentionPeriod time.Duration
    EncryptionKey []byte
}

// DataRetentionManager manages data retention policies and enforcement.
type DataRetentionManager struct {
    Policies []RetentionPolicy
    dataLock sync.Mutex
    logger *log.Logger
}

// NewDataRetentionManager initializes a new DataRetentionManager.
func NewDataRetentionManager(logger *log.Logger) *DataRetentionManager {
    return &DataRetentionManager{
        Policies: make([]RetentionPolicy, 0),
        logger: logger,
    }
}

// AddPolicy adds a new data retention policy.
func (drm *DataRetentionManager) AddPolicy(category string, period time.Duration, key []byte) {
    drm.dataLock.Lock()
    defer drm.dataLock.Unlock()
    drm.Policies = append(drm.Policies, RetentionPolicy{
        DataCategory: category,
        RetentionPeriod: period,
        EncryptionKey: key,
    })
    drm.logger.Printf("Added new policy for category %s with retention period %s\n", category, period)
}

// RemovePolicy removes an existing data retention policy.
func (drm *DataRetentionManager) RemovePolicy(category string) error {
    drm.dataLock.Lock()
    defer drm.dataLock.Unlock()
    for i, policy := range drm.Policies {
        if policy.DataCategory == category {
            drm.Policies = append(drm.Policies[:i], drm.Policies[i+1:]...)
            drm.logger.Printf("Removed policy for category %s\n", category)
            return nil
        }
    }
    return errors.New("policy not found")
}

// EncryptData encrypts data using the provided key.
func EncryptData(data, key []byte) (string, error) {
    block, err := aes.NewCipher(key)
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

    ciphertext := gcm.Seal(nonce, nonce, data, nil)
    return hex.EncodeToString(ciphertext), nil
}

// DecryptData decrypts data using the provided key.
func DecryptData(encryptedData string, key []byte) ([]byte, error) {
    ciphertext, _ := hex.DecodeString(encryptedData)

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
        return nil, errors.New("ciphertext too short")
    }

    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    return gcm.Open(nil, nonce, ciphertext, nil)
}

// RetainData retains data according to the policy.
func (drm *DataRetentionManager) RetainData(dataCategory string, data []byte) (string, error) {
    drm.dataLock.Lock()
    defer drm.dataLock.Unlock()
    for _, policy := range drm.Policies {
        if policy.DataCategory == dataCategory {
            encryptedData, err := EncryptData(data, policy.EncryptionKey)
            if err != nil {
                drm.logger.Printf("Error encrypting data for category %s: %v\n", dataCategory, err)
                return "", err
            }
            drm.logger.Printf("Data for category %s retained and encrypted\n", dataCategory)
            return encryptedData, nil
        }
    }
    return "", errors.New("no retention policy found for data category")
}

// PruneData prunes data that exceeds the retention period.
func (drm *DataRetentionManager) PruneData(category string, encryptedData string) (bool, error) {
    drm.dataLock.Lock()
    defer drm.dataLock.Unlock()
    for _, policy := range drm.Policies {
        if policy.DataCategory == category {
            decryptedData, err := DecryptData(encryptedData, policy.EncryptionKey)
            if err != nil {
                drm.logger.Printf("Error decrypting data for category %s: %v\n", category, err)
                return false, err
            }
            // Simulate data timestamp retrieval and pruning decision
            dataTimestamp := time.Now().Add(-policy.RetentionPeriod - time.Hour) // Assume data is older than retention period
            if time.Since(dataTimestamp) > policy.RetentionPeriod {
                drm.logger.Printf("Data for category %s pruned\n", category)
                return true, nil
            }
            drm.logger.Printf("Data for category %s is within retention period\n", category)
            return false, nil
        }
    }
    return false, errors.New("no retention policy found for data category")
}

// Example usage
func main() {
    logger := log.New(os.Stdout, "DataRetentionManager: ", log.LstdFlags)
    drm := NewDataRetentionManager(logger)

    key := []byte("a very very very very secret key") // 32 bytes for AES-256
    drm.AddPolicy("financial", 30*24*time.Hour, key) // 30 days retention

    data := []byte("Sensitive financial data")
    encryptedData, err := drm.RetainData("financial", data)
    if err != nil {
        logger.Fatalf("Error retaining data: %v", err)
    }

    time.Sleep(1 * time.Second) // Simulate passage of time

    pruned, err := drm.PruneData("financial", encryptedData)
    if err != nil {
        logger.Fatalf("Error pruning data: %v", err)
    }
    if pruned {
        logger.Println("Data was pruned")
    } else {
        logger.Println("Data was retained")
    }
}
