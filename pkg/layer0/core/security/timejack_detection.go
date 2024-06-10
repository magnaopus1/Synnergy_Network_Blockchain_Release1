package security

import (
    "crypto/rand"
    "errors"
    "log"
    "time"

    "golang.org/x/crypto/argon2"
    "golang.org/x/crypto/scrypt"
)

const (
    SaltSize       = 16
    KeyLength      = 32
    ArgonTime      = 1
    ArgonMemory    = 64 * 1024
    ArgonThreads   = 4
    ScryptN        = 16384
    ScryptR        = 8
    ScryptP        = 1
    TimeThreshold  = 5 * time.Minute // Allowable time difference between nodes
)

// TimejackDetector is responsible for detecting discrepancies in node times.
type TimejackDetector struct {
    localTime time.Time
}

// NewTimejackDetector creates a new instance of TimejackDetector.
func NewTimejackDetector() *TimejackDetector {
    return &TimejackDetector{
        localTime: time.Now(),
    }
}

// SyncTime simulates synchronization of local time with a reference time, could be replaced with actual time sync logic.
func (t *TimejackDetector) SyncTime(referenceTime time.Time) {
    t.localTime = referenceTime
}

// ValidateNodeTime compares the provided node time with the local time and checks if it's within the acceptable threshold.
func (t *TimejackDetector) ValidateNodeTime(nodeTime time.Time) bool {
    timeDiff := t.localTime.Sub(nodeTime)
    if timeDiff < -TimeThreshold || timeDiff > TimeThreshold {
        log.Printf("Timejack attempt detected: Node time %s deviates from local time %s", nodeTime, t.localTime)
        return false
    }
    return true
}

// EncryptData secures data using Argon2.
func EncryptData(data, salt []byte) ([]byte, error) {
    key := argon2.IDKey(data, salt, ArgonTime, ArgonMemory, ArgonThreads, KeyLength)
    if key == nil {
        return nil, errors.New("encryption failed")
    }
    return key, nil
}

// DecryptData decrypts data using Scrypt.
func DecryptData(data, salt []byte) ([]byte, error) {
    dk, err := scrypt.Key(data, salt, ScryptN, ScryptR, ScryptP, KeyLength)
    if err != nil {
        log.Printf("Decryption error: %v", err)
        return nil, err
    }
    return dk, nil
}

// Example main function to demonstrate functionality.
func main() {
    detector := NewTimejackDetector()
    referenceTime := time.Now() // This would be synchronized time in a real application
    detector.SyncTime(referenceTime)

    // Simulating a node time for validation
    nodeTime := referenceTime.Add(3 * time.Minute) // Within threshold
    if detector.ValidateNodeTime(nodeTime) {
        log.Println("Node time is valid.")
    } else {
        log.Println("Node time validation failed, possible timejack detected.")
    }
}
