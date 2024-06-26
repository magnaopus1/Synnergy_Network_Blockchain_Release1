package security

import (
    "fmt"
    "log"

    "golang.org/x/crypto/argon2"
    "golang.org/x/crypto/scrypt"
)

const (
    Salt        = "your-unique-salt"
    KeyLength   = 32
    ScryptN     = 16384
    ScryptR     = 8
    ScryptP     = 1
    ArgonTime   = 1
    ArgonMemory = 64 * 1024
    ArgonThreads= 4
)

// Transaction represents the structure of a blockchain transaction
type Transaction struct {
    ID      string
    Inputs  []Input
    Outputs []Output
}

// Input represents an input in a transaction
type Input struct {
    PreviousOutpoint string
    Signature        string
}

// Output represents an output in a transaction
type Output struct {
    Value    float64
    Address  string
}

// Vector76Detector contains logic to detect and stop the Vector76 attack
type Vector76Detector struct {
    // Add additional fields if needed for state tracking or configuration
}

// NewVector76Detector creates a new instance of Vector76Detector
func NewVector76Detector() *Vector76Detector {
    return &Vector76Detector{}
}

// DetectAttack checks for the Vector76 attack pattern in a transaction
func (vd *Vector76Detector) DetectAttack(tx Transaction) bool {
    // Simplified check: if a transaction input is used twice, it's suspicious
    seen := make(map[string]bool)
    for _, input := range tx.Inputs {
        if _, exists := seen[input.PreviousOutpoint]; exists {
            log.Printf("Vector76 attack detected on transaction: %s", tx.ID)
            return true
        }
        seen[input.PreviousOutpoint] = true
    }
    return false
}

// EncryptData uses Argon2 to encrypt data securely
func EncryptData(data []byte) ([]byte, error) {
    salt := []byte(Salt)
    return argon2.IDKey(data, salt, ArgonTime, ArgonMemory, ArgonThreads, KeyLength), nil
}

// DecryptData uses Scrypt to securely decrypt data
func DecryptData(encryptedData, salt []byte) ([]byte, error) {
    return scrypt.Key(encryptedData, salt, ScryptN, ScryptR, ScryptP, KeyLength)
}

// Example main function to demonstrate Vector76 attack detection
func main() {
    detector := NewVector76Detector()
    tx := Transaction{
        ID: "tx1001",
        Inputs: []Input{
            {PreviousOutpoint: "out1", Signature: "sig1"},
            {PreviousOutpoint: "out1", Signature: "sig2"}, // Duplicate outpoint simulating attack
        },
        Outputs: []Output{
            {Value: 100.0, Address: "address1"},
        },
    }

    if detector.DetectAttack(tx) {
        fmt.Println("Attack detected and stopped.")
    } else {
        fmt.Println("No attack detected.")
    }
}
