package security

import (
    "crypto/rand"
    "fmt"
    "log"
    "golang.org/x/crypto/argon2"
    "golang.org/x/crypto/scrypt"
)

const (
    SaltSize       = 16 // Size of the salt
    KeyLength      = 32 // Length of the derived key
    ArgonTime      = 1  // Argon2 time parameter
    ArgonMemory    = 64 * 1024 // Argon2 memory usage
    ArgonThreads   = 4  // Argon2 threads
    ScryptN        = 16384 // Scrypt N parameter
    ScryptR        = 8    // Scrypt R parameter
    ScryptP        = 1    // Scrypt P parameter
)

// Vector76Transaction represents a transaction to be verified against the Vector76 attack.
type Vector76Transaction struct {
    ID      string   // Transaction ID
    Inputs  []string // List of input identifiers
    Outputs []string // List of output identifiers
}

// Vector76Detector encapsulates the functionality to detect Vector76 attacks.
type Vector76Detector struct {
    transactions map[string]bool // Map to store observed transaction inputs
}

// NewVector76Detector initializes a new Vector76Detector.
func NewVector76Detector() *Vector76Detector {
    return &Vector76Detector{
        transactions: make(map[string]bool),
    }
}

// DetectAttack analyzes the given transaction to detect potential Vector76 attacks.
func (v *Vector76Detector) DetectAttack(tx Vector76Transaction) bool {
    for _, input := range tx.Inputs {
        if _, exists := v.transactions[input]; exists {
            log.Printf("Vector76 attack detected: Transaction %s reuses input %s", tx.ID, input)
            return true
        }
        v.transactions[input] = true
    }
    return false
}

// GenerateSalt generates a secure random salt.
func GenerateSalt() ([]byte, error) {
    salt := make([]byte, SaltSize)
    _, err := rand.Read(salt)
    if err != nil {
        return nil, err
    }
    return salt, nil
}

// EncryptData securely encrypts data using Argon2.
func EncryptData(data, salt []byte) []byte {
    return argon2.IDKey(data, salt, ArgonTime, ArgonMemory, ArgonThreads, KeyLength)
}

// DecryptData securely decrypts data using Scrypt.
func DecryptData(data, salt []byte) ([]byte, error) {
    return scrypt.Key(data, salt, ScryptN, ScryptR, ScryptP, KeyLength)
}

// main function to demonstrate the functionality of Vector76Detector.
func main() {
    detector := NewVector76Detector()
    transaction := Vector76Transaction{
        ID: "tx1002",
        Inputs: []string{"input1", "input2"},
        Outputs: []string{"output1", "output2"},
    }

    // Simulating transaction processing
    if detector.DetectAttack(transaction) {
        fmt.Println("Attack detected.")
    } else {
        fmt.Println("No attack detected. Transaction is safe.")
    }

    // Assume transaction continues to processing
    salt, _ := GenerateSalt()
    encryptedInput := EncryptData([]byte(transaction.Inputs[0]), salt)
    fmt.Printf("Encrypted input: %x\n", encryptedInput)

    // Decryption for demonstration
    decryptedInput, _ := DecryptData(encryptedInput, salt)
    fmt.Printf("Decrypted input: %s\n", string(decryptedInput))
}
