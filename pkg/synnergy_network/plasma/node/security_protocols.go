package node

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "io"
    "log"
    "sync"

    "golang.org/x/crypto/scrypt"
)

// Node represents a node in the blockchain network
type Node struct {
    Blockchain       []Block
    Nodes            map[string]*Node
    PendingTxns      []child_chain.Transaction
    Consensus        string
    Difficulty       int
    mu               sync.Mutex
    NodeID           string
    Stake            int
    ValidatorSet     map[string]int
    ValidatorAddress string
    Address          string
    Port             string
}

// GenerateSalt generates a random salt
func GenerateSalt() ([]byte, error) {
    salt := make([]byte, 16)
    _, err := io.ReadFull(rand.Reader, salt)
    if err != nil {
        return nil, err
    }
    return salt, nil
}

// DeriveKey derives a key from a password using scrypt
func DeriveKey(password string, salt []byte) ([]byte, error) {
    return scrypt.Key([]byte(password), salt, 1<<15, 8, 1, 32)
}

// Encrypt encrypts data using AES-GCM
func Encrypt(data, key []byte) (string, error) {
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

    ciphertext := gcm.Seal(nonce, nonce, data, nil)
    return hex.EncodeToString(ciphertext), nil
}

// Decrypt decrypts data using AES-GCM
func Decrypt(data string, key []byte) ([]byte, error) {
    ciphertext, err := hex.DecodeString(data)
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
    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    return gcm.Open(nil, nonce, ciphertext, nil)
}

// HashData hashes the given data using SHA-256
func HashData(data []byte) string {
    hash := sha256.Sum256(data)
    return hex.EncodeToString(hash[:])
}

// VerifyHash verifies if the data matches the hash
func VerifyHash(data []byte, hash string) bool {
    return HashData(data) == hash
}

// SecureBroadcast securely broadcasts data to all connected nodes
func (n *Node) SecureBroadcast(data []byte, password string) error {
    salt, err := GenerateSalt()
    if err != nil {
        return err
    }

    key, err := DeriveKey(password, salt)
    if err != nil {
        return err
    }

    encryptedData, err := Encrypt(data, key)
    if err != nil {
        return err
    }

    for _, node := range n.Nodes {
        if err := node.ReceiveSecureMessage(encryptedData, salt); err != nil {
            log.Printf("Failed to send secure message to node %s: %v", node.NodeID, err)
        }
    }

    return nil
}

// ReceiveSecureMessage processes the received secure message
func (n *Node) ReceiveSecureMessage(encryptedData string, salt []byte) error {
    password := "shared_secret_password" // This should be securely managed and distributed
    key, err := DeriveKey(password, salt)
    if err != nil {
        return err
    }

    data, err := Decrypt(encryptedData, key)
    if err != nil {
        return err
    }

    // Process the received data
    log.Printf("Received secure message: %s", data)
    return nil
}
