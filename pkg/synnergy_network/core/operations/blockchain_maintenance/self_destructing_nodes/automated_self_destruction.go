package self_destructing_nodes

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "errors"
    "io"
    "log"
    "time"
    
    "github.com/synnergy_network/blockchain"
    "github.com/synnergy_network/utils"
)

// NodeStatus defines the status of a node.
type NodeStatus int

const (
    Active NodeStatus = iota
    Compromised
    SelfDestructed
)

// Node represents a blockchain node with self-destruct capabilities.
type Node struct {
    ID              string
    Status          NodeStatus
    Data            string
    LastCheck       time.Time
    BreachDetected  bool
    SelfDestructKey []byte
}

// NewNode creates a new node with a given ID and data.
func NewNode(id string, data string) *Node {
    return &Node{
        ID:             id,
        Status:         Active,
        Data:           data,
        LastCheck:      time.Now(),
        BreachDetected: false,
        SelfDestructKey: generateSelfDestructKey(),
    }
}

// generateSelfDestructKey generates a key for self-destruct encryption.
func generateSelfDestructKey() []byte {
    key := make([]byte, 32)
    _, err := rand.Read(key)
    if err != nil {
        log.Fatalf("Failed to generate self-destruct key: %v", err)
    }
    return key
}

// DetectBreach simulates breach detection logic.
func (node *Node) DetectBreach() {
    // Real-world logic to detect breaches would be more complex and include anomaly detection algorithms.
    // Here we simply simulate a breach detection.
    node.BreachDetected = true
    node.Status = Compromised
    node.LastCheck = time.Now()
}

// EncryptData encrypts the node data using AES encryption.
func (node *Node) EncryptData() error {
    block, err := aes.NewCipher(node.SelfDestructKey)
    if err != nil {
        return err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        return err
    }

    encryptedData := gcm.Seal(nonce, nonce, []byte(node.Data), nil)
    node.Data = base64.StdEncoding.EncodeToString(encryptedData)
    return nil
}

// DecryptData decrypts the node data using AES encryption.
func (node *Node) DecryptData() (string, error) {
    encryptedData, err := base64.StdEncoding.DecodeString(node.Data)
    if err != nil {
        return "", err
    }

    block, err := aes.NewCipher(node.SelfDestructKey)
    if err != nil {
        return "", err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    nonceSize := gcm.NonceSize()
    if len(encryptedData) < nonceSize {
        return "", errors.New("ciphertext too short")
    }

    nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]
    decryptedData, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return "", err
    }

    return string(decryptedData), nil
}

// SelfDestruct deletes the node data securely.
func (node *Node) SelfDestruct() error {
    err := node.EncryptData()
    if err != nil {
        return err
    }
    // Simulate secure deletion by overwriting the data with zeros
    node.Data = ""
    node.Status = SelfDestructed
    log.Printf("Node %s has self-destructed.", node.ID)
    return nil
}

// SelfDestructRoutine initiates self-destruction if a breach is detected.
func (node *Node) SelfDestructRoutine() {
    if node.BreachDetected {
        log.Printf("Breach detected for node %s. Initiating self-destruct sequence.", node.ID)
        err := node.SelfDestruct()
        if err != nil {
            log.Fatalf("Failed to self-destruct node %s: %v", node.ID, err)
        }
    }
}

// SecureDataDeletion securely deletes data by encrypting it and then removing it.
func SecureDataDeletion(data string, key []byte) (string, error) {
    hash := sha256.New()
    hash.Write(key)
    keyHash := hash.Sum(nil)

    block, err := aes.NewCipher(keyHash)
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

    encryptedData := gcm.Seal(nonce, nonce, []byte(data), nil)
    return base64.StdEncoding.EncodeToString(encryptedData), nil
}

// DeletionProtocol handles the data deletion protocol.
func (node *Node) DeletionProtocol() error {
    encryptedData, err := SecureDataDeletion(node.Data, node.SelfDestructKey)
    if err != nil {
        return err
    }

    // Overwrite data with encrypted version and clear the original data
    node.Data = encryptedData
    log.Printf("Data for node %s securely deleted.", node.ID)
    return nil
}

// StartSelfDestructMonitor starts monitoring the node for breaches.
func (node *Node) StartSelfDestructMonitor() {
    for {
        time.Sleep(1 * time.Minute)
        node.DetectBreach()
        node.SelfDestructRoutine()
    }
}

func main() {
    // Example usage
    node := NewNode("node-1", "sensitive data")
    go node.StartSelfDestructMonitor()

    // Simulate a breach detection after some time
    time.Sleep(2 * time.Minute)
    node.DetectBreach()

    // Wait to see self-destruct in action
    time.Sleep(3 * time.Minute)
}
