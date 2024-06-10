package security

import (
    "crypto/sha256"
    "fmt"
    "golang.org/x/crypto/argon2"
    "golang.org/x/crypto/scrypt"
    "log"
)

const (
    Salt       = "secure-random-salt"
    KeyLength  = 32
    Iterations = 3
    Memory     = 64 * 1024
    Threads    = 4
)

// NodeIdentity represents the identity of a node in the network.
type NodeIdentity struct {
    ID        string
    PublicKey string
    Activity  int
}

// SybilDetector manages the detection of Sybil nodes in the network.
type SybilDetector struct {
    nodes map[string]NodeIdentity
}

// NewSybilDetector initializes a new instance of SybilDetector.
func NewSybilDetector() *SybilDetector {
    return &SybilDetector{
        nodes: make(map[string]NodeIdentity),
    }
}

// RegisterNode attempts to register a new node and checks for Sybil attacks.
func (sd *SybilDetector) RegisterNode(node NodeIdentity) error {
    if _, exists := sd.nodes[node.ID]; exists {
        return fmt.Errorf("node with ID %s already exists", node.ID)
    }
    sd.nodes[node.ID] = node
    log.Printf("Node registered: %s", node.ID)
    return nil
}

// CheckForSybil detects potential Sybil nodes based on network activity patterns.
func (sd *SybilDetector) CheckForSybil() {
    var suspiciousNodes []NodeIdentity
    for _, node := range sd.nodes {
        if node.Activity < 1 {
            suspiciousNodes = append(suspiciousNodes, node)
            log.Printf("Potential Sybil node detected: %s", node.ID)
        }
    }
    // Further analysis logic could be implemented here
}

// EncryptData uses Argon2 to encrypt node data.
func EncryptData(data string) string {
    salt := []byte(Salt)
    hash := argon2.IDKey([]byte(data), salt, Iterations, Memory, Threads, KeyLength)
    return fmt.Sprintf("%x", hash)
}

// DecryptData uses Scrypt to decrypt node data.
func DecryptData(data string) (string, error) {
    salt := []byte(Salt)
    dataBytes, err := scrypt.Key([]byte(data), salt, 16384, 8, 1, KeyLength)
    if err != nil {
        return "", err
    }
    return string(dataBytes), nil
}

// Example main function for demonstration.
func main() {
    sd := NewSybilDetector()
    sd.RegisterNode(NodeIdentity{ID: "node123", PublicKey: "pubkey1", Activity: 0})
    sd.RegisterNode(NodeIdentity{ID: "node124", PublicKey: "pubkey2", Activity: 2})
    
    sd.CheckForSybil()

    encryptedData := EncryptData("node123")
    fmt.Println("Encrypted Node ID:", encryptedData)

    decryptedData, _ := DecryptData(encryptedData)
    fmt.Println("Decrypted Node ID:", decryptedData)
}

