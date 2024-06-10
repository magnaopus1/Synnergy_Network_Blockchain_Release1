package security

import (
    "crypto/sha256"
    "fmt"
    "golang.org/x/crypto/argon2"
    "golang.org/x/crypto/scrypt"
    "log"
    "sync"
)

const (
    Salt       = "unique-salt-for-security"
    KeyLength  = 32
    Iterations = 3
    Memory     = 64 * 1024
    Threads    = 4
)

// SybilBlocker handles blocking of Sybil nodes in the network.
type SybilBlocker struct {
    registeredNodes map[string]bool
    mutex           sync.Mutex
}

// NewSybilBlocker creates a new instance of a Sybil blocker.
func NewSybilBlocker() *SybilBlocker {
    return &SybilBlocker{
        registeredNodes: make(map[string]bool),
    }
}

// BlockNode marks a node as blocked based on its ID.
func (sb *SybilBlocker) BlockNode(nodeID string) error {
    sb.mutex.Lock()
    defer sb.mutex.Unlock()

    if sb.registeredNodes[nodeID] {
        return fmt.Errorf("node %s is already blocked", nodeID)
    }

    sb.registeredNodes[nodeID] = true
    log.Printf("Node %s has been blocked", nodeID)
    return nil
}

// UnblockNode removes the block from a node based on its ID.
func (sb *SybilBlocker) UnblockNode(nodeID string) error {
    sb.mutex.Lock()
    defer sb.mutex.Unlock()

    if !sb.registeredNodes[nodeID] {
        return fmt.Errorf("node %s is not blocked", nodeID)
    }

    delete(sb.registeredNodes, nodeID)
    log.Printf("Node %s has been unblocked", nodeID)
    return nil
}

// CheckIfBlocked checks if a node is blocked.
func (sb *SybilBlocker) CheckIfBlocked(nodeID string) bool {
    sb.mutex.Lock()
    defer sb.mutex.Unlock()

    return sb.registeredNodes[nodeID]
}

// EncryptData uses Argon2 to encrypt node identifiers.
func EncryptData(data string) string {
    salt := []byte(Salt)
    hash := argon2.IDKey([]byte(data), salt, Iterations, Memory, Threads, KeyLength)
    return fmt.Sprintf("%x", hash)
}

// DecryptData uses Scrypt to decrypt node identifiers.
func DecryptData(data string) (string, error) {
    salt := []byte(Salt)
    dataBytes, err := scrypt.Key([]byte(data), salt, 16384, 8, 1, KeyLength)
    if err != nil {
        return "", err
    }
    return string(dataBytes), nil
}

// Example usage of the SybilBlocker
func main() {
    blocker := NewSybilBlocker()
    nodeID := "node001"

    // Example of blocking a node
    if err := blocker.BlockNode(nodeID); err != nil {
        log.Println(err)
    }

    // Example of checking if a node is blocked
    if blocked := blocker.CheckIfBlocked(nodeID); blocked {
        log.Printf("Node %s is currently blocked", nodeID)
    }

    // Example of unblocking a node
    if err := blocker.UnblockNode(nodeID); err != nil {
        log.Println(err)
    }
}
