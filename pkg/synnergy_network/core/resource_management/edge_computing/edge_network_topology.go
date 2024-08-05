package edge_computing

import (
    "sync"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "io"
    "errors"
)

// Node represents an edge computing node in the network.
type Node struct {
    ID       string
    IP       string
    Capacity int
    Load     int
    Location string
}

// EdgeNetworkTopology manages the network of edge nodes.
type EdgeNetworkTopology struct {
    nodes      map[string]*Node
    mutex      sync.Mutex
    encryptionKey []byte
}

// NewEdgeNetworkTopology initializes a new EdgeNetworkTopology.
func NewEdgeNetworkTopology(encryptionKey []byte) *EdgeNetworkTopology {
    return &EdgeNetworkTopology{
        nodes: make(map[string]*Node),
        encryptionKey: encryptionKey,
    }
}

// AddNode adds a new node to the network.
func (net *EdgeNetworkTopology) AddNode(node *Node) error {
    net.mutex.Lock()
    defer net.mutex.Unlock()
    if _, exists := net.nodes[node.ID]; exists {
        return errors.New("node already exists")
    }
    net.nodes[node.ID] = node
    return nil
}

// RemoveNode removes a node from the network.
func (net *EdgeNetworkTopology) RemoveNode(nodeID string) error {
    net.mutex.Lock()
    defer net.mutex.Unlock()
    if _, exists := net.nodes[nodeID]; !exists {
        return errors.New("node not found")
    }
    delete(net.nodes, nodeID)
    return nil
}

// GetNode returns the details of a specific node.
func (net *EdgeNetworkTopology) GetNode(nodeID string) (*Node, error) {
    net.mutex.Lock()
    defer net.mutex.Unlock()
    node, exists := net.nodes[nodeID]
    if !exists {
        return nil, errors.New("node not found")
    }
    return node, nil
}

// EncryptData encrypts data using AES.
func (net *EdgeNetworkTopology) EncryptData(data string) (string, error) {
    block, err := aes.NewCipher(net.encryptionKey)
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
    ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
    return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptData decrypts data using AES.
func (net *EdgeNetworkTopology) DecryptData(data string) (string, error) {
    block, err := aes.NewCipher(net.encryptionKey)
    if err != nil {
        return "", err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }
    encoded, err := base64.StdEncoding.DecodeString(data)
    if err != nil {
        return "", err
    }
    nonceSize := gcm.NonceSize()
    if len(encoded) < nonceSize {
        return "", errors.New("ciphertext too short")
    }
    nonce, ciphertext := encoded[:nonceSize], encoded[nonceSize:]
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return "", err
    }
    return string(plaintext), nil
}

// LoadBalance dynamically balances the load across nodes.
func (net *EdgeNetworkTopology) LoadBalance() {
    net.mutex.Lock()
    defer net.mutex.Unlock()

    var totalCapacity, totalLoad int
    for _, node := range net.nodes {
        totalCapacity += node.Capacity
        totalLoad += node.Load
    }

    if totalCapacity == 0 {
        return
    }

    avgLoad := totalLoad / totalCapacity
    for _, node := range net.nodes {
        if node.Load > avgLoad {
            // Example logic for redistributing load
            // Detailed balancing logic would involve specific rules or algorithms
        }
    }
}

// SecureNodeCommunication encrypts communication between nodes.
func (net *EdgeNetworkTopology) SecureNodeCommunication(nodeID string, message string) (string, error) {
    node, err := net.GetNode(nodeID)
    if err != nil {
        return "", err
    }
    encryptedMessage, err := net.EncryptData(message)
    if err != nil {
        return "", err
    }
    // Normally, we would send this encryptedMessage to the node's IP address securely
    return encryptedMessage, nil
}
