package edge_computing

import (
    "sync"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "errors"
    "fmt"
    "io"
)

// Node represents an edge computing node participating in federated learning.
type Node struct {
    ID             string
    LocalModel     []byte
    DataSamples    [][]byte
    ModelVersion   int
    Status         string
    AggregatedData []byte
}

// FederatedLearningManager manages the federated learning process across nodes.
type FederatedLearningManager struct {
    nodes         map[string]*Node
    globalModel   []byte
    modelVersion  int
    mutex         sync.Mutex
    encryptionKey []byte
}

// NewFederatedLearningManager initializes a new FederatedLearningManager.
func NewFederatedLearningManager(encryptionKey []byte) *FederatedLearningManager {
    return &FederatedLearningManager{
        nodes:        make(map[string]*Node),
        encryptionKey: encryptionKey,
    }
}

// RegisterNode registers a new node for federated learning.
func (flm *FederatedLearningManager) RegisterNode(node *Node) error {
    flm.mutex.Lock()
    defer flm.mutex.Unlock()
    if _, exists := flm.nodes[node.ID]; exists {
        return errors.New("node already exists")
    }
    flm.nodes[node.ID] = node
    return nil
}

// RemoveNode removes a node from the federated learning network.
func (flm *FederatedLearningManager) RemoveNode(nodeID string) error {
    flm.mutex.Lock()
    defer flm.mutex.Unlock()
    if _, exists := flm.nodes[nodeID]; !exists {
        return errors.New("node not found")
    }
    delete(flm.nodes, nodeID)
    return nil
}

// EncryptData encrypts data using AES.
func (flm *FederatedLearningManager) EncryptData(data []byte) (string, error) {
    block, err := aes.NewCipher(flm.encryptionKey)
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
    return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptData decrypts data using AES.
func (flm *FederatedLearningManager) DecryptData(data string) ([]byte, error) {
    block, err := aes.NewCipher(flm.encryptionKey)
    if err != nil {
        return nil, err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    encoded, err := base64.StdEncoding.DecodeString(data)
    if err != nil {
        return nil, err
    }
    nonceSize := gcm.NonceSize()
    if len(encoded) < nonceSize {
        return nil, errors.New("ciphertext too short")
    }
    nonce, ciphertext := encoded[:nonceSize], encoded[nonceSize:]
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return nil, err
    }
    return plaintext, nil
}

// AggregateModels aggregates the local models from all nodes to update the global model.
func (flm *FederatedLearningManager) AggregateModels() error {
    flm.mutex.Lock()
    defer flm.mutex.Unlock()
    
    var aggregatedModel []byte
    for _, node := range flm.nodes {
        // Placeholder for aggregation logic, such as averaging model weights
        aggregatedModel = append(aggregatedModel, node.LocalModel...)
    }

    // Update global model with aggregated data
    flm.globalModel = aggregatedModel
    flm.modelVersion++
    return nil
}

// DistributeGlobalModel distributes the updated global model to all nodes.
func (flm *FederatedLearningManager) DistributeGlobalModel() error {
    flm.mutex.Lock()
    defer flm.mutex.Unlock()

    for _, node := range flm.nodes {
        node.LocalModel = flm.globalModel
        node.ModelVersion = flm.modelVersion
    }

    return nil
}

// TrainLocalModel trains the local model on a node using its local data.
func (flm *FederatedLearningManager) TrainLocalModel(nodeID string) error {
    flm.mutex.Lock()
    node, exists := flm.nodes[nodeID]
    flm.mutex.Unlock()

    if !exists {
        return errors.New("node not found")
    }

    // Placeholder for local training logic
    // Update node.LocalModel based on node.DataSamples

    return nil
}

// SecureAggregateData secures the aggregated data before sharing or storing.
func (flm *FederatedLearningManager) SecureAggregateData(data []byte) (string, error) {
    return flm.EncryptData(data)
}

// DecryptAggregateData decrypts the secured aggregated data.
func (flm *FederatedLearningManager) DecryptAggregateData(encryptedData string) ([]byte, error) {
    return flm.DecryptData(encryptedData)
}
