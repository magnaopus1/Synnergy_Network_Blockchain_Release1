// Package deployment provides scripts and tools for deploying the Synnergy Network.
package deployment

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/hex"
    "errors"
    "fmt"
    "io"
    "os"
    "os/exec"
    "path/filepath"
    "sync"
)

// DeploymentConfig holds the configuration for deploying the network.
type DeploymentConfig struct {
    NetworkName      string
    NodeCount        int
    ConsensusType    string
    DeploymentPath   string
    InitialValidators []string
    EncryptionKey    string
}

// Validate checks if the deployment configuration is valid.
func (config *DeploymentConfig) Validate() error {
    if config.NetworkName == "" {
        return errors.New("NetworkName cannot be empty")
    }
    if config.NodeCount <= 0 {
        return errors.New("NodeCount must be greater than zero")
    }
    if config.ConsensusType == "" {
        return errors.New("ConsensusType cannot be empty")
    }
    if config.DeploymentPath == "" {
        return errors.New("DeploymentPath cannot be empty")
    }
    if len(config.InitialValidators) == 0 {
        return errors.New("InitialValidators cannot be empty")
    }
    if config.EncryptionKey == "" {
        return errors.New("EncryptionKey cannot be empty")
    }
    return nil
}

// Encrypt encrypts the given data using AES encryption with the provided key.
func Encrypt(key, text string) (string, error) {
    block, err := aes.NewCipher([]byte(key))
    if err != nil {
        return "", err
    }
    aesGCM, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }
    nonce := make([]byte, aesGCM.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        return "", err
    }
    ciphertext := aesGCM.Seal(nonce, nonce, []byte(text), nil)
    return hex.EncodeToString(ciphertext), nil
}

// Decrypt decrypts the given data using AES decryption with the provided key.
func Decrypt(key, cryptoText string) (string, error) {
    data, err := hex.DecodeString(cryptoText)
    if err != nil {
        return "", err
    }
    block, err := aes.NewCipher([]byte(key))
    if err != nil {
        return "", err
    }
    aesGCM, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }
    nonceSize := aesGCM.NonceSize()
    nonce, ciphertext := data[:nonceSize], data[nonceSize:]
    plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return "", err
    }
    return string(plaintext), nil
}

// DeployNetwork deploys the network based on the given configuration.
func DeployNetwork(config DeploymentConfig) error {
    if err := config.Validate(); err != nil {
        return err
    }

    encryptedKey, err := Encrypt(config.EncryptionKey, "InitialSetup")
    if err != nil {
        return fmt.Errorf("failed to encrypt key: %v", err)
    }

    // Create deployment directory
    if err := os.MkdirAll(config.DeploymentPath, os.ModePerm); err != nil {
        return fmt.Errorf("failed to create deployment directory: %v", err)
    }

    // Deploy nodes
    var wg sync.WaitGroup
    for i := 0; i < config.NodeCount; i++ {
        wg.Add(1)
        go func(nodeID int) {
            defer wg.Done()
            if err := deployNode(nodeID, config, encryptedKey); err != nil {
                fmt.Printf("failed to deploy node %d: %v\n", nodeID, err)
            }
        }(i)
    }
    wg.Wait()

    // Final setup steps
    if err := finalSetup(config); err != nil {
        return fmt.Errorf("failed in final setup: %v", err)
    }

    fmt.Println("Network deployment completed successfully")
    return nil
}

// deployNode deploys a single node.
func deployNode(nodeID int, config DeploymentConfig, encryptedKey string) error {
    nodePath := filepath.Join(config.DeploymentPath, fmt.Sprintf("node%d", nodeID))
    if err := os.MkdirAll(nodePath, os.ModePerm); err != nil {
        return fmt.Errorf("failed to create node directory: %v", err)
    }

    // Generate node key
    nodeKey := fmt.Sprintf("node_key_%d", nodeID)
    encryptedNodeKey, err := Encrypt(config.EncryptionKey, nodeKey)
    if err != nil {
        return fmt.Errorf("failed to encrypt node key: %v", err)
    }

    // Save configuration files
    configFilePath := filepath.Join(nodePath, "config.yaml")
    if err := saveConfigFile(configFilePath, config, encryptedNodeKey); err != nil {
        return fmt.Errorf("failed to save config file: %v", err)
    }

    // Start node process
    cmd := exec.Command("start_node", configFilePath)
    if err := cmd.Start(); err != nil {
        return fmt.Errorf("failed to start node process: %v", err)
    }
    return nil
}

// saveConfigFile saves the node configuration to a file.
func saveConfigFile(path string, config DeploymentConfig, encryptedKey string) error {
    configData := fmt.Sprintf(`
network_name: %s
consensus_type: %s
initial_validators: %v
encrypted_key: %s
    `, config.NetworkName, config.ConsensusType, config.InitialValidators, encryptedKey)

    return os.WriteFile(path, []byte(configData), 0644)
}

// finalSetup performs final setup steps after deploying all nodes.
func finalSetup(config DeploymentConfig) error {
    // Example of final setup steps
    fmt.Println("Performing final setup steps...")
    // Add additional setup logic as needed
    return nil
}
