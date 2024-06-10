package smart_contract_orchestration

import (
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "log"
    "crypto/aes"
    "crypto/cipher"
)

// OrchestrationService provides services to orchestrate smart contracts
type OrchestrationService struct {
    orchestrator ContractOrchestrator
}

// NewOrchestrationService creates a new instance of OrchestrationService
func NewOrchestrationService(orchestrator ContractOrchestrator) *OrchestrationService {
    return &OrchestrationService{orchestrator: orchestrator}
}

// DeployAndExecuteContract deploys and then immediately executes a contract
func (s *OrchestrationService) DeployAndExecuteContract(config ContractConfig, action ContractAction) (ExecutionResult, error) {
    contractID, err := s.orchestrator.DeployContract(config)
    if err != nil {
        log.Printf("Error deploying contract: %v", err)
        return ExecutionResult{}, err
    }
    log.Printf("Contract deployed with ID: %s", contractID)

    result, err := s.orchestrator.ExecuteContract(contractID, action)
    if err != nil {
        log.Printf("Error executing contract action: %v", err)
        return ExecutionResult{}, err
    }
    return result, nil
}

// UpdateAndExecuteContract updates and then executes a contract
func (s *OrchestrationService) UpdateAndExecuteContract(contractID string, newConfig ContractConfig, action ContractAction) (ExecutionResult, error) {
    err := s.orchestrator.UpdateContract(contractID, newConfig)
    if err != nil {
        log.Printf("Error updating contract: %v", err)
        return ExecutionResult{}, err
    }
    log.Printf("Contract updated with new configuration")

    return s.orchestrator.ExecuteContract(contractID, action)
}

// SecureConfig encrypts the sensitive information within a ContractConfig using AES
func (s *OrchestrationService) SecureConfig(config *ContractConfig, encryptionKey []byte) error {
    encryptedData, err := encryptData(config.EncryptedSecrets, encryptionKey)
    if err != nil {
        return fmt.Errorf("failed to encrypt secrets: %v", err)
    }
    config.EncryptedSecrets = encryptedData
    return nil
}

// Helper functions

// encryptData performs AES encryption on data using the given key
func encryptData(data []byte, key []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    ciphertext := make([]byte, aes.BlockSize+len(data))
    iv := ciphertext[:aes.BlockSize]
    _, err = rand.Read(iv)
    if err != nil {
        return nil, err
    }
    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ciphertext[aes.BlockSize:], data)
    return ciphertext, nil
}

// generateEncryptionKey generates a new AES encryption key
func generateEncryptionKey() ([]byte, error) {
    key := make([]byte, 32) // Generates a 256-bit key
    _, err := rand.Read(key)
    if err != nil {
        return nil, fmt.Errorf("error generating encryption key: %v", err)
    }
    return key, nil
}

// base64Encode encodes data into a base64 format
func base64Encode(data []byte) string {
    return base64.StdEncoding.EncodeToString(data)
}
