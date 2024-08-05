package automated_testing

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"testing"
	"time"

	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/argon2"

)

// Encrypt data using AES
func encrypt(data []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 1<<15, 8, 1, 32)
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

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return append(salt, ciphertext...), nil
}

// Decrypt data using AES
func decrypt(data []byte, passphrase string) ([]byte, error) {
	salt := data[:16]
	data = data[16:]

	key, err := scrypt.Key([]byte(passphrase), salt, 1<<15, 8, 1, 32)
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
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// Generate hash using Argon2
func generateHash(data string, salt []byte) (string, error) {
	hash := argon2.IDKey([]byte(data), salt, 1, 64*1024, 4, 32)
	return fmt.Sprintf("%x", hash), nil
}

// Generate a new block
func generateBlock(oldBlock common.Block, data string, nonce string) (common.Block, error) {
	var newBlock core.Block
	t := time.Now()
	newBlock.Index = oldBlock.Index + 1
	newBlock.Timestamp = t.String()
	newBlock.Data = data
	newBlock.PreviousHash = oldBlock.Hash
	newBlock.Nonce = nonce

	hash, err := generateHash(newBlock.Data+newBlock.PreviousHash+newBlock.Nonce, []byte("fixed_salt"))
	if err != nil {
		return core.Block{}, err
	}
	newBlock.Hash = hash

	return newBlock, nil
}

// Verify blockchain integrity
func isBlockchainValid(chain []core.Block) bool {
	for i := 1; i < len(chain); i++ {
		prevBlock := chain[i-1]
		currentBlock := chain[i]

		if currentBlock.PreviousHash != prevBlock.Hash {
			return false
		}

		hash, err := generateHash(currentBlock.Data+currentBlock.PreviousHash+currentBlock.Nonce, []byte("fixed_salt"))
		if err != nil {
			return false
		}
		if currentBlock.Hash != hash {
			return false
		}
	}
	return true
}

// Mock data for testing
func createMockBlockchain() core.Blockchain {
	genesisBlock := core.Block{0, time.Now().String(), "Genesis Block", "0", "", "nonce"}
	genesisBlock.Hash, _ = generateHash(genesisBlock.Data+genesisBlock.PreviousHash+genesisBlock.Nonce, []byte("fixed_salt"))
	blockchain := core.Blockchain{[]core.Block{genesisBlock}, 1}

	for i := 1; i < 5; i++ {
		newBlock, _ := generateBlock(blockchain.Chain[i-1], fmt.Sprintf("Block %d Data", i), "nonce")
		blockchain.Chain = append(blockchain.Chain, newBlock)
		blockchain.Length++
	}

	return blockchain
}

// Test function for blockchain integrity
func TestBlockchainIntegrity(t *testing.T) {
	blockchain := createMockBlockchain()
	if !isBlockchainValid(blockchain.Chain) {
		t.Errorf("Blockchain is invalid")
	}
}

// Test function for encryption and decryption
func TestEncryptionDecryption(t *testing.T) {
	data := []byte("Test Data")
	passphrase := "password"
	encryptedData, err := encrypt(data, passphrase)
	if err != nil {
		t.Fatalf("Failed to encrypt data: %v", err)
	}

	decryptedData, err := decrypt(encryptedData, passphrase)
	if err != nil {
		t.Fatalf("Failed to decrypt data: %v", err)
	}

	if !bytes.Equal(data, decryptedData) {
		t.Errorf("Decrypted data does not match original data")
	}
}

// Test function for consensus algorithm
func TestConsensusAlgorithm(t *testing.T) {
	blockchain := createMockBlockchain()
	consensusReached := consensus.PoW(blockchain)

	if !consensusReached {
		t.Errorf("Consensus algorithm failed to reach agreement")
	}
}

// Performance test function
func TestPerformance(t *testing.T) {
	start := time.Now()
	blockchain := createMockBlockchain()
	duration := time.Since(start)

	t.Logf("Blockchain creation took %v", duration)
	if duration.Seconds() > 1 {
		t.Errorf("Blockchain creation took too long: %v", duration)
	}
}

// Security test function
func TestSecurity(t *testing.T) {
	blockchain := createMockBlockchain()
	blockchain.Chain[2].Data = "Tampered Data"

	if isBlockchainValid(blockchain.Chain) {
		t.Errorf("Blockchain integrity check failed to detect tampering")
	}
}

// Integration test function
func TestIntegration(t *testing.T) {
	blockchain := createMockBlockchain()
	data := map[string]string{"Data": "Test Data"}
	jsonData, _ := json.Marshal(data)

	newBlock, err := generateBlock(blockchain.Chain[blockchain.Length-1], string(jsonData), "nonce")
	if err != nil {
		t.Fatalf("Failed to generate new block: %v", err)
	}

	blockchain.Chain = append(blockchain.Chain, newBlock)
	blockchain.Length++

	if !isBlockchainValid(blockchain.Chain) {
		t.Errorf("Blockchain is invalid after adding new block")
	}
}

// Test function for smart contract deployment
func TestSmartContractDeployment(t *testing.T) {
	contract := `{"name": "TestContract", "version": "1.0", "code": "function() { return 'Hello, world!'; }"}`
	compiledContract, err := core.CompileSmartContract(contract)
	if err != nil {
		t.Fatalf("Failed to compile smart contract: %v", err)
	}

	deploymentSuccess := core.DeploySmartContract(compiledContract)
	if !deploymentSuccess {
		t.Errorf("Smart contract deployment failed")
	}
}

// Test function for automated recovery
func TestAutomatedRecovery(t *testing.T) {
	blockchain := createMockBlockchain()
	blockchain.Chain[2].Data = "Tampered Data"

	recoverySuccess := security.AutomatedRecovery(blockchain)
	if !recoverySuccess {
		t.Errorf("Automated recovery failed")
	}
}

// Test function for AI-driven maintenance
func TestAIDrivenMaintenance(t *testing.T) {
	blockchain := createMockBlockchain()
	maintenanceSuccess := core.AIDrivenMaintenance(blockchain)

	if !maintenanceSuccess {
		t.Errorf("AI-driven maintenance failed")
	}
}
