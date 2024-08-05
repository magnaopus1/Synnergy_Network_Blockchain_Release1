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
	"github.com/synnergy_network/blockchain/core"
	"github.com/synnergy_network/blockchain/security"
	"github.com/synnergy_network/blockchain/consensus"
	"github.com/synnergy_network/blockchain/monitoring"
)

// Helper function to generate random bytes
func generateRandomBytes(size int) ([]byte, error) {
	bytes := make([]byte, size)
	_, err := rand.Read(bytes)
	return bytes, err
}

// Encrypt data using AES
func encrypt(data []byte, passphrase string) ([]byte, error) {
	salt, err := generateRandomBytes(16)
	if err != nil {
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

	nonce, err := generateRandomBytes(gcm.NonceSize())
	if err != nil {
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

// Test encryption and decryption
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

// Test hash generation
func TestGenerateHash(t *testing.T) {
	data := "Test Data"
	salt := []byte("fixed_salt")
	hash1, err := generateHash(data, salt)
	if err != nil {
		t.Fatalf("Failed to generate hash: %v", err)
	}

	hash2, err := generateHash(data, salt)
	if err != nil {
		t.Fatalf("Failed to generate hash: %v", err)
	}

	if hash1 != hash2 {
		t.Errorf("Hashes do not match")
	}
}

// Create a mock blockchain for testing
func createMockBlockchain() core.Blockchain {
	genesisBlock := core.Block{
		Index:        0,
		Timestamp:    time.Now().String(),
		Data:         "Genesis Block",
		PreviousHash: "0",
		Nonce:        "nonce",
	}
	genesisBlock.Hash, _ = generateHash(genesisBlock.Data+genesisBlock.PreviousHash+genesisBlock.Nonce, []byte("fixed_salt"))
	blockchain := core.Blockchain{Chain: []core.Block{genesisBlock}, Length: 1}

	for i := 1; i < 5; i++ {
		newBlock, _ := generateBlock(blockchain.Chain[i-1], fmt.Sprintf("Block %d Data", i), "nonce")
		blockchain.Chain = append(blockchain.Chain, newBlock)
		blockchain.Length++
	}

	return blockchain
}

// Generate a new block
func generateBlock(oldBlock core.Block, data string, nonce string) (core.Block, error) {
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

// Test blockchain integrity
func TestBlockchainIntegrity(t *testing.T) {
	blockchain := createMockBlockchain()
	if !isBlockchainValid(blockchain.Chain) {
		t.Errorf("Blockchain is invalid")
	}
}

// Test function for consensus
func TestConsensusMechanism(t *testing.T) {
	blockchain := createMockBlockchain()
	newBlock, err := generateBlock(blockchain.Chain[len(blockchain.Chain)-1], "New Block Data", "nonce")
	if err != nil {
		t.Fatalf("Failed to generate new block: %v", err)
	}

	isValid, err := consensus.ValidateBlock(newBlock, blockchain.Chain[len(blockchain.Chain)-1])
	if err != nil {
		t.Fatalf("Consensus validation failed: %v", err)
	}

	if !isValid {
		t.Errorf("New block is not valid according to consensus mechanism")
	}
}

// Mock security module tests
func TestSecurityModule(t *testing.T) {
	blockchain := createMockBlockchain()
	vulnerabilities := security.ScanForVulnerabilities(blockchain)

	if len(vulnerabilities) > 0 {
		t.Errorf("Vulnerabilities found: %v", vulnerabilities)
	}

	code := `
		package main

		func main() {
			println("Hello, world!")
		}
	`
	issues := security.StaticCodeAnalysis(code)
	if len(issues) > 0 {
		t.Errorf("Static code analysis found issues: %v", issues)
	}
}

// Test function for monitoring
func TestMonitoringModule(t *testing.T) {
	blockchain := createMockBlockchain()
	monitoringData := monitoring.CollectData(blockchain)

	if len(monitoringData) == 0 {
		t.Errorf("No monitoring data collected")
	}
}
