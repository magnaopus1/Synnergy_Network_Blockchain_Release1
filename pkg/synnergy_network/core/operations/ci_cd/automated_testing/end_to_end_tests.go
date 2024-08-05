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

// Structs for blockchain components
type Block struct {
	Index        int
	Timestamp    string
	Data         string
	PreviousHash string
	Hash         string
	Nonce        string
}

type Blockchain struct {
	Chain  []Block
	Length int
}

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
func generateBlock(oldBlock Block, data string, nonce string) (Block, error) {
	var newBlock Block
	t := time.Now()
	newBlock.Index = oldBlock.Index + 1
	newBlock.Timestamp = t.String()
	newBlock.Data = data
	newBlock.PreviousHash = oldBlock.Hash
	newBlock.Nonce = nonce

	hash, err := generateHash(newBlock.Data+newBlock.PreviousHash+newBlock.Nonce, []byte("fixed_salt"))
	if err != nil {
		return Block{}, err
	}
	newBlock.Hash = hash

	return newBlock, nil
}

// Verify blockchain integrity
func isBlockchainValid(chain []Block) bool {
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
func createMockBlockchain() Blockchain {
	genesisBlock := Block{0, time.Now().String(), "Genesis Block", "0", "", "nonce"}
	genesisBlock.Hash, _ = generateHash(genesisBlock.Data+genesisBlock.PreviousHash+genesisBlock.Nonce, []byte("fixed_salt"))
	blockchain := Blockchain{[]Block{genesisBlock}, 1}

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
