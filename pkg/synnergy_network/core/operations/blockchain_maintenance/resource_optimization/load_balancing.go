package resource_optimization

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"time"

	"golang.org/x/crypto/scrypt"
)

// Block represents a single block in the blockchain.
type Block struct {
	Index        int
	Timestamp    time.Time
	Data         string
	PreviousHash string
	Hash         string
	Nonce        int
}

// Blockchain represents the entire blockchain.
type Blockchain struct {
	Blocks []Block
}

// NewBlock creates a new block using the given data and previous block's hash.
func NewBlock(data string, previousHash string, index int) Block {
	block := Block{
		Index:        index,
		Timestamp:    time.Now(),
		Data:         data,
		PreviousHash: previousHash,
		Hash:         "",
		Nonce:        0,
	}
	block.Hash = block.calculateHash()
	return block
}

// AddBlock adds a new block to the blockchain.
func (bc *Blockchain) AddBlock(data string) {
	prevBlock := bc.Blocks[len(bc.Blocks)-1]
	newBlock := NewBlock(data, prevBlock.Hash, prevBlock.Index+1)
	bc.Blocks = append(bc.Blocks, newBlock)
}

// calculateHash calculates the hash of the block.
func (b *Block) calculateHash() string {
	// Hash calculation logic, you can replace it with a more complex logic
	// if needed.
	record := string(b.Index) + b.Timestamp.String() + b.Data + b.PreviousHash + string(b.Nonce)
	return generateHash(record)
}

// ProofOfWork performs the proof-of-work algorithm to mine a new block.
func (b *Block) ProofOfWork(difficulty int) {
	target := ""
	for i := 0; i < difficulty; i++ {
		target += "0"
	}
	for b.Hash[:difficulty] != target {
		b.Nonce++
		b.Hash = b.calculateHash()
	}
}

// generateHash generates a hash using Scrypt.
func generateHash(data string) string {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		panic(err)
	}
	dk, err := scrypt.Key([]byte(data), salt, 16384, 8, 1, 32)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(dk)
}

// NewBlockchain creates a new blockchain with the genesis block.
func NewBlockchain() *Blockchain {
	genesisBlock := NewBlock("Genesis Block", "", 0)
	return &Blockchain{[]Block{genesisBlock}}
}

// Encrypt encrypts data using AES encryption.
func Encrypt(data string, passphrase string) (string, error) {
	block, err := aes.NewCipher([]byte(createHash(passphrase)))
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

	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return hex.EncodeToString(ciphertext), nil
}

// Decrypt decrypts data using AES encryption.
func Decrypt(encryptedData string, passphrase string) (string, error) {
	data, err := hex.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher([]byte(createHash(passphrase)))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// createHash creates a hash using Scrypt.
func createHash(passphrase string) string {
	salt := []byte("somesalt") // Replace with a more secure way to generate salt
	dk, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
	if err != nil {
		panic(err)
	}
	return string(dk)
}
