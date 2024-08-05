// Package node provides functionalities and services for the nodes within the Synnergy Network blockchain,
// including block validation to ensure the integrity and security of the blockchain.
package node

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/synnergy_network/security"
)

// Block represents a block in the blockchain.
type Block struct {
	Index        int
	Timestamp    time.Time
	Data         string
	PreviousHash string
	Hash         string
	Nonce        int
}

// Blockchain represents the blockchain.
type Blockchain struct {
	blocks       []Block
	mutex        sync.Mutex
	SecuritySettings SecuritySettings
}

// SecuritySettings contains settings related to the security of the blockchain.
type SecuritySettings struct {
	EncryptionAlgorithm string
	Salt                []byte
}

// NewBlockchain creates a new Blockchain with a genesis block.
func NewBlockchain(securitySettings SecuritySettings) *Blockchain {
	bc := &Blockchain{
		SecuritySettings: securitySettings,
	}
	bc.addGenesisBlock()
	return bc
}

// addGenesisBlock adds the genesis block to the blockchain.
func (bc *Blockchain) addGenesisBlock() {
	genesisBlock := Block{
		Index:        0,
		Timestamp:    time.Now(),
		Data:         "Genesis Block",
		PreviousHash: "",
		Hash:         calculateHash(0, time.Now(), "Genesis Block", "", 0),
		Nonce:        0,
	}
	bc.blocks = append(bc.blocks, genesisBlock)
}

// GetLastBlock returns the last block in the blockchain.
func (bc *Blockchain) GetLastBlock() Block {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	return bc.blocks[len(bc.blocks)-1]
}

// AddBlock adds a new block to the blockchain.
func (bc *Blockchain) AddBlock(data string) error {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	lastBlock := bc.blocks[len(bc.blocks)-1]
	newBlock, err := generateBlock(lastBlock, data)
	if err != nil {
		return err
	}

	if !isBlockValid(newBlock, lastBlock) {
		return errors.New("invalid block")
	}

	bc.blocks = append(bc.blocks, newBlock)
	return nil
}

// generateBlock generates a new block based on the previous block and data.
func generateBlock(prevBlock Block, data string) (Block, error) {
	newBlock := Block{
		Index:        prevBlock.Index + 1,
		Timestamp:    time.Now(),
		Data:         data,
		PreviousHash: prevBlock.Hash,
	}
	newBlock.Hash = calculateHash(newBlock.Index, newBlock.Timestamp, newBlock.Data, newBlock.PreviousHash, newBlock.Nonce)

	return newBlock, nil
}

// calculateHash calculates the hash for a block.
func calculateHash(index int, timestamp time.Time, data, previousHash string, nonce int) string {
	record := string(index) + timestamp.String() + data + previousHash + string(nonce)
	hash := sha256.New()
	hash.Write([]byte(record))
	hashed := hash.Sum(nil)
	return hex.EncodeToString(hashed)
}

// isBlockValid validates a block based on the previous block.
func isBlockValid(newBlock, oldBlock Block) bool {
	if oldBlock.Index+1 != newBlock.Index {
		return false
	}

	if oldBlock.Hash != newBlock.PreviousHash {
		return false
	}

	if calculateHash(newBlock.Index, newBlock.Timestamp, newBlock.Data, newBlock.PreviousHash, newBlock.Nonce) != newBlock.Hash {
		return false
	}

	return true
}

// EncryptBlock encrypts the block data using the specified encryption algorithm.
func (bc *Blockchain) EncryptBlock(block *Block) error {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	data, err := json.Marshal(block)
	if err != nil {
		return err
	}

	var encryptedData []byte
	switch bc.SecuritySettings.EncryptionAlgorithm {
	case "AES":
		encryptedData, err = security.EncryptAES(data, bc.SecuritySettings.Salt)
	case "Scrypt":
		encryptedData, err = security.EncryptScrypt(data, bc.SecuritySettings.Salt)
	case "Argon2":
		encryptedData, err = security.EncryptArgon2(data, bc.SecuritySettings.Salt)
	default:
		return errors.New("unsupported encryption algorithm")
	}

	if err != nil {
		return err
	}

	block.Data = hex.EncodeToString(encryptedData)
	return nil
}

// DecryptBlock decrypts the block data using the specified encryption algorithm.
func (bc *Blockchain) DecryptBlock(block *Block) error {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	encryptedData, err := hex.DecodeString(block.Data)
	if err != nil {
		return err
	}

	var decryptedData []byte
	switch bc.SecuritySettings.EncryptionAlgorithm {
	case "AES":
		decryptedData, err = security.DecryptAES(encryptedData, bc.SecuritySettings.Salt)
	case "Scrypt":
		decryptedData, err = security.DecryptScrypt(encryptedData, bc.SecuritySettings.Salt)
	case "Argon2":
		decryptedData, err = security.DecryptArgon2(encryptedData, bc.SecuritySettings.Salt)
	default:
		return errors.New("unsupported encryption algorithm")
	}

	if err != nil {
		return err
	}

	err = json.Unmarshal(decryptedData, block)
	if err != nil {
		return err
	}

	return nil
}
