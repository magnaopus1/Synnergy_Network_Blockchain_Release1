package consensus

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"math/big"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
	"synnergy_network_blockchain/pkg/synnergy_network/core/common"
)


// NewProofOfHistory creates a new ProofOfHistory instance
func NewProofOfHistory() *ProofOfHistory {
	return &ProofOfHistory{
		timestampIndex: make(map[string]time.Time),
		rewards:        make(map[string]*big.Int),
		violations:     make(map[string][]common.Violation),
	}
}

// ProcessTransactions processes a list of transactions
func (poh *ProofOfHistory) ProcessTransactions(txs []*common.Transaction) error {
	for _, tx := range txs {
		// Generate timestamp
		txHash, err := poh.GenerateTimestamp(tx)
		if err != nil {
			return err
		}

		// Validate transaction
		err = poh.ValidateTransaction(tx, txHash)
		if err != nil {
			return err
		}

		// Add transaction to the latest block
		poh.blockchain[len(poh.blockchain)-1].Transactions = append(poh.blockchain[len(poh.blockchain)-1].Transactions, *tx)
	}

	// Generate new block with the processed transactions
	newBlock, err := poh.generateBlock(poh.blockchain[len(poh.blockchain)-1], "Processed Transactions")
	if err != nil {
		return err
	}

	// Add new block to the blockchain
	err = poh.addBlock(newBlock)
	if err != nil {
		return err
	}

	// Distribute rewards to validators
	err = poh.RewardValidators()
	if err != nil {
		return err
	}

	return nil
}

// GenerateTimestamp generates a timestamp for a given transaction
func (poh *ProofOfHistory) GenerateTimestamp(tx *Transaction) (string, error) {
	poh.mutex.Lock()
	defer poh.mutex.Unlock()

	txHash := sha256.Sum256([]byte(tx.ID + tx.Sender + tx.Receiver + fmt.Sprintf("%f", tx.Amount)))
	timestamp := time.Now()
	hashString := hex.EncodeToString(txHash[:])

	poh.timestampIndex[hashString] = timestamp

	return hashString, nil
}

// ValidateTransaction validates a transaction
func (poh *ProofOfHistory) ValidateTransaction(tx *common.Transaction, txHash string) error {
	// Check if the transaction hash is in the timestamp index
	if _, exists := poh.timestampIndex[txHash]; !exists {
		return errors.New("invalid transaction hash")
	}

	return nil
}

// Generate a new block
func (poh *ProofOfHistory) generateBlock(oldBlock common.Block, data string) (common.Block, error) {
	var newBlock common.Block

	t := time.Now()

	newBlock.Index = oldBlock.Index + 1
	newBlock.Timestamp = t.Unix()
	newBlock.PreviousHash = oldBlock.Hash
	newBlock.Data = data
	newBlock.CryptographicAnchor = poh.generateAnchor(oldBlock.CryptographicAnchor)
	newBlock.Hash = poh.calculateHash(newBlock)

	signature := poh.generateHash(newBlock.Hash)
	newBlock.Signature = hex.EncodeToString(signature)

	return newBlock, nil
}

// Calculate the hash of the block
func (poh *ProofOfHistory) calculateHash(block Block) string {
	record := fmt.Sprintf("%d%d%s%s%s", block.Index, block.Timestamp, block.PreviousHash, block.Data, block.CryptographicAnchor)
	h := sha256.Sum256([]byte(record))
	return hex.EncodeToString(h[:])
}

// Generate a cryptographic anchor
func (poh *ProofOfHistory) generateAnchor(previousAnchor string) string {
	t := time.Now()
	record := previousAnchor + t.String()
	h := sha256.Sum256([]byte(record))
	return hex.EncodeToString(h[:])
}

// Add a new block to the blockchain
func (poh *ProofOfHistory) addBlock(newBlock common.Block) error {
	poh.mutex.Lock()
	defer poh.mutex.Unlock()

	oldBlock := poh.blockchain[len(poh.blockchain)-1]
	if poh.isBlockValid(newBlock, oldBlock) {
		poh.blockchain = append(poh.blockchain, newBlock)
		return nil
	} else {
		return errors.New("invalid block")
	}
}

// Check if a block is valid
func (poh *ProofOfHistory) isBlockValid(newBlock, oldBlock common.Block) bool {
	if oldBlock.Index+1 != newBlock.Index {
		return false
	}

	if oldBlock.Hash != newBlock.PreviousHash {
		return false
	}

	if poh.calculateHash(newBlock) != newBlock.Hash {
		return false
	}

	return true
}

// Reward validators
func (poh *ProofOfHistory) RewardValidators() error {
	poh.mutex.Lock()
	defer poh.mutex.Unlock()

	lastBlock := poh.blockchain[len(poh.blockchain)-1]
	reward := big.NewInt(1000) // Placeholder reward value

	for _, tx := range lastBlock.Transactions {
		if _, exists := poh.rewards[tx.Sender]; !exists {
			poh.rewards[tx.Sender] = big.NewInt(0)
		}
		poh.rewards[tx.Sender].Add(poh.rewards[tx.Sender], reward)
	}

	return nil
}

// Generate hash using SHA-256
func (poh *ProofOfHistory) generateHash(data string) []byte {
	hash := sha256.Sum256([]byte(data))
	return hash[:]
}

