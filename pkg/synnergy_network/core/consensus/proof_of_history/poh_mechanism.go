package consensus

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"synnergy_network/pkg/synnergy_network/core/common"
)

// PoH defines the structure for managing Proof of History.
type PoH struct {
	Blocks []*Block
	ChainLock sync.Mutex
}

// Block defines the structure of each block in the blockchain.
type Block struct {
	Timestamp       time.Time
	Transactions    []*Transaction
	PrevBlockHash   string
	ThisBlockHash   string
	MerkleRoot      string
	CryptographicAnchor string
}

// Transaction defines the structure of a blockchain transaction.
type Transaction struct {
	ID        string
	Timestamp time.Time
	Payload   interface{}
	Signature string
}

// NewPoH initializes a new Proof of History blockchain.
func NewPoH() *PoH {
	return &PoH{
		Blocks: make([]*Block, 0),
	}
}

// GenerateHash computes the SHA-256 hash for block data.
func GenerateHash(block *Block) string {
	record := string(block.Timestamp.Format(time.RFC3339)) + block.PrevBlockHash + block.MerkleRoot
	hash := sha256.Sum256([]byte(record))
	return hex.EncodeToString(hash[:])
}

// CreateBlock creates a new block using the provided transactions.
func (p *PoH) CreateBlock(transactions []*Transaction, prevBlock *Block) *Block {
	block := &Block{
		Timestamp:       time.Now(),
		Transactions:    transactions,
		PrevBlockHash:   prevBlock.ThisBlockHash,
		MerkleRoot:      CalculateMerkleRoot(transactions),
	}
	block.ThisBlockHash = GenerateHash(block)
	block.CryptographicAnchor = GenerateCryptographicAnchor(block)
	return block
}

// CalculateMerkleRoot calculates the Merkle root for the transactions in the block.
func CalculateMerkleRoot(transactions []*Transaction) string {
	var transactionHashes []string
	for _, transaction := range transactions {
		hash := sha256.Sum256([]byte(transaction.ID))
		transactionHashes = append(transactionHashes, hex.EncodeToString(hash[:]))
	}
	return GenerateMerkleRootFromHashes(transactionHashes)
}

// GenerateMerkleRootFromHashes helper function to generate Merkle root from hashes.
func GenerateMerkleRootFromHashes(hashes []string) string {
	if len(hashes) == 1 {
		return hashes[0]
	}
	var newLevel []string
	for i := 0; i < len(hashes); i += 2 {
		if i+1 < len(hashes) {
			hash := sha256.Sum256([]byte(hashes[i] + hashes[i+1]))
			newLevel = append(newLevel, hex.EncodeToString(hash[:]))
		} else {
			newLevel = append(newLevel, hashes[i])
		}
	}
	return GenerateMerkleRootFromHashes(newLevel)
}

// GenerateCryptographicAnchor generates a cryptographic anchor for the block.
func GenerateCryptographicAnchor(block *Block) string {
	data := block.ThisBlockHash + block.MerkleRoot
	return hex.EncodeToString(sha256.New().Sum([]byte(data)))
}

// AppendBlock adds a new block to the blockchain.
func (p *PoH) AppendBlock(block *Block) error {
	p.ChainLock.Lock()
	defer p.ChainLock.Unlock()

	if len(p.Blocks) > 0 && p.Blocks[len(p.Blocks)-1].ThisBlockHash != block.PrevBlockHash {
		return errors.New("invalid block sequence")
	}
	p.Blocks = append(p.Blocks, block)
	return nil
}

// GetCurrentBlock returns the most recent block in the chain.
func (p *PoH) GetCurrentBlock() *Block {
	if len(p.Blocks) == 0 {
		return nil
	}
	return p.Blocks[len(p.Blocks)-1]
}
