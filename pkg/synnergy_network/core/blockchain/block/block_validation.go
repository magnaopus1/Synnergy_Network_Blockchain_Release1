package block

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/synnergy_network/crypto"
	"github.com/synnergy_network/utils"
)

// Block represents a block in the blockchain.
type Block struct {
	Header       BlockHeader `json:"header"`
	Transactions []Transaction `json:"transactions"`
}

// Transaction represents a transaction within a block.
type Transaction struct {
	Sender    string `json:"sender"`
	Recipient string `json:"recipient"`
	Amount    int    `json:"amount"`
	Signature string `json:"signature"`
	Timestamp time.Time `json:"timestamp"`
}

// NewBlock creates a new Block with the provided transactions and previous block hash.
func NewBlock(transactions []Transaction, previousHash string, difficulty int, validatorPubKey string) *Block {
	block := &Block{
		Header:       *NewBlockHeader(previousHash, difficulty, validatorPubKey),
		Transactions: transactions,
	}
	block.Header.MerkleRoot = block.calculateMerkleRoot()
	block.Header.Hash = block.Header.CalculateHash()
	return block
}

// calculateMerkleRoot calculates the Merkle root of the block's transactions.
func (b *Block) calculateMerkleRoot() string {
	var txHashes []string
	for _, tx := range b.Transactions {
		txHashes = append(txHashes, tx.CalculateHash())
	}
	return utils.CalculateMerkleRoot(txHashes)
}

// ValidateBlock verifies the integrity and validity of the block.
func (b *Block) ValidateBlock() error {
	if err := b.Header.VerifyBlockHeader(); err != nil {
		return err
	}
	if !b.validateMerkleRoot() {
		return errors.New("invalid Merkle root")
	}
	for _, tx := range b.Transactions {
		if err := tx.ValidateTransaction(); err != nil {
			return err
		}
	}
	return nil
}

// validateMerkleRoot checks if the Merkle root matches the calculated root.
func (b *Block) validateMerkleRoot() bool {
	return b.Header.MerkleRoot == b.calculateMerkleRoot()
}

// Serialize converts the block to a byte array.
func (b *Block) Serialize() ([]byte, error) {
	var result bytes.Buffer
	encoder := gob.NewEncoder(&result)
	err := encoder.Encode(b)
	if err != nil {
		return nil, err
	}
	return result.Bytes(), nil
}

// DeserializeBlock converts a byte array back to a Block.
func DeserializeBlock(data []byte) (*Block, error) {
	var b Block
	reader := bytes.NewReader(data)
	decoder := gob.NewDecoder(reader)
	err := decoder.Decode(&b)
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// Transaction validation

// CalculateHash computes the hash of the transaction.
func (tx *Transaction) CalculateHash() string {
	txBytes, _ := json.Marshal(tx)
	hash := sha256.Sum256(txBytes)
	return hex.EncodeToString(hash[:])
}

// ValidateTransaction verifies the integrity and validity of the transaction.
func (tx *Transaction) ValidateTransaction() error {
	txBytes, err := json.Marshal(tx)
	if err != nil {
		return err
	}
	if !crypto.VerifySignature(txBytes, tx.Signature, tx.Sender) {
		return errors.New("invalid transaction signature")
	}
	return nil
}

// Mining and validation functions

// MineBlock performs the mining operation to find a valid hash for the block.
func (b *Block) MineBlock() error {
	for {
		b.Header.Hash = b.Header.CalculateHash()
		if b.Header.ValidateHash() {
			return nil
		}
		b.Header.IncrementNonce()
	}
}

// VerifyBlockChain verifies the integrity and validity of the entire blockchain.
func VerifyBlockChain(blocks []*Block) error {
	for i := 1; i < len(blocks); i++ {
		if err := blocks[i].ValidateBlock(); err != nil {
			return err
		}
		if blocks[i].Header.PreviousHash != blocks[i-1].Header.Hash {
			return errors.New("invalid previous block hash")
		}
	}
	return nil
}
