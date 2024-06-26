package block

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/synnergy_network/crypto"
	"github.com/synnergy_network/utils"
)

// BlockHeader represents the metadata of a block.
type BlockHeader struct {
	PreviousHash string    `json:"previous_hash"`
	Timestamp    time.Time `json:"timestamp"`
	Nonce        int       `json:"nonce"`
	MerkleRoot   string    `json:"merkle_root"`
	Hash         string    `json:"hash"`
	Difficulty   int       `json:"difficulty"`
	ValidatorPubKey string `json:"validator_pub_key"`
}

// Block represents a block in the blockchain.
type Block struct {
	Header       BlockHeader   `json:"header"`
	Transactions []Transaction `json:"transactions"`
}

// Transaction represents a transaction within a block.
type Transaction struct {
	Sender    string    `json:"sender"`
	Recipient string    `json:"recipient"`
	Amount    int       `json:"amount"`
	Signature string    `json:"signature"`
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

// NewBlockHeader creates a new BlockHeader.
func NewBlockHeader(previousHash string, difficulty int, validatorPubKey string) *BlockHeader {
	return &BlockHeader{
		PreviousHash:  previousHash,
		Timestamp:     time.Now(),
		Difficulty:    difficulty,
		ValidatorPubKey: validatorPubKey,
	}
}

// CalculateHash computes the hash of the block header.
func (h *BlockHeader) CalculateHash() string {
	record := h.PreviousHash + h.Timestamp.String() + string(h.Nonce) + h.MerkleRoot + string(h.Difficulty) + h.ValidatorPubKey
	hash := sha256.New()
	hash.Write([]byte(record))
	hashed := hash.Sum(nil)
	return hex.EncodeToString(hashed)
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

// VerifyBlockHeader verifies the block header integrity and difficulty.
func (h *BlockHeader) VerifyBlockHeader() error {
	calculatedHash := h.CalculateHash()
	if h.Hash != calculatedHash {
		return errors.New("block header hash does not match calculated hash")
	}
	if !h.ValidateHash() {
		return errors.New("block header hash does not meet difficulty requirements")
	}
	return nil
}

// ValidateHash checks if the hash meets the difficulty requirements.
func (h *BlockHeader) ValidateHash() bool {
	prefix := bytes.Repeat([]byte{0}, h.Difficulty)
	return bytes.HasPrefix([]byte(h.Hash), prefix)
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
		b.Header.Nonce++
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
