package chain

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/synnergy_network/pkg/synnergy_network/core/blockchain/block"
	"github.com/synnergy_network/pkg/synnergy_network/core/crypto"
	"github.com/synnergy_network/pkg/synnergy_network/core/utils"
	"github.com/synnergy_network/pkg/synnergy_network/core/ai"
)

// Chain represents the blockchain as a whole
type Chain struct {
	Blocks     []*block.Block
	Difficulty int
	Logger     *utils.Logger
}

// NewChain initializes a new blockchain with a genesis block
func NewChain() *Chain {
	genesisBlock := createGenesisBlock()
	return &Chain{
		Blocks:     []*block.Block{genesisBlock},
		Difficulty: 4, // Example difficulty level, adjust as needed
		Logger:     utils.NewLogger(),
	}
}

// createGenesisBlock creates the genesis block for the blockchain
func createGenesisBlock() *block.Block {
	genesisBlock := &block.Block{
		Header: block.BlockHeader{
			PreviousHash: "",
			Timestamp:    time.Now(),
			Nonce:        0,
			MerkleRoot:   "",
		},
		Body: block.BlockBody{
			Transactions: []block.Transaction{},
		},
	}
	genesisBlock.GenerateMerkleRoot()
	return genesisBlock
}

// AddBlock adds a new block to the blockchain after validation and consensus
func (c *Chain) AddBlock(newBlock *block.Block) error {
	lastBlock := c.Blocks[len(c.Blocks)-1]
	newBlock.Header.PreviousHash = lastBlock.Header.MerkleRoot

	if err := c.mineBlock(newBlock); err != nil {
		return err
	}

	if err := c.validateBlock(newBlock); err != nil {
		return err
	}

	c.Blocks = append(c.Blocks, newBlock)
	c.Logger.Info("Block added: %s", newBlock.Header.MerkleRoot)
	return nil
}

// mineBlock performs proof of work to add the block to the chain
func (c *Chain) mineBlock(b *block.Block) error {
	target := fmt.Sprintf("%x", 1<<(256-c.Difficulty))
	for {
		hash := b.Hash()
		if hash < target {
			b.Header.MerkleRoot = hash
			return nil
		}
		b.Header.Nonce++
	}
}

// validateBlock verifies the integrity and validity of a block
func (c *Chain) validateBlock(b *block.Block) error {
	previousBlock := c.Blocks[len(c.Blocks)-1]
	if b.Header.PreviousHash != previousBlock.Header.MerkleRoot {
		return errors.New("invalid previous hash")
	}
	return b.VerifyBlock()
}

// ZeroKnowledgeProof represents a zero-knowledge proof structure
type ZeroKnowledgeProof struct {
	Proof       string             `json:"proof"`
	ProofType   string             `json:"proof_type"`
	Verified    bool               `json:"verified"`
	Transaction block.Transaction `json:"transaction"`
}

// Block represents a block in the blockchain
type Block struct {
	Header   BlockHeader      `json:"header"`
	Body     BlockBody        `json:"body"`
	ZKProofs []ZeroKnowledgeProof `json:"zk_proofs"`
}

// BlockHeader represents the metadata of a block
type BlockHeader struct {
	PreviousHash string    `json:"previous_hash"`
	Timestamp    time.Time `json:"timestamp"`
	Nonce        int       `json:"nonce"`
	MerkleRoot   string    `json:"merkle_root"`
}

// BlockBody represents the actual transactional data in a block
type BlockBody struct {
	Transactions []Transaction `json:"transactions"`
}

// Transaction represents a blockchain transaction
type Transaction struct {
	Sender    string `json:"sender"`
	Recipient string `json:"recipient"`
	Amount    int    `json:"amount"`
	Signature string `json:"signature"`
}

// ZeroKnowledgeIntegration represents the integration logic for zero-knowledge proofs
type ZeroKnowledgeIntegration struct {
	logger     *utils.Logger
	proofModel ai.Model
}

// NewZeroKnowledgeIntegration creates a new instance of ZeroKnowledgeIntegration
func NewZeroKnowledgeIntegration() *ZeroKnowledgeIntegration {
	return &ZeroKnowledgeIntegration{
		logger:     utils.NewLogger(),
		proofModel: ai.NewModel("zero_knowledge_proofs"),
	}
}

// AddZeroKnowledgeProof adds a zero-knowledge proof to a block
func (zki *ZeroKnowledgeIntegration) AddZeroKnowledgeProof(block *Block, proof ZeroKnowledgeProof) error {
	if err := zki.verifyZeroKnowledgeProof(proof); err != nil {
		return fmt.Errorf("zero-knowledge proof failed verification: %w", err)
	}

	block.ZKProofs = append(block.ZKProofs, proof)
	zki.logger.Info("Zero-knowledge proof added to block: %s", proof.ProofType)
	return nil
}

// verifyZeroKnowledgeProof verifies a zero-knowledge proof using AI
func (zki *ZeroKnowledgeIntegration) verifyZeroKnowledgeProof(proof ZeroKnowledgeProof) error {
	result, err := zki.proofModel.Evaluate(proof)
	if err != nil {
		zki.logger.Error("AI verification failed: %s", err)
		return err
	}
	if result.Score < 0.95 { // Example threshold, adjust as necessary
		zki.logger.Warn("Zero-knowledge proof verification failed: %s", result.Reason)
		return errors.New(result.Reason)
	}
	zki.logger.Info("Zero-knowledge proof verification passed")
	return nil
}

// GenerateMerkleRoot generates a Merkle root for the transactions in the block
func (block *Block) GenerateMerkleRoot() {
	var txHashes [][]byte
	for _, tx := range block.Body.Transactions {
		txHash := sha256.Sum256([]byte(fmt.Sprintf("%s%s%d%s", tx.Sender, tx.Recipient, tx.Amount, tx.Signature)))
		txHashes = append(txHashes, txHash[:])
	}

	merkleRoot := computeMerkleRoot(txHashes)
	block.Header.MerkleRoot = fmt.Sprintf("%x", merkleRoot)
}

// computeMerkleRoot computes the Merkle root from transaction hashes
func computeMerkleRoot(txHashes [][]byte) []byte {
	if len(txHashes) == 0 {
		return nil
	}
	if len(txHashes) == 1 {
		return txHashes[0]
	}

	var newLevel [][]byte
	for i := 0; i < len(txHashes); i += 2 {
		if i+1 < len(txHashes) {
			newLevel = append(newLevel, hashPair(txHashes[i], txHashes[i+1]))
		} else {
			newLevel = append(newLevel, hashPair(txHashes[i], txHashes[i]))
		}
	}

	return computeMerkleRoot(newLevel)
}

// hashPair hashes a pair of byte slices
func hashPair(a, b []byte) []byte {
	h := sha256.New()
	h.Write(a)
	h.Write(b)
	return h.Sum(nil)
}

// VerifyBlock verifies the block's transactions and zero-knowledge proofs
func (block *Block) VerifyBlock() error {
	for _, tx := range block.Body.Transactions {
		if err := verifyTransaction(tx); err != nil {
			return err
		}
	}
	for _, zkProof := range block.ZKProofs {
		if err := verifyZeroKnowledgeProof(zkProof); err != nil {
			return err
		}
	}
	return nil
}

// verifyTransaction verifies a single transaction
func verifyTransaction(tx Transaction) error {
	// Placeholder for actual transaction verification logic
	return nil
}

// verifyZeroKnowledgeProof verifies a single zero-knowledge proof
func verifyZeroKnowledgeProof(zkProof ZeroKnowledgeProof) error {
	// Placeholder for actual zero-knowledge proof verification logic
	return nil
}

// Serialize serializes a block to JSON
func (block *Block) Serialize() ([]byte, error) {
	return json.Marshal(block)
}

// Deserialize deserializes JSON data to a block
func (block *Block) Deserialize(data []byte) error {
	return json.Unmarshal(data, block)
}

// Hash computes the hash of a block
func (b *Block) Hash() string {
	data := fmt.Sprintf("%s%s%d", b.Header.PreviousHash, b.Header.Timestamp, b.Header.Nonce)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// ValidateChain checks the integrity of the entire blockchain
func (c *Chain) ValidateChain() error {
	for i := 1; i < len(c.Blocks); i++ {
		currentBlock := c.Blocks[i]
		previousBlock := c.Blocks[i-1]

		if currentBlock.Header.PreviousHash != previousBlock.Header.MerkleRoot {
			return fmt.Errorf("block %d has invalid previous hash", i)
		}

		if err := currentBlock.VerifyBlock(); err != nil {
			return fmt.Errorf("block %d failed verification: %w", i, err)
		}
	}

	c.Logger.Info("Blockchain validation passed")
	return nil
}

// AdjustDifficulty dynamically adjusts the difficulty of the blockchain
func (c *Chain) AdjustDifficulty() {
	if len(c.Blocks) < 10 {
		return
	}

	lastBlock := c.Blocks[len(c.Blocks)-1]
	firstBlock := c.Blocks[len(c.Blocks)-10]

	timeTaken := lastBlock.Header.Timestamp.Sub(firstBlock.Header.Timestamp)
	expectedTime := time.Duration(10 * 10 * time.Second)

	if timeTaken < expectedTime {
		c.Difficulty++
	} else if timeTaken > expectedTime {
		c.Difficulty--
	}

	c.Logger.Info("Adjusted difficulty to %d", c.Difficulty)
}

// GetBlockByHash retrieves a block by its hash
func (c *Chain) GetBlockByHash(hash string) (*block.Block, error) {
	for _, blk := range c.Blocks {
		if blk.Hash() == hash {
			return blk, nil
		}
	}
	return nil, fmt.Errorf("block with hash %s not found", hash)
}

// GetBlockByIndex retrieves a block by its index
func (c *Chain) GetBlockByIndex(index int) (*block.Block, error) {
	if index < 0 || index >= len(c.Blocks) {
		return nil, fmt.Errorf("block index %d out of range", index)
	}
	return c.Blocks[index], nil
}

// PerformTransaction executes a transaction and adds it to the next block
func (c *Chain) PerformTransaction(tx block.Transaction) error {
	// Validate the transaction
	if err := verifyTransaction(tx); err != nil {
		return err
	}

	// Create a new block with the transaction
	newBlock := &block.Block{
		Header: block.BlockHeader{
			PreviousHash: c.Blocks[len(c.Blocks)-1].Header.MerkleRoot,
			Timestamp:    time.Now(),
			Nonce:        0,
		},
		Body: block.BlockBody{
			Transactions: []block.Transaction{tx},
		},
	}

	// Mine and add the block to the chain
	return c.AddBlock(newBlock)
}

// EncryptTransaction encrypts transaction data
func EncryptTransaction(tx block.Transaction, key []byte) ([]byte, error) {
	data, err := json.Marshal(tx)
	if err != nil {
		return nil, err
	}
	return crypto.EncryptAES(data, key)
}

// DecryptTransaction decrypts transaction data
func DecryptTransaction(data []byte, key []byte) (*block.Transaction, error) {
	decryptedData, err := crypto.DecryptAES(data, key)
	if err != nil {
		return nil, err
	}
	var tx block.Transaction
	err = json.Unmarshal(decryptedData, &tx)
	if err != nil {
		return nil, err
	}
	return &tx, nil
}

// LogBlock logs the block details
func LogBlock(b *block.Block) {
	fmt.Printf("Block:\n")
	fmt.Printf("  Previous Hash: %s\n", b.Header.PreviousHash)
	fmt.Printf("  Timestamp: %s\n", b.Header.Timestamp)
	fmt.Printf("  Nonce: %d\n", b.Header.Nonce)
	fmt.Printf("  Merkle Root: %s\n", b.Header.MerkleRoot)
	fmt.Printf("  Transactions: %d\n", len(b.Body.Transactions))
	for i, tx := range b.Body.Transactions {
		fmt.Printf("    Transaction %d:\n", i)
		fmt.Printf("      Sender: %s\n", tx.Sender)
		fmt.Printf("      Recipient: %s\n", tx.Recipient)
		fmt.Printf("      Amount: %d\n", tx.Amount)
		fmt.Printf("      Signature: %s\n", tx.Signature)
	}
}

// SaveChain saves the blockchain to a file
func (c *Chain) SaveChain(filename string) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return utils.WriteFile(filename, data)
}

// LoadChain loads the blockchain from a file
func LoadChain(filename string) (*Chain, error) {
	data, err := utils.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var chain Chain
	err = json.Unmarshal(data, &chain)
	if err != nil {
		return nil, err
	}
	return &chain, nil
}
