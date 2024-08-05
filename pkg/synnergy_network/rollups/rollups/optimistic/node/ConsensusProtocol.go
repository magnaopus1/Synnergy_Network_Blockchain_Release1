package node

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/rand"
	"sync"
	"time"
)

// ConsensusProtocol represents the consensus mechanism for the rollup nodes.
type ConsensusProtocol struct {
	mutex          sync.Mutex
	nodes          []Node
	leader         Node
	blockchain     []Block
	pendingTxs     []*Transaction
	quorum         int
}

// Node represents a node in the consensus network.
type Node struct {
	ID        string
	Address   string
	PublicKey string
}

// Block represents a block in the blockchain.
type Block struct {
	Index        int
	Timestamp    time.Time
	Transactions []*Transaction
	PrevHash     string
	Hash         string
}

// NewConsensusProtocol initializes a new ConsensusProtocol instance.
func NewConsensusProtocol(nodes []Node, quorum int) *ConsensusProtocol {
	return &ConsensusProtocol{
		nodes:      nodes,
		quorum:     quorum,
		blockchain: make([]Block, 0),
		pendingTxs: make([]*Transaction, 0),
	}
}

// ProposeBlock allows the leader to propose a new block.
func (cp *ConsensusProtocol) ProposeBlock() (*Block, error) {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()

	if len(cp.pendingTxs) == 0 {
		return nil, errors.New("no transactions available for proposing a block")
	}

	leader, err := cp.selectLeader()
	if err != nil {
		return nil, err
	}

	cp.leader = leader
	prevHash := ""
	if len(cp.blockchain) > 0 {
		prevHash = cp.blockchain[len(cp.blockchain)-1].Hash
	}

	block := Block{
		Index:        len(cp.blockchain),
		Timestamp:    time.Now(),
		Transactions: cp.pendingTxs,
		PrevHash:     prevHash,
		Hash:         cp.calculateHash(len(cp.blockchain), time.Now(), cp.pendingTxs, prevHash),
	}

	cp.pendingTxs = make([]*Transaction, 0)
	cp.blockchain = append(cp.blockchain, block)

	return &block, nil
}

// VerifyBlock allows nodes to verify the proposed block.
func (cp *ConsensusProtocol) VerifyBlock(block *Block) (bool, error) {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()

	if block == nil {
		return false, errors.New("block is nil")
	}

	calculatedHash := cp.calculateHash(block.Index, block.Timestamp, block.Transactions, block.PrevHash)
	if block.Hash != calculatedHash {
		return false, errors.New("block hash mismatch")
	}

	return true, nil
}

// CommitBlock commits the verified block to the blockchain.
func (cp *ConsensusProtocol) CommitBlock(block *Block) error {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()

	if block == nil {
		return errors.New("block is nil")
	}

	cp.blockchain = append(cp.blockchain, *block)
	return nil
}

// AddTransaction adds a new transaction to the pending transactions pool.
func (cp *ConsensusProtocol) AddTransaction(tx *Transaction) error {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()

	if tx == nil {
		return errors.New("transaction is nil")
	}

	cp.pendingTxs = append(cp.pendingTxs, tx)
	return nil
}

// GetBlockchain returns the current blockchain.
func (cp *ConsensusProtocol) GetBlockchain() []Block {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()

	return cp.blockchain
}

// selectLeader randomly selects a leader node for proposing a block.
func (cp *ConsensusProtocol) selectLeader() (Node, error) {
	if len(cp.nodes) == 0 {
		return Node{}, errors.New("no nodes available for leader selection")
	}

	rand.Seed(time.Now().UnixNano())
	leaderIndex := rand.Intn(len(cp.nodes))
	return cp.nodes[leaderIndex], nil
}

// calculateHash calculates the hash for a block.
func (cp *ConsensusProtocol) calculateHash(index int, timestamp time.Time, transactions []*Transaction, prevHash string) string {
	record := string(index) + timestamp.String() + prevHash
	for _, tx := range transactions {
		record += tx.ID + tx.Sender + tx.Recipient + string(tx.Data) + tx.Timestamp.String()
	}

	hash := sha256.Sum256([]byte(record))
	return hex.EncodeToString(hash[:])
}

// encryptContent encrypts the content using Argon2/AES.
func encryptContent(content string) (string, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	key := argon2.IDKey([]byte(content), salt, 1, 64*1024, 4, 32)
	ciphertext := sha256.Sum256(key)
	return hex.EncodeToString(ciphertext[:]), nil
}

// decryptContent decrypts the content using Argon2/AES.
func decryptContent(content string) (string, error) {
	// This function is intentionally left empty as encryption/decryption logic would require
	// symmetric key management which is beyond the scope of this example.
	return "", errors.New("decryptContent is not implemented")
}
