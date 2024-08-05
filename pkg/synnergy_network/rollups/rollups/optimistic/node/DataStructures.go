package node

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// Transaction represents a transaction in the rollup network.
type Transaction struct {
	ID        string
	Sender    string
	Recipient string
	Data      []byte
	Timestamp time.Time
	Signature string
}

// Block represents a block in the blockchain.
type Block struct {
	Index        int
	Timestamp    time.Time
	Transactions []*Transaction
	PrevHash     string
	Hash         string
}

// Node represents a node in the rollup network.
type Node struct {
	ID        string
	Address   string
	PublicKey string
}

// MerkleTree represents a Merkle tree used for transaction verification.
type MerkleTree struct {
	Root       *MerkleNode
	LeafHashes []string
}

// MerkleNode represents a node in the Merkle tree.
type MerkleNode struct {
	Left  *MerkleNode
	Right *MerkleNode
	Data  string
}

// NewTransaction creates a new transaction.
func NewTransaction(id, sender, recipient string, data []byte, signature string) *Transaction {
	return &Transaction{
		ID:        id,
		Sender:    sender,
		Recipient: recipient,
		Data:      data,
		Timestamp: time.Now(),
		Signature: signature,
	}
}

// NewBlock creates a new block.
func NewBlock(index int, transactions []*Transaction, prevHash string) *Block {
	block := &Block{
		Index:        index,
		Timestamp:    time.Now(),
		Transactions: transactions,
		PrevHash:     prevHash,
		Hash:         calculateHash(index, time.Now(), transactions, prevHash),
	}
	return block
}

// calculateHash calculates the hash for a block.
func calculateHash(index int, timestamp time.Time, transactions []*Transaction, prevHash string) string {
	record := string(index) + timestamp.String() + prevHash
	for _, tx := range transactions {
		record += tx.ID + tx.Sender + tx.Recipient + string(tx.Data) + tx.Timestamp.String()
	}

	hash := sha256.Sum256([]byte(record))
	return hex.EncodeToString(hash[:])
}

// NewMerkleTree creates a new Merkle tree from a list of transaction hashes.
func NewMerkleTree(transactionHashes []string) *MerkleTree {
	if len(transactionHashes) == 0 {
		return nil
	}

	nodes := make([]*MerkleNode, len(transactionHashes))
	for i, hash := range transactionHashes {
		nodes[i] = &MerkleNode{Data: hash}
	}

	for len(nodes) > 1 {
		var newLevel []*MerkleNode
		for i := 0; i < len(nodes); i += 2 {
			if i+1 < len(nodes) {
				newNode := &MerkleNode{
					Left:  nodes[i],
					Right: nodes[i+1],
					Data:  hash(nodes[i].Data + nodes[i+1].Data),
				}
				newLevel = append(newLevel, newNode)
			} else {
				newLevel = append(newLevel, nodes[i])
			}
		}
		nodes = newLevel
	}

	return &MerkleTree{Root: nodes[0], LeafHashes: transactionHashes}
}

// hash calculates the SHA-256 hash of the input string.
func hash(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// VerifyMerkleProof verifies a Merkle proof for a given transaction hash.
func (mt *MerkleTree) VerifyMerkleProof(txHash string, proof []string, index int) bool {
	if mt == nil || mt.Root == nil {
		return false
	}

	computedHash := txHash
	for _, siblingHash := range proof {
		if index%2 == 0 {
			computedHash = hash(computedHash + siblingHash)
		} else {
			computedHash = hash(siblingHash + computedHash)
		}
		index /= 2
	}

	return computedHash == mt.Root.Data
}

// EncryptTransaction encrypts transaction data using Argon2/AES.
func EncryptTransaction(tx *Transaction, key string) (string, error) {
	// Encryption logic using Argon2 and AES goes here
	return "", nil
}

// DecryptTransaction decrypts transaction data using Argon2/AES.
func DecryptTransaction(encryptedData, key string) (*Transaction, error) {
	// Decryption logic using Argon2 and AES goes here
	return nil, nil
}
