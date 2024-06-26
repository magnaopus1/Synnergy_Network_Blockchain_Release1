package hash_based

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// HashChain structure
type HashChain struct {
	chain []string
	mutex sync.Mutex
}

// NewHashChain creates a new HashChain
func NewHashChain() *HashChain {
	return &HashChain{
		chain: []string{},
	}
}

// AddBlock adds a new block to the hash chain
func (hc *HashChain) AddBlock(data string) (string, error) {
	hc.mutex.Lock()
	defer hc.mutex.Unlock()

	// Get the previous block hash
	prevHash := ""
	if len(hc.chain) > 0 {
		prevHash = hc.chain[len(hc.chain)-1]
	}

	// Generate a new block hash
	newHash, err := hc.generateHash(prevHash, data)
	if err != nil {
		return "", err
	}

	// Add the new block hash to the chain
	hc.chain = append(hc.chain, newHash)
	return newHash, nil
}

// generateHash creates a new hash from the previous hash and the new data
func (hc *HashChain) generateHash(prevHash, data string) (string, error) {
	hash := sha256.New()
	_, err := hash.Write([]byte(prevHash + data))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// VerifyChain verifies the integrity of the hash chain
func (hc *HashChain) VerifyChain() bool {
	hc.mutex.Lock()
	defer hc.mutex.Unlock()

	for i := 1; i < len(hc.chain); i++ {
		prevHash := hc.chain[i-1]
		currHash := hc.chain[i]
		expectedHash, err := hc.generateHash(prevHash, "")
		if err != nil || currHash != expectedHash {
			return false
		}
	}
	return true
}

// GetChain returns the entire hash chain
func (hc *HashChain) GetChain() []string {
	hc.mutex.Lock()
	defer hc.mutex.Unlock()

	return hc.chain
}

// Argon2Hash generates a hash using Argon2
func Argon2Hash(password, salt string) (string, error) {
	saltBytes := []byte(salt)
	hash := argon2.IDKey([]byte(password), saltBytes, 1, 64*1024, 4, 32)
	return hex.EncodeToString(hash), nil
}

// SecureMessage encapsulates a message with hash-based signatures
type SecureMessage struct {
	Message   string
	Timestamp int64
	Hash      string
}

// NewSecureMessage creates a new secure message
func NewSecureMessage(message string) (*SecureMessage, error) {
	timestamp := time.Now().Unix()
	hash, err := Argon2Hash(message, fmt.Sprintf("%d", timestamp))
	if err != nil {
		return nil, err
	}
	return &SecureMessage{
		Message:   message,
		Timestamp: timestamp,
		Hash:      hash,
	}, nil
}

// Validate validates the integrity of the secure message
func (sm *SecureMessage) Validate() bool {
	expectedHash, err := Argon2Hash(sm.Message, fmt.Sprintf("%d", sm.Timestamp))
	if err != nil {
		return false
	}
	return sm.Hash == expectedHash
}

// MerkleNode represents a node in the Merkle Tree
type MerkleNode struct {
	Left  *MerkleNode
	Right *MerkleNode
	Hash  string
}

// MerkleTree represents a Merkle Tree
type MerkleTree struct {
	Root *MerkleNode
}

// NewMerkleTree creates a new Merkle Tree
func NewMerkleTree(data []string) (*MerkleTree, error) {
	if len(data) == 0 {
		return nil, errors.New("data must not be empty")
	}
	var nodes []*MerkleNode
	for _, datum := range data {
		hash := sha256.Sum256([]byte(datum))
		nodes = append(nodes, &MerkleNode{Hash: hex.EncodeToString(hash[:])})
	}

	for len(nodes) > 1 {
		var level []*MerkleNode
		for i := 0; i < len(nodes); i += 2 {
			if i+1 < len(nodes) {
				hash := sha256.Sum256([]byte(nodes[i].Hash + nodes[i+1].Hash))
				level = append(level, &MerkleNode{
					Left:  nodes[i],
					Right: nodes[i+1],
					Hash:  hex.EncodeToString(hash[:]),
				})
			} else {
				level = append(level, nodes[i])
			}
		}
		nodes = level
	}

	return &MerkleTree{Root: nodes[0]}, nil
}

// VerifyData verifies if a piece of data is included in the Merkle Tree
func (mt *MerkleTree) VerifyData(data string, proof []string) bool {
	hash := sha256.Sum256([]byte(data))
	currentHash := hex.EncodeToString(hash[:])

	for _, p := range proof {
		hash := sha256.Sum256([]byte(currentHash + p))
		currentHash = hex.EncodeToString(hash[:])
	}

	return currentHash == mt.Root.Hash
}

// GenerateProof generates a proof of inclusion for a piece of data in the Merkle Tree
func (mt *MerkleTree) GenerateProof(data string) ([]string, error) {
	var proof []string
	hash := sha256.Sum256([]byte(data))
	currentHash := hex.EncodeToString(hash[:])

	var traverse func(*MerkleNode) bool
	traverse = func(node *MerkleNode) bool {
		if node == nil {
			return false
		}
		if node.Hash == currentHash {
			return true
		}
		if traverse(node.Left) {
			proof = append(proof, node.Right.Hash)
			return true
		}
		if traverse(node.Right) {
			proof = append(proof, node.Left.Hash)
			return true
		}
		return false
	}

	if !traverse(mt.Root) {
		return nil, errors.New("data not found in Merkle Tree")
	}

	return proof, nil
}
