package hash_based

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"sync"

	"golang.org/x/crypto/argon2"
)

// MerkleNode represents a node in the Merkle tree
type MerkleNode struct {
	Left  *MerkleNode
	Right *MerkleNode
	Hash  string
}

// MerkleTree represents a Merkle tree
type MerkleTree struct {
	Root *MerkleNode
}

// NewMerkleTree creates a new Merkle tree from the provided data
func NewMerkleTree(data [][]byte) (*MerkleTree, error) {
	if len(data) == 0 {
		return nil, errors.New("data must not be empty")
	}

	var nodes []*MerkleNode
	for _, datum := range data {
		hash := sha256.Sum256(datum)
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

// MerkleSignatureScheme represents the Merkle signature scheme
type MerkleSignatureScheme struct {
	tree          *MerkleTree
	secretKeys    [][]byte
	publicKey     string
	mutex         sync.Mutex
	usedLeafNodes map[int]bool
}

// NewMerkleSignatureScheme creates a new Merkle Signature Scheme
func NewMerkleSignatureScheme(secretKeys [][]byte) (*MerkleSignatureScheme, error) {
	tree, err := NewMerkleTree(secretKeys)
	if err != nil {
		return nil, err
	}

	return &MerkleSignatureScheme{
		tree:          tree,
		secretKeys:    secretKeys,
		publicKey:     tree.Root.Hash,
		usedLeafNodes: make(map[int]bool),
	}, nil
}

// GetPublicKey returns the public key of the Merkle Signature Scheme
func (mss *MerkleSignatureScheme) GetPublicKey() string {
	return mss.publicKey
}

// Sign signs the given message using an available leaf node
func (mss *MerkleSignatureScheme) Sign(message []byte) (string, []string, error) {
	mss.mutex.Lock()
	defer mss.mutex.Unlock()

	leafIndex, err := mss.getAvailableLeafIndex()
	if err != nil {
		return "", nil, err
	}

	secretKey := mss.secretKeys[leafIndex]
	signature, err := argon2Key(message, secretKey)
	if err != nil {
		return "", nil, err
	}

	proof, err := mss.tree.generateProof(secretKey)
	if err != nil {
		return "", nil, err
	}

	mss.usedLeafNodes[leafIndex] = true
	return signature, proof, nil
}

// Verify verifies the signature of the given message
func (mss *MerkleSignatureScheme) Verify(message []byte, signature string, proof []string) bool {
	for i, sk := range mss.secretKeys {
		calculatedSignature, err := argon2Key(message, sk)
		if err != nil || calculatedSignature != signature {
			continue
		}

		return mss.tree.verifyProof(sk, proof)
	}
	return false
}

// getAvailableLeafIndex finds the next available leaf index for signing
func (mss *MerkleSignatureScheme) getAvailableLeafIndex() (int, error) {
	for i := range mss.secretKeys {
		if !mss.usedLeafNodes[i] {
			return i, nil
		}
	}
	return 0, errors.New("no available leaf nodes")
}

// argon2Key generates an Argon2 key from the message and secret key
func argon2Key(message, secretKey []byte) (string, error) {
	salt := sha256.Sum256(secretKey)
	key := argon2.IDKey(message, salt[:], 1, 64*1024, 4, 32)
	return hex.EncodeToString(key), nil
}

// generateProof generates a proof of inclusion for the given leaf node
func (mt *MerkleTree) generateProof(data []byte) ([]string, error) {
	var proof []string
	hash := sha256.Sum256(data)
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

// verifyProof verifies if the given data and proof lead to the root hash
func (mt *MerkleTree) verifyProof(data []byte, proof []string) bool {
	hash := sha256.Sum256(data)
	currentHash := hex.EncodeToString(hash[:])

	for _, p := range proof {
		hash := sha256.Sum256([]byte(currentHash + p))
		currentHash = hex.EncodeToString(hash[:])
	}

	return currentHash == mt.Root.Hash
}

// Argon2Hash generates a hash using Argon2
func Argon2Hash(password, salt string) (string, error) {
	saltBytes := []byte(salt)
	hash := argon2.IDKey([]byte(password), saltBytes, 1, 64*1024, 4, 32)
	return hex.EncodeToString(hash), nil
}

// Example of how to generate a set of secret keys
func generateSecretKeys(n int) ([][]byte, error) {
	var secretKeys [][]byte
	for i := 0; i < n; i++ {
		secretKey, err := generateRandomBytes(32)
		if err != nil {
			return nil, err
		}
		secretKeys = append(secretKeys, secretKey)
	}
	return secretKeys, nil
}

// generateRandomBytes generates a slice of random bytes of the given length
func generateRandomBytes(length int) ([]byte, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}
