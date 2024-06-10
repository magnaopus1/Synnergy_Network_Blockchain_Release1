package quantum_resistance

import (
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"errors"

	"github.com/codenotary/merkletree"
	"golang.org/x/crypto/sha3"
)

// HashBasedSignature represents a structure for hash-based signatures using Merkle trees.
type HashBasedSignature struct {
	Tree *merkletree.Tree
	KeyPairs [][]byte
	LeafHashes [][]byte
	Root []byte
	UsedLeaves map[string]bool
}

// NewHashBasedSignature initializes a new instance of HashBasedSignature.
func NewHashBasedSignature(keyCount int) (*HashBasedSignature, error) {
	if keyCount <= 0 {
		return nil, errors.New("key count must be positive")
	}

	// Initialize the Merkle tree
	tree := merkletree.New(sha3.New256())

	// Generate key pairs and corresponding leaf nodes
	keyPairs := make([][]byte, keyCount)
	leafHashes := make([][]byte, keyCount)
	for i := 0; i < keyCount; i++ {
		key := make([]byte, 32) // Assuming 256-bit keys
		_, err := rand.Read(key)
		if err != nil {
			return nil, err
		}
		keyPairs[i] = key
		hash := sha3.Sum256(key)
		tree.Add(hash[:])
		leafHashes[i] = hash[:]
	}

	return &HashBasedSignature{
		Tree: tree,
		KeyPairs: keyPairs,
		LeafHashes: leafHashes,
		Root: tree.MerkleRoot(),
		UsedLeaves: make(map[string]bool),
	}, nil
}

// Sign generates a signature using an unused leaf from the Merkle tree.
func (hbs *HashBasedSignature) Sign(data []byte) (signature []byte, proof [][]byte, index int, err error) {
	for i, hash := range hbs.LeafHashes {
		if !hbs.UsedLeaves[hex.EncodeToString(hash)] {
			// Mark the leaf as used
			hbs.UsedLeaves[hex.EncodeToString(hash)] = true
			// Calculate the hash of the data to sign
			dataHash := sha3.Sum256(data)
			// Append the leaf index hash
			signedHash := sha3.Sum256(append(dataHash[:], hash...))
			// Generate the proof
			proof, err := hbs.Tree.GenerateProof(hash)
			if err != nil {
				return nil, nil, 0, err
			}
			return signedHash[:], proof, i, nil
		}
	}
	return nil, nil, -1, errors.New("no unused leaves available for signing")
}

// Verify checks if the data signature is valid using the provided proof and Merkle root.
func (hbs *HashBasedSignature) Verify(data []byte, signature []byte, proof [][]byte, index int) bool {
	dataHash := sha3.Sum256(data)
	signedHash := sha3.Sum256(append(dataHash[:], hbs.LeafHashes[index]...))
	return hbs.Tree.VerifyProof(proof, signedHash[:], hbs.Root)
}
