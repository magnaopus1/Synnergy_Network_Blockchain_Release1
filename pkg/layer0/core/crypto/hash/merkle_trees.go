package hash

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// MerkleNode represents a node in the Merkle tree.
type MerkleNode struct {
	Left  *MerkleNode
	Right *MerkleNode
	Data  []byte
}

// MerkleTree represents the entire Merkle tree.
type MerkleTree struct {
	Root *MerkleNode
}

// NewMerkleNode creates a new Merkle node.
func NewMerkleNode(left, right *MerkleNode, data []byte) *MerkleNode {
	mNode := MerkleNode{}

	if left == nil && right == nil {
		hash := sha256.Sum256(data)
		mNode.Data = hash[:]
	} else {
		prevHashes := append(left.Data, right.Data...)
		hash := sha256.Sum256(prevHashes)
		mNode.Data = hash[:]
	}
	mNode.Left = left
	mNode.Right = right

	return &mNode
}

// NewMerkleTree creates a new Merkle tree from a slice of data.
func NewMerkleTree(data [][]byte) (*MerkleTree, error) {
	if len(data) == 0 {
		return nil, errors.New("no data provided for Merkle tree")
	}

	var nodes []*MerkleNode

	for _, datum := range data {
		node := NewMerkleNode(nil, nil, datum)
		nodes = append(nodes, node)
	}

	for len(nodes) > 1 {
		var newLevel []*MerkleNode

		for i := 0; i < len(nodes); i += 2 {
			if i+1 < len(nodes) {
				node := NewMerkleNode(nodes[i], nodes[i+1], nil)
				newLevel = append(newLevel, node)
			} else {
				newLevel = append(newLevel, nodes[i])
			}
		}

		nodes = newLevel
	}

	mTree := MerkleTree{Root: nodes[0]}
	return &mTree, nil
}

// Example usage
func main() {
	data := [][]byte{
		[]byte("transaction1"),
		[]byte("transaction2"),
		[]byte("transaction3"),
		[]byte("transaction4"),
	}

	tree, err := NewMerkleTree(data)
	if err != nil {
		fmt.Println("Error creating Merkle Tree:", err)
		return
	}

	fmt.Println("Merkle Tree root hash:", hex.EncodeToString(tree.Root.Data))
}

// This Merkle tree implementation is crucial for ensuring data integrity within the blockchain. It uses SHA-256 hashing, supported in Golang through the crypto/sha256 package, to create a secure, efficient structure that enables quick and reliable data verification across the network.
