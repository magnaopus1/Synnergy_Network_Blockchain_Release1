package proof_of_work_challenge

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"sync"
	"time"
)

// PoWChallenge represents a Proof of Work challenge for node registration.
type PoWChallenge struct {
	Challenge string
	Target    *big.Int
	Difficulty int
}

// NewPoWChallenge generates a new Proof of Work challenge with a given difficulty.
func NewPoWChallenge(difficulty int) (*PoWChallenge, error) {
	if difficulty <= 0 {
		return nil, errors.New("difficulty must be a positive integer")
	}

	challenge, err := generateRandomChallenge()
	if err != nil {
		return nil, err
	}

	target := calculateTarget(difficulty)

	return &PoWChallenge{
		Challenge:  challenge,
		Target:     target,
		Difficulty: difficulty,
	}, nil
}

// generateRandomChallenge generates a random challenge string.
func generateRandomChallenge() (string, error) {
	rand.Seed(time.Now().UnixNano())
	challengeBytes := make([]byte, 32)
	_, err := rand.Read(challengeBytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(challengeBytes), nil
}

// calculateTarget calculates the target value based on the difficulty.
func calculateTarget(difficulty int) *big.Int {
	target := big.NewInt(1)
	target.Lsh(target, uint(256-difficulty))
	return target
}

// Solve attempts to solve the Proof of Work challenge.
func (p *PoWChallenge) Solve() (string, error) {
	var nonce int64
	var hash [32]byte

	for {
		nonceBytes := []byte(fmt.Sprintf("%s:%d", p.Challenge, nonce))
		hash = sha256.Sum256(nonceBytes)
		hashInt := new(big.Int).SetBytes(hash[:])

		if hashInt.Cmp(p.Target) == -1 {
			return hex.EncodeToString(nonceBytes), nil
		}
		nonce++
	}
}

// Verify verifies if the provided solution is valid for the challenge.
func (p *PoWChallenge) Verify(solution string) bool {
	hash := sha256.Sum256([]byte(solution))
	hashInt := new(big.Int).SetBytes(hash[:])
	return hashInt.Cmp(p.Target) == -1
}

// PoWManager manages Proof of Work challenges for multiple nodes.
type PoWManager struct {
	mu          sync.Mutex
	activeNodes map[string]*PoWChallenge
}

// NewPoWManager creates a new PoWManager.
func NewPoWManager() *PoWManager {
	return &PoWManager{
		activeNodes: make(map[string]*PoWChallenge),
	}
}

// CreateChallenge creates a new challenge for a node.
func (m *PoWManager) CreateChallenge(nodeID string, difficulty int) (*PoWChallenge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	challenge, err := NewPoWChallenge(difficulty)
	if err != nil {
		return nil, err
	}

	m.activeNodes[nodeID] = challenge
	return challenge, nil
}

// VerifySolution verifies a solution for a given node's challenge.
func (m *PoWManager) VerifySolution(nodeID, solution string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	challenge, exists := m.activeNodes[nodeID]
	if !exists {
		return false
	}

	if challenge.Verify(solution) {
		delete(m.activeNodes, nodeID)
		return true
	}

	return false
}

// Example usage
func main() {
	manager := NewPoWManager()
	nodeID := "node123"
	difficulty := 20

	// Create a new challenge for the node
	challenge, err := manager.CreateChallenge(nodeID, difficulty)
	if err != nil {
		panic(err)
	}

	// Solve the challenge
	solution, err := challenge.Solve()
	if err != nil {
		panic(err)
	}

	// Verify the solution
	valid := manager.VerifySolution(nodeID, solution)
	if valid {
		fmt.Println("Node successfully solved the challenge and registered!")
	} else {
		fmt.Println("Failed to solve the challenge.")
	}
}
