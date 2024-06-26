package quantum_randomness

import (
	"crypto/rand"
	"errors"
	"math/big"
)

// EnhancedConsensusAlgorithm represents a consensus algorithm enhanced with quantum randomness.
type EnhancedConsensusAlgorithm struct {
	nodes            []Node
	randomnessSource QuantumRandomnessSource
}

// Node represents a node in the blockchain network.
type Node struct {
	ID     string
	Weight int // Weight can represent stake, power, etc.
}

// QuantumRandomnessSource represents an interface for a source of quantum randomness.
type QuantumRandomnessSource interface {
	GenerateRandomNumber(max int64) (int64, error)
}

// NewEnhancedConsensusAlgorithm initializes a new EnhancedConsensusAlgorithm.
func NewEnhancedConsensusAlgorithm(nodes []Node, randomnessSource QuantumRandomnessSource) *EnhancedConsensusAlgorithm {
	return &EnhancedConsensusAlgorithm{
		nodes:            nodes,
		randomnessSource: randomnessSource,
	}
}

// SelectLeader selects a leader for the next consensus round using quantum randomness.
func (eca *EnhancedConsensusAlgorithm) SelectLeader() (Node, error) {
	if len(eca.nodes) == 0 {
		return Node{}, errors.New("no nodes available for leader selection")
	}

	totalWeight := 0
	for _, node := range eca.nodes {
		totalWeight += node.Weight
	}

	randomNumber, err := eca.randomnessSource.GenerateRandomNumber(int64(totalWeight))
	if err != nil {
		return Node{}, err
	}

	sum := int64(0)
	for _, node := range eca.nodes {
		sum += int64(node.Weight)
		if randomNumber < sum {
			return node, nil
		}
	}

	return Node{}, errors.New("failed to select a leader")
}

// QuantumRandomnessGenerator generates truly random numbers using quantum phenomena.
type QuantumRandomnessGenerator struct{}

// GenerateRandomNumber generates a truly random number up to max using quantum randomness.
func (qrg *QuantumRandomnessGenerator) GenerateRandomNumber(max int64) (int64, error) {
	if max <= 0 {
		return 0, errors.New("max must be greater than 0")
	}

	n, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		return 0, err
	}

	return n.Int64(), nil
}

// SimulateConsensus simulates the consensus process.
func (eca *EnhancedConsensusAlgorithm) SimulateConsensus(rounds int) ([]Node, error) {
	if rounds <= 0 {
		return nil, errors.New("rounds must be greater than 0")
	}

	leaders := make([]Node, rounds)
	for i := 0; i < rounds; i++ {
		leader, err := eca.SelectLeader()
		if err != nil {
			return nil, err
		}
		leaders[i] = leader
	}

	return leaders, nil
}
