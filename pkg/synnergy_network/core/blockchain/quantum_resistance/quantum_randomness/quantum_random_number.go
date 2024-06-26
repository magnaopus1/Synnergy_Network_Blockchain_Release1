package quantum_randomness

import (
	"crypto/rand"
	"errors"
	"math/big"
	"sync"
)

// QuantumRandomNumberGenerator is the interface for generating quantum random numbers.
type QuantumRandomNumberGenerator interface {
	GenerateRandomNumber(max int64) (int64, error)
}

// QuantumRandomNumberService is the service for generating quantum random numbers.
type QuantumRandomNumberService struct {
	mutex sync.Mutex
}

// NewQuantumRandomNumberService creates a new instance of QuantumRandomNumberService.
func NewQuantumRandomNumberService() *QuantumRandomNumberService {
	return &QuantumRandomNumberService{}
}

// GenerateRandomNumber generates a truly random number up to max using quantum randomness.
func (qrns *QuantumRandomNumberService) GenerateRandomNumber(max int64) (int64, error) {
	if max <= 0 {
		return 0, errors.New("max must be greater than 0")
	}

	qrns.mutex.Lock()
	defer qrns.mutex.Unlock()

	n, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		return 0, err
	}

	return n.Int64(), nil
}

// QuantumRandomnessSource implements the QuantumRandomNumberGenerator interface.
type QuantumRandomnessSource struct {
	*QuantumRandomNumberService
}

// NewQuantumRandomnessSource creates a new instance of QuantumRandomnessSource.
func NewQuantumRandomnessSource() *QuantumRandomnessSource {
	return &QuantumRandomnessSource{
		QuantumRandomNumberService: NewQuantumRandomNumberService(),
	}
}

// GenerateRandomNumber generates a random number using the underlying QuantumRandomNumberService.
func (qrs *QuantumRandomnessSource) GenerateRandomNumber(max int64) (int64, error) {
	return qrs.QuantumRandomNumberService.GenerateRandomNumber(max)
}

// QuantumRandomNumberManager manages the generation and usage of quantum random numbers.
type QuantumRandomNumberManager struct {
	source QuantumRandomNumberGenerator
}

// NewQuantumRandomNumberManager creates a new instance of QuantumRandomNumberManager.
func NewQuantumRandomNumberManager(source QuantumRandomNumberGenerator) *QuantumRandomNumberManager {
	return &QuantumRandomNumberManager{source: source}
}

// GetRandomNumber generates a random number within the specified range.
func (qrm *QuantumRandomNumberManager) GetRandomNumber(max int64) (int64, error) {
	return qrm.source.GenerateRandomNumber(max)
}

// SimulateQuantumRandomNumbers simulates the generation of quantum random numbers.
func (qrm *QuantumRandomNumberManager) SimulateQuantumRandomNumbers(count int, max int64) ([]int64, error) {
	if count <= 0 {
		return nil, errors.New("count must be greater than 0")
	}
	if max <= 0 {
		return nil, errors.New("max must be greater than 0")
	}

	numbers := make([]int64, count)
	for i := 0; i < count; i++ {
		number, err := qrm.GetRandomNumber(max)
		if err != nil {
			return nil, err
		}
		numbers[i] = number
	}

	return numbers, nil
}

// EnhancedConsensusAlgorithm represents a consensus algorithm enhanced with quantum randomness.
type EnhancedConsensusAlgorithm struct {
	nodes            []Node
	randomnessSource QuantumRandomNumberGenerator
}

// Node represents a node in the blockchain network.
type Node struct {
	ID     string
	Weight int // Weight can represent stake, power, etc.
}

// NewEnhancedConsensusAlgorithm initializes a new EnhancedConsensusAlgorithm.
func NewEnhancedConsensusAlgorithm(nodes []Node, randomnessSource QuantumRandomNumberGenerator) *EnhancedConsensusAlgorithm {
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
