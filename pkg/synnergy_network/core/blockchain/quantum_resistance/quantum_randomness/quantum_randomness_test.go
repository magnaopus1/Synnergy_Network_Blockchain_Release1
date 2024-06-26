package quantum_randomness

import (
	"testing"
)

// TestQuantumRandomNumberService tests the QuantumRandomNumberService for generating random numbers.
func TestQuantumRandomNumberService(t *testing.T) {
	qrns := NewQuantumRandomNumberService()

	max := int64(100)
	randomNumber, err := qrns.GenerateRandomNumber(max)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if randomNumber < 0 || randomNumber >= max {
		t.Fatalf("expected random number in range [0, %d), got %d", max, randomNumber)
	}
}

// TestQuantumRandomNumberService_InvalidMax tests the QuantumRandomNumberService for invalid max values.
func TestQuantumRandomNumberService_InvalidMax(t *testing.T) {
	qrns := NewQuantumRandomNumberService()

	_, err := qrns.GenerateRandomNumber(0)
	if err == nil {
		t.Fatal("expected error for max = 0, got none")
	}

	_, err = qrns.GenerateRandomNumber(-1)
	if err == nil {
		t.Fatal("expected error for max < 0, got none")
	}
}

// TestQuantumRandomNumberManager tests the QuantumRandomNumberManager for generating random numbers.
func TestQuantumRandomNumberManager(t *testing.T) {
	qrns := NewQuantumRandomNumberService()
	qrnm := NewQuantumRandomNumberManager(qrns)

	max := int64(100)
	randomNumber, err := qrnm.GetRandomNumber(max)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if randomNumber < 0 || randomNumber >= max {
		t.Fatalf("expected random number in range [0, %d), got %d", max, randomNumber)
	}
}

// TestQuantumRandomNumberManager_SimulateQuantumRandomNumbers tests simulation of quantum random numbers.
func TestQuantumRandomNumberManager_SimulateQuantumRandomNumbers(t *testing.T) {
	qrns := NewQuantumRandomNumberService()
	qrnm := NewQuantumRandomNumberManager(qrns)

	count := 10
	max := int64(100)
	numbers, err := qrnm.SimulateQuantumRandomNumbers(count, max)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(numbers) != count {
		t.Fatalf("expected %d numbers, got %d", count, len(numbers))
	}

	for _, num := range numbers {
		if num < 0 || num >= max {
			t.Fatalf("expected number in range [0, %d), got %d", max, num)
		}
	}
}

// TestEnhancedConsensusAlgorithm tests the EnhancedConsensusAlgorithm for leader selection.
func TestEnhancedConsensusAlgorithm(t *testing.T) {
	nodes := []Node{
		{ID: "node1", Weight: 1},
		{ID: "node2", Weight: 2},
		{ID: "node3", Weight: 3},
	}

	qrns := NewQuantumRandomNumberService()
	eca := NewEnhancedConsensusAlgorithm(nodes, qrns)

	leader, err := eca.SelectLeader()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	found := false
	for _, node := range nodes {
		if node.ID == leader.ID {
			found = true
			break
		}
	}

	if !found {
		t.Fatalf("expected leader to be one of the nodes, got %v", leader.ID)
	}
}

// TestEnhancedConsensusAlgorithm_SimulateConsensus tests the simulation of consensus process.
func TestEnhancedConsensusAlgorithm_SimulateConsensus(t *testing.T) {
	nodes := []Node{
		{ID: "node1", Weight: 1},
		{ID: "node2", Weight: 2},
		{ID: "node3", Weight: 3},
	}

	qrns := NewQuantumRandomNumberService()
	eca := NewEnhancedConsensusAlgorithm(nodes, qrns)

	rounds := 10
	leaders, err := eca.SimulateConsensus(rounds)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(leaders) != rounds {
		t.Fatalf("expected %d leaders, got %d", rounds, len(leaders))
	}

	for _, leader := range leaders {
		found := false
		for _, node := range nodes {
			if node.ID == leader.ID {
				found = true
				break
			}
		}

		if !found {
			t.Fatalf("expected leader to be one of the nodes, got %v", leader.ID)
		}
	}
}

