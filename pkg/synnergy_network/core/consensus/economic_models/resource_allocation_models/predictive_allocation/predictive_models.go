package predictive_allocation

import (
	"fmt"
	"math"
	"math/big"
	"sync"
	"time"

	"github.com/synthron_blockchain_final/pkg/layer0/core/smart_contract"
	"github.com/synthron_blockchain_final/pkg/layer0/core/transaction"
)

// Predictor interface defines the methods for predictive resource allocation
type Predictor interface {
	Predict(transaction.Transaction) *big.Int
	Update(transaction.Transaction)
}

// SimpleMovingAveragePredictor implements a simple moving average for prediction
type SimpleMovingAveragePredictor struct {
	sync.Mutex
	windowSize int
	values     []int64
}

// NewSimpleMovingAveragePredictor creates a new instance of SimpleMovingAveragePredictor
func NewSimpleMovingAveragePredictor(windowSize int) *SimpleMovingAveragePredictor {
	return &SimpleMovingAveragePredictor{
		windowSize: windowSize,
		values:     make([]int64, 0, windowSize),
	}
}

// Predict predicts the future resource requirement based on past data
func (sma *SimpleMovingAveragePredictor) Predict(tx transaction.Transaction) *big.Int {
	sma.Lock()
	defer sma.Unlock()

	if len(sma.values) == 0 {
		return big.NewInt(0)
	}

	sum := int64(0)
	for _, value := range sma.values {
		sum += value
	}

	average := sum / int64(len(sma.values))
	return big.NewInt(average)
}

// Update updates the predictor with new transaction data
func (sma *SimpleMovingAveragePredictor) Update(tx transaction.Transaction) {
	sma.Lock()
	defer sma.Unlock()

	if len(sma.values) >= sma.windowSize {
		sma.values = sma.values[1:]
	}

	sma.values = append(sma.values, tx.GasLimit.Int64())
}

// ResourceAllocator manages resource allocation based on predictions
type ResourceAllocator struct {
	sync.Mutex
	predictor Predictor
	allocated map[string]*big.Int
}

// NewResourceAllocator creates a new instance of ResourceAllocator
func NewResourceAllocator(predictor Predictor) *ResourceAllocator {
	return &ResourceAllocator{
		predictor: predictor,
		allocated: make(map[string]*big.Int),
	}
}

// AllocateResources allocates resources to a transaction based on predictions
func (ra *ResourceAllocator) AllocateResources(tx transaction.Transaction) (*big.Int, error) {
	ra.Lock()
	defer ra.Unlock()

	prediction := ra.predictor.Predict(tx)
	if prediction.Cmp(big.NewInt(0)) == 0 {
		return nil, fmt.Errorf("failed to predict resources for transaction %s", tx.ID)
	}

	ra.allocated[tx.ID] = prediction
	return prediction, nil
}

// UpdatePredictor updates the predictor with new transaction data
func (ra *ResourceAllocator) UpdatePredictor(tx transaction.Transaction) {
	ra.Lock()
	defer ra.Unlock()

	ra.predictor.Update(tx)
}

// GetAllocatedResources returns the allocated resources for a transaction
func (ra *ResourceAllocator) GetAllocatedResources(txID string) (*big.Int, error) {
	ra.Lock()
	defer ra.Unlock()

	allocated, exists := ra.allocated[txID]
	if !exists {
		return nil, fmt.Errorf("no resources allocated for transaction %s", txID)
	}

	return allocated, nil
}

// Example usage
func main() {
	predictor := NewSimpleMovingAveragePredictor(10)
	allocator := NewResourceAllocator(predictor)

	tx1 := transaction.Transaction{ID: "tx1", GasLimit: big.NewInt(100)}
	tx2 := transaction.Transaction{ID: "tx2", GasLimit: big.NewInt(200)}

	allocator.UpdatePredictor(tx1)
	allocator.UpdatePredictor(tx2)

	allocated, err := allocator.AllocateResources(tx1)
	if err != nil {
		fmt.Println("Error allocating resources:", err)
		return
	}

	fmt.Printf("Allocated resources for tx1: %s\n", allocated.String())
}
