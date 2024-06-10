package predictive_allocation

import (
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/synthron_blockchain_final/pkg/layer0/core/smart_contract"
	"github.com/synthron_blockchain_final/pkg/layer0/core/transaction"
	"golang.org/x/crypto/scrypt"
)

// Predictor interface defines the methods for predictive resource allocation
type Predictor interface {
	Predict(transaction.Transaction) *big.Int
	Update(transaction.Transaction)
}

// HistoricalDataPredictor uses historical data to predict future resource requirements
type HistoricalDataPredictor struct {
	sync.Mutex
	windowSize int
	values     []int64
}

// NewHistoricalDataPredictor creates a new instance of HistoricalDataPredictor
func NewHistoricalDataPredictor(windowSize int) *HistoricalDataPredictor {
	return &HistoricalDataPredictor{
		windowSize: windowSize,
		values:     make([]int64, 0, windowSize),
	}
}

// Predict predicts the future resource requirement based on historical data
func (hdp *HistoricalDataPredictor) Predict(tx transaction.Transaction) *big.Int {
	hdp.Lock()
	defer hdp.Unlock()

	if len(hdp.values) == 0 {
		return big.NewInt(0)
	}

	sum := int64(0)
	for _, value := range hdp.values {
		sum += value
	}

	average := sum / int64(len(hdp.values))
	return big.NewInt(average)
}

// Update updates the predictor with new transaction data
func (hdp *HistoricalDataPredictor) Update(tx transaction.Transaction) {
	hdp.Lock()
	defer hdp.Unlock()

	if len(hdp.values) >= hdp.windowSize {
		hdp.values = hdp.values[1:]
	}

	hdp.values = append(hdp.values, tx.GasLimit.Int64())
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

// EncryptData encrypts the given data using Scrypt and AES
func EncryptData(data []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, 16)
	_, err := time.Now().UnixNano().Read(salt)
	if err != nil {
		return nil, err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	return key, nil // Encryption logic to be added
}

// DecryptData decrypts the given data using Scrypt and AES
func DecryptData(data []byte, passphrase string) ([]byte, error) {
	salt := data[:16]
	encryptedData := data[16:]

	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	return key, nil // Decryption logic to be added
}

// Example usage
func main() {
	predictor := NewHistoricalDataPredictor(10)
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

	passphrase := "securepassword"
	encrypted, err := EncryptData([]byte("Sensitive data"), passphrase)
	if err != nil {
		fmt.Println("Error encrypting data:", err)
		return
	}

	decrypted, err := DecryptData(encrypted, passphrase)
	if err != nil {
		fmt.Println("Error decrypting data:", err)
		return
	}

	fmt.Printf("Decrypted data: %s\n", decrypted)
}
