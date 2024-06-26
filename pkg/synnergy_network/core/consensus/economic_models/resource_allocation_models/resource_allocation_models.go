package resource_allocation_models

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/synthron_blockchain_final/pkg/layer0/core/smart_contract"
	"github.com/synthron_blockchain_final/pkg/layer0/core/transaction"
	"github.com/synthron_blockchain_final/pkg/layer0/economic_models/resource_allocation_models/auction_systems"
	"github.com/synthron_blockchain_final/pkg/layer0/economic_models/resource_allocation_models/predictive_allocation"
	"golang.org/x/crypto/scrypt"
)

// ResourceAllocatorInterface defines the methods for resource allocation
type ResourceAllocatorInterface interface {
	AllocateResources(tx transaction.Transaction) (*big.Int, error)
	UpdatePredictor(tx transaction.Transaction)
	GetAllocatedResources(txID string) (*big.Int, error)
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
	predictor *HistoricalDataPredictor
	allocated map[string]*big.Int
}

// NewResourceAllocator creates a new instance of ResourceAllocator
func NewResourceAllocator(predictor *HistoricalDataPredictor) *ResourceAllocator {
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

// AuctionMechanism defines the methods for resource auction systems
type AuctionMechanism struct {
	sync.Mutex
	auctions map[string]*auction_systems.Auction
}

// NewAuctionMechanism creates a new instance of AuctionMechanism
func NewAuctionMechanism() *AuctionMechanism {
	return &AuctionMechanism{
		auctions: make(map[string]*auction_systems.Auction),
	}
}

// CreateAuction creates a new auction for resources
func (am *AuctionMechanism) CreateAuction(resourceID string, startingBid *big.Int, duration time.Duration) {
	am.Lock()
	defer am.Unlock()

	auction := auction_systems.NewAuction(resourceID, startingBid, duration)
	am.auctions[resourceID] = auction
}

// PlaceBid places a bid on an auction
func (am *AuctionMechanism) PlaceBid(resourceID string, bidder string, amount *big.Int) error {
	am.Lock()
	defer am.Unlock()

	auction, exists := am.auctions[resourceID]
	if !exists {
		return fmt.Errorf("no auction found for resource %s", resourceID)
	}

	return auction.PlaceBid(bidder, amount)
}

// FinalizeAuction finalizes an auction and allocates the resource
func (am *AuctionMechanism) FinalizeAuction(resourceID string) (*auction_systems.Bid, error) {
	am.Lock()
	defer am.Unlock()

	auction, exists := am.auctions[resourceID]
	if !exists {
		return nil, fmt.Errorf("no auction found for resource %s", resourceID)
	}

	return auction.Finalize()
}

// PredictiveResourceAllocator manages resource allocation based on predictive models
type PredictiveResourceAllocator struct {
	sync.Mutex
	predictor *predictive_allocation.ResourceForecasting
	allocated map[string]*big.Int
}

// NewPredictiveResourceAllocator creates a new instance of PredictiveResourceAllocator
func NewPredictiveResourceAllocator(predictor *predictive_allocation.ResourceForecasting) *PredictiveResourceAllocator {
	return &PredictiveResourceAllocator{
		predictor: predictor,
		allocated: make(map[string]*big.Int),
	}
}

// AllocateResources allocates resources to a transaction based on predictions
func (pra *PredictiveResourceAllocator) AllocateResources(tx transaction.Transaction) (*big.Int, error) {
	pra.Lock()
	defer pra.Unlock()

	prediction, err := pra.predictor.PredictResources(tx)
	if err != nil {
		return nil, err
	}

	pra.allocated[tx.ID] = prediction
	return prediction, nil
}

// UpdatePredictor updates the predictor with new transaction data
func (pra *PredictiveResourceAllocator) UpdatePredictor(tx transaction.Transaction) {
	pra.Lock()
	defer pra.Unlock()

	pra.predictor.Update(tx)
}

// GetAllocatedResources returns the allocated resources for a transaction
func (pra *PredictiveResourceAllocator) GetAllocatedResources(txID string) (*big.Int, error) {
	pra.Lock()
	defer pra.Unlock()

	allocated, exists := pra.allocated[txID]
	if !exists {
		return nil, fmt.Errorf("no resources allocated for transaction %s", txID)
	}

	return allocated, nil
}

// EncryptData encrypts the given data using Scrypt and AES
func EncryptData(data []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return append(salt, ciphertext...), nil
}

// DecryptData decrypts the given data using Scrypt and AES
func DecryptData(data []byte, passphrase string) ([]byte, error) {
	if len(data) < 16 {
		return nil, errors.New("invalid ciphertext")
	}

	salt := data[:16]
	ciphertext := data[16:]

	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("invalid ciphertext")
	}

	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// Example usage
func main() {
	historicalPredictor := NewHistoricalDataPredictor(10)
	allocator := NewResourceAllocator(historicalPredictor)

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

	predictor := predictive_allocation.NewResourceForecasting()
	predictiveAllocator := NewPredictiveResourceAllocator(predictor)

	predictiveAllocated, err := predictiveAllocator.AllocateResources(tx1)
	if err != nil {
		fmt.Println("Error allocating predictive resources:", err)
		return
	}

	fmt.Printf("Predictive allocated resources for tx1: %s\n", predictiveAllocated.String())

	auctionMechanism := NewAuctionMechanism()
	auctionMechanism.CreateAuction("resource1", big.NewInt(1000), time.Hour)
	err = auctionMechanism.PlaceBid("resource1", "bidder1", big.NewInt(1500))
	if err != nil {
		fmt.Println("Error placing bid:", err)
		return
	}

	finalBid, err := auctionMechanism.FinalizeAuction("resource1")
	if err != nil {
		fmt.Println("Error finalizing auction:", err)
		return
	}

	fmt.Printf("Finalized auction for resource1: %s with bid %s\n", finalBid.Bidder, finalBid.Amount.String())
}
