package swap_functionality

import (
	"errors"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/shopspring/decimal"
)

// SwapTransaction represents a swap transaction with necessary details
type SwapTransaction struct {
	TxID       string
	FromToken  string
	ToToken    string
	Amount     decimal.Decimal
	Fee        decimal.Decimal
	Timestamp  time.Time
	User       common.Address
}

// InstantSwapManager manages instant swap transactions
type InstantSwapManager struct {
	SwapPairs map[string]SwapPair
	Transactions map[string]SwapTransaction
	Lock       sync.Mutex
}

// SwapPair represents a pair of tokens available for swap
type SwapPair struct {
	FromToken string
	ToToken   string
	Rate      decimal.Decimal
	ReverseRate decimal.Decimal
}

// NewInstantSwapManager creates a new InstantSwapManager instance
func NewInstantSwapManager() *InstantSwapManager {
	return &InstantSwapManager{
		SwapPairs:    make(map[string]SwapPair),
		Transactions: make(map[string]SwapTransaction),
	}
}

// AddSwapPair adds a new swap pair with the given rate
func (ism *InstantSwapManager) AddSwapPair(fromToken, toToken string, rate, reverseRate decimal.Decimal) {
	ism.Lock.Lock()
	defer ism.Lock.Unlock()

	swapPair := SwapPair{
		FromToken: fromToken,
		ToToken: toToken,
		Rate:     rate,
		ReverseRate: reverseRate,
	}
	ism.SwapPairs[fromToken+"-"+toToken] = swapPair
	ism.SwapPairs[toToken+"-"+fromToken] = SwapPair{
		FromToken: toToken,
		ToToken: fromToken,
		Rate: reverseRate,
		ReverseRate: rate,
	}
}

// RemoveSwapPair removes a swap pair
func (ism *InstantSwapManager) RemoveSwapPair(fromToken, toToken string) {
	ism.Lock.Lock()
	defer ism.Lock.Unlock()

	delete(ism.SwapPairs, fromToken+"-"+toToken)
	delete(ism.SwapPairs, toToken+"-"+fromToken)
}

// ExecuteSwap executes an instant swap between two tokens
func (ism *InstantSwapManager) ExecuteSwap(user common.Address, fromToken, toToken string, amount decimal.Decimal) (SwapTransaction, error) {
	ism.Lock.Lock()
	defer ism.Lock.Unlock()

	swapPair, exists := ism.SwapPairs[fromToken+"-"+toToken]
	if !exists {
		return SwapTransaction{}, errors.New("swap pair not found")
	}

	toAmount := amount.Mul(swapPair.Rate)
	fee := toAmount.Mul(decimal.NewFromFloat(0.01)) // 1% fee
	netAmount := toAmount.Sub(fee)

	txID := generateTransactionID(user, fromToken, toToken, amount)
	tx := SwapTransaction{
		TxID:      txID,
		FromToken: fromToken,
		ToToken:   toToken,
		Amount:    netAmount,
		Fee:       fee,
		Timestamp: time.Now(),
		User:      user,
	}

	ism.Transactions[txID] = tx
	return tx, nil
}

// GetTransaction retrieves a swap transaction by its ID
func (ism *InstantSwapManager) GetTransaction(txID string) (SwapTransaction, error) {
	ism.Lock.Lock()
	defer ism.Lock.Unlock()

	tx, exists := ism.Transactions[txID]
	if !exists {
		return SwapTransaction{}, errors.New("transaction not found")
	}

	return tx, nil
}

// generateTransactionID generates a unique transaction ID
func generateTransactionID(user common.Address, fromToken, toToken string, amount decimal.Decimal) string {
	data := append(user.Bytes(), []byte(fromToken+toToken+amount.String())...)
	hash := crypto.Keccak256Hash(data)
	return hash.Hex()
}

// ListSwapPairs lists all available swap pairs
func (ism *InstantSwapManager) ListSwapPairs() []SwapPair {
	ism.Lock.Lock()
	defer ism.Lock.Unlock()

	swapPairs := []SwapPair{}
	for _, pair := range ism.SwapPairs {
		swapPairs = append(swapPairs, pair)
	}
	return swapPairs
}
