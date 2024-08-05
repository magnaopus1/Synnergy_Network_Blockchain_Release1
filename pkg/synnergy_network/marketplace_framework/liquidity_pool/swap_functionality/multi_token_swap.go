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

// MultiTokenSwapTransaction represents a multi-token swap transaction
type MultiTokenSwapTransaction struct {
	TxID          string
	FromTokens    []string
	ToTokens      []string
	Amounts       []decimal.Decimal
	TotalFee      decimal.Decimal
	Timestamp     time.Time
	User          common.Address
}

// MultiTokenSwapManager manages multi-token swap transactions
type MultiTokenSwapManager struct {
	SwapPairs    map[string]SwapPair
	Transactions map[string]MultiTokenSwapTransaction
	Lock         sync.Mutex
}

// SwapPair represents a pair of tokens available for swap
type SwapPair struct {
	FromToken  string
	ToToken    string
	Rate       decimal.Decimal
	ReverseRate decimal.Decimal
}

// NewMultiTokenSwapManager creates a new MultiTokenSwapManager instance
func NewMultiTokenSwapManager() *MultiTokenSwapManager {
	return &MultiTokenSwapManager{
		SwapPairs:    make(map[string]SwapPair),
		Transactions: make(map[string]MultiTokenSwapTransaction),
	}
}

// AddSwapPair adds a new swap pair with the given rate
func (mtsm *MultiTokenSwapManager) AddSwapPair(fromToken, toToken string, rate, reverseRate decimal.Decimal) {
	mtsm.Lock.Lock()
	defer mtsm.Lock.Unlock()

	swapPair := SwapPair{
		FromToken: fromToken,
		ToToken:   toToken,
		Rate:      rate,
		ReverseRate: reverseRate,
	}
	mtsm.SwapPairs[fromToken+"-"+toToken] = swapPair
	mtsm.SwapPairs[toToken+"-"+fromToken] = SwapPair{
		FromToken: toToken,
		ToToken: fromToken,
		Rate: reverseRate,
		ReverseRate: rate,
	}
}

// RemoveSwapPair removes a swap pair
func (mtsm *MultiTokenSwapManager) RemoveSwapPair(fromToken, toToken string) {
	mtsm.Lock.Lock()
	defer mtsm.Lock.Unlock()

	delete(mtsm.SwapPairs, fromToken+"-"+toToken)
	delete(mtsm.SwapPairs, toToken+"-"+fromToken)
}

// ExecuteMultiTokenSwap executes a multi-token swap
func (mtsm *MultiTokenSwapManager) ExecuteMultiTokenSwap(user common.Address, fromTokens, toTokens []string, amounts []decimal.Decimal) (MultiTokenSwapTransaction, error) {
	mtsm.Lock.Lock()
	defer mtsm.Lock.Unlock()

	if len(fromTokens) != len(toTokens) || len(fromTokens) != len(amounts) {
		return MultiTokenSwapTransaction{}, errors.New("mismatched input lengths")
	}

	var totalFee decimal.Decimal
	for i := range fromTokens {
		swapPair, exists := mtsm.SwapPairs[fromTokens[i]+"-"+toTokens[i]]
		if !exists {
			return MultiTokenSwapTransaction{}, errors.New("swap pair not found for token pair: " + fromTokens[i] + " to " + toTokens[i])
		}

		// Calculate the amount to be swapped
		toAmount := amounts[i].Mul(swapPair.Rate)
		fee := toAmount.Mul(decimal.NewFromFloat(0.01)) // 1% fee
		netAmount := toAmount.Sub(fee)

		totalFee = totalFee.Add(fee)
		amounts[i] = netAmount
	}

	txID := generateTransactionID(user, fromTokens, toTokens, amounts)
	tx := MultiTokenSwapTransaction{
		TxID:       txID,
		FromTokens: fromTokens,
		ToTokens:   toTokens,
		Amounts:    amounts,
		TotalFee:   totalFee,
		Timestamp:  time.Now(),
		User:       user,
	}

	mtsm.Transactions[txID] = tx
	return tx, nil
}

// GetTransaction retrieves a multi-token swap transaction by its ID
func (mtsm *MultiTokenSwapManager) GetTransaction(txID string) (MultiTokenSwapTransaction, error) {
	mtsm.Lock.Lock()
	defer mtsm.Lock.Unlock()

	tx, exists := mtsm.Transactions[txID]
	if !exists {
		return MultiTokenSwapTransaction{}, errors.New("transaction not found")
	}

	return tx, nil
}

// generateTransactionID generates a unique transaction ID for multi-token swaps
func generateTransactionID(user common.Address, fromTokens, toTokens []string, amounts []decimal.Decimal) string {
	data := user.Bytes()
	for i := range fromTokens {
		data = append(data, []byte(fromTokens[i]+toTokens[i]+amounts[i].String())...)
	}
	hash := crypto.Keccak256Hash(data)
	return hash.Hex()
}

// ListSwapPairs lists all available swap pairs
func (mtsm *MultiTokenSwapManager) ListSwapPairs() []SwapPair {
	mtsm.Lock.Lock()
	defer mtsm.Lock.Unlock()

	swapPairs := []SwapPair{}
	for _, pair := range mtsm.SwapPairs {
		swapPairs = append(swapPairs, pair)
	}
	return swapPairs
}
