package exchange_protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/crypto"
)

type Order struct {
	ID        string
	Trader    common.Address
	Amount    *big.Int
	Price     *big.Int
	Timestamp time.Time
}

type OrderBook struct {
	buyOrders  []Order
	sellOrders []Order
	mu         sync.Mutex
}

type DecentralizedOrderMatching struct {
	OrderBook       OrderBook
	Client          *rpc.Client
	Auth            *bind.TransactOpts
	ContractAddress common.Address
	PrivateKey      string
}

func NewDecentralizedOrderMatching(contractAddress, privateKey string, client *rpc.Client) (*DecentralizedOrderMatching, error) {
	auth, err := bind.NewTransactorWithChainID(strings.NewReader(privateKey), nil)
	if err != nil {
		return nil, err
	}

	return &DecentralizedOrderMatching{
		OrderBook:       OrderBook{buyOrders: []Order{}, sellOrders: []Order{}},
		Client:          client,
		Auth:            auth,
		ContractAddress: common.HexToAddress(contractAddress),
		PrivateKey:      privateKey,
	}, nil
}

func (dom *DecentralizedOrderMatching) AddOrder(order Order, isBuy bool) {
	dom.OrderBook.mu.Lock()
	defer dom.OrderBook.mu.Unlock()

	if isBuy {
		dom.OrderBook.buyOrders = append(dom.OrderBook.buyOrders, order)
	} else {
		dom.OrderBook.sellOrders = append(dom.OrderBook.sellOrders, order)
	}
}

func (dom *DecentralizedOrderMatching) MatchOrders() {
	dom.OrderBook.mu.Lock()
	defer dom.OrderBook.mu.Unlock()

	for i := 0; i < len(dom.OrderBook.buyOrders); i++ {
		for j := 0; j < len(dom.OrderBook.sellOrders); j++ {
			buyOrder := dom.OrderBook.buyOrders[i]
			sellOrder := dom.OrderBook.sellOrders[j]

			if buyOrder.Price.Cmp(sellOrder.Price) >= 0 && buyOrder.Amount.Cmp(sellOrder.Amount) >= 0 {
				// Match found, process the trade
				fmt.Printf("Match found: Buy Order %s and Sell Order %s\n", buyOrder.ID, sellOrder.ID)
				// Process the trade...
				// Remove matched orders
				dom.OrderBook.buyOrders = append(dom.OrderBook.buyOrders[:i], dom.OrderBook.buyOrders[i+1:]...)
				dom.OrderBook.sellOrders = append(dom.OrderBook.sellOrders[:j], dom.OrderBook.sellOrders[j+1:]...)
				i-- // Adjust index after removing the matched order
				break
			}
		}
	}
}

func (dom *DecentralizedOrderMatching) ValidateOrder(order Order) (bool, error) {
	orderHash := sha256.Sum256([]byte(order.ID))
	fmt.Printf("Validating order with hash: %s\n", hex.EncodeToString(orderHash[:]))

	// Simulate order validation logic
	if len(order.ID) == 0 || order.Amount.Sign() <= 0 || order.Price.Sign() <= 0 {
		return false, errors.New("invalid order")
	}

	return true, nil
}

func (dom *DecentralizedOrderMatching) ExecuteTrade(buyOrder, sellOrder Order) error {
	fmt.Printf("Executing trade: Buy Order %s and Sell Order %s\n", buyOrder.ID, sellOrder.ID)
	// Simulate trade execution logic
	// This would include transferring assets, recording the trade on the blockchain, etc.

	// For demonstration purposes, we'll just print out the trade details
	fmt.Printf("Trade executed: %s bought %d units at %d from %s\n",
		buyOrder.Trader.Hex(), buyOrder.Amount, buyOrder.Price, sellOrder.Trader.Hex())

	return nil
}

func (dom *DecentralizedOrderMatching) EncryptData(data string) (string, error) {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:]), nil
}

func (dom *DecentralizedOrderMatching) DecryptData(encryptedData string) (string, error) {
	data, err := hex.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func (dom *DecentralizedOrderMatching) validateHash(hash string) error {
	if len(hash) == 0 {
		return errors.New("hash cannot be empty")
	}
	return nil
}
