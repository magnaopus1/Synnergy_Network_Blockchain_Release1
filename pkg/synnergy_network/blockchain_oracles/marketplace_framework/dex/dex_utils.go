package dex

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

// OrderType represents the type of an order
type OrderType int

const (
	MarketOrder OrderType = iota
	LimitOrder
	StopOrder
)

// Order represents a trading order
type Order struct {
	ID         common.Hash
	Type       OrderType
	Price      *big.Int
	Quantity   *big.Int
	Timestamp  time.Time
	Trader     common.Address
	IsFilled   bool
	Nonce      uint64
	Signature  []byte
}

// OrderBook maintains buy and sell orders
type OrderBook struct {
	BuyOrders  []*Order
	SellOrders []*Order
	Lock       sync.Mutex
}

// NewOrderBook creates a new order book
func NewOrderBook() *OrderBook {
	return &OrderBook{
		BuyOrders:  []*Order{},
		SellOrders: []*Order{},
	}
}

// AddOrder adds a new order to the order book
func (ob *OrderBook) AddOrder(order *Order) error {
	ob.Lock.Lock()
	defer ob.Lock.Unlock()

	if order.Type == MarketOrder {
		return errors.New("market orders are not allowed in the order book")
	}

	if order.Type == LimitOrder {
		if order.Price == nil || order.Price.Cmp(big.NewInt(0)) <= 0 {
			return errors.New("invalid price for limit order")
		}
		if order.Quantity == nil || order.Quantity.Cmp(big.NewInt(0)) <= 0 {
			return errors.New("invalid quantity for limit order")
		}
	} else if order.Type == StopOrder {
		if order.Price == nil || order.Price.Cmp(big.NewInt(0)) <= 0 {
			return errors.New("invalid price for stop order")
		}
		if order.Quantity == nil || order.Quantity.Cmp(big.NewInt(0)) <= 0 {
			return errors.New("invalid quantity for stop order")
		}
	}

	order.ID = generateOrderID(order)
	order.Timestamp = time.Now()

	if order.IsFilled {
		return errors.New("cannot add a filled order to the order book")
	}

	if order.Type == LimitOrder || order.Type == StopOrder {
		if order.Trader == common.Address{} {
			return errors.New("invalid trader address")
		}
	}

	if order.Signature == nil {
		return errors.New("order must be signed")
	}

	isValid, err := verifyOrderSignature(order)
	if err != nil {
		return err
	}

	if !isValid {
		return errors.New("invalid order signature")
	}

	if order.Quantity.Cmp(big.NewInt(0)) <= 0 {
		return errors.New("order quantity must be greater than zero")
	}

	if order.Type == LimitOrder {
		ob.BuyOrders = append(ob.BuyOrders, order)
	} else if order.Type == StopOrder {
		ob.SellOrders = append(ob.SellOrders, order)
	}

	return nil
}

// RemoveOrder removes an order from the order book
func (ob *OrderBook) RemoveOrder(orderID common.Hash) error {
	ob.Lock.Lock()
	defer ob.Lock.Unlock()

	for i, order := range ob.BuyOrders {
		if order.ID == orderID {
			ob.BuyOrders = append(ob.BuyOrders[:i], ob.BuyOrders[i+1:]...)
			return nil
		}
	}

	for i, order := range ob.SellOrders {
		if order.ID == orderID {
			ob.SellOrders = append(ob.SellOrders[:i], ob.SellOrders[i+1:]...)
			return nil
		}
	}

	return errors.New("order not found")
}

// MatchOrders matches buy and sell orders in the order book
func (ob *OrderBook) MatchOrders() []*Order {
	ob.Lock.Lock()
	defer ob.Lock.Unlock()

	var matchedOrders []*Order

	for _, buyOrder := range ob.BuyOrders {
		for _, sellOrder := range ob.SellOrders {
			if buyOrder.Price.Cmp(sellOrder.Price) >= 0 && !buyOrder.IsFilled && !sellOrder.IsFilled {
				matchQuantity := big.NewInt(0)
				if buyOrder.Quantity.Cmp(sellOrder.Quantity) <= 0 {
					matchQuantity = buyOrder.Quantity
				} else {
					matchQuantity = sellOrder.Quantity
				}

				buyOrder.Quantity.Sub(buyOrder.Quantity, matchQuantity)
				sellOrder.Quantity.Sub(sellOrder.Quantity, matchQuantity)

				if buyOrder.Quantity.Cmp(big.NewInt(0)) == 0 {
					buyOrder.IsFilled = true
				}

				if sellOrder.Quantity.Cmp(big.NewInt(0)) == 0 {
					sellOrder.IsFilled = true
				}

				matchedOrders = append(matchedOrders, buyOrder, sellOrder)

				if buyOrder.IsFilled {
					ob.RemoveOrder(buyOrder.ID)
				}

				if sellOrder.IsFilled {
					ob.RemoveOrder(sellOrder.ID)
				}
			}
		}
	}

	return matchedOrders
}

// generateOrderID generates a unique order ID based on order details
func generateOrderID(order *Order) common.Hash {
	data := fmt.Sprintf("%v:%v:%v:%v:%v", order.Trader.Hex(), order.Type, order.Price, order.Quantity, time.Now().UnixNano())
	hash := sha256.Sum256([]byte(data))
	return common.BytesToHash(hash[:])
}

// signOrder signs the order using the trader's private key
func signOrder(order *Order, privateKey []byte) ([]byte, error) {
	orderData := fmt.Sprintf("%v:%v:%v:%v:%v", order.Trader.Hex(), order.Type, order.Price, order.Quantity, order.Nonce)
	orderHash := sha256.Sum256([]byte(orderData))

	key, err := scryptKey(privateKey, 32)
	if err != nil {
		return nil, err
	}

	signature := make([]byte, 32)
	for i := range orderHash {
		signature[i] = orderHash[i] ^ key[i]
	}

	return signature, nil
}

// verifyOrderSignature verifies the order signature using the trader's public key
func verifyOrderSignature(order *Order) (bool, error) {
	orderData := fmt.Sprintf("%v:%v:%v:%v:%v", order.Trader.Hex(), order.Type, order.Price, order.Quantity, order.Nonce)
	orderHash := sha256.Sum256([]byte(orderData))

	key, err := scryptKey(order.Trader.Bytes(), 32)
	if err != nil {
		return false, err
	}

	for i := range orderHash {
		if order.Signature[i] != (orderHash[i] ^ key[i]) {
			return false, nil
		}
	}

	return true, nil
}

// scryptKey generates a key using scrypt
func scryptKey(data []byte, keyLen int) ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}

	key, err := scrypt.Key(data, salt, 16384, 8, 1, keyLen)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// InitializeEthereumClient initializes an Ethereum client
func InitializeEthereumClient(clientURL string) (*ethclient.Client, error) {
	client, err := ethclient.Dial(clientURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Ethereum client: %w", err)
	}
	return client, nil
}

// SendTransaction sends a signed transaction to the Ethereum network
func SendTransaction(client *ethclient.Client, tx *types.Transaction) error {
	err := client.SendTransaction(context.Background(), tx)
	if err != nil {
		return fmt.Errorf("failed to send transaction: %w", err)
	}
	return nil
}

// GetTransactionReceipt retrieves the receipt of a transaction
func GetTransactionReceipt(client *ethclient.Client, txHash common.Hash) (*types.Receipt, error) {
	receipt, err := client.TransactionReceipt(context.Background(), txHash)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve transaction receipt: %w", err)
	}
	return receipt, nil
}
