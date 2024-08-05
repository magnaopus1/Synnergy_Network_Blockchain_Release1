package trading

import (
	"errors"
	"log"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/speculation"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/transactions"
)

// OrderType defines the type of order
type OrderType string

const (
	BuyOrder  OrderType = "buy"
	SellOrder OrderType = "sell"
)

// Order represents a single order in the order book
type Order struct {
	OrderID   string
	Trader    common.Address
	OrderType OrderType
	Price     *big.Int
	Amount    *big.Int
	Timestamp time.Time
}

// OrderBook holds buy and sell orders
type OrderBook struct {
	buyOrders  []Order
	sellOrders []Order
	mutex      sync.Mutex
}

// OrderMatchingEngine handles order matching on the DEX
type OrderMatchingEngine struct {
	client           *rpc.Client
	orderBook        *OrderBook
	ledgerManager    *ledger.LedgerManager
	positionManager  *speculation.PositionManager
	transactionMgr   *transactions.TransactionManager
	tradingPair      string
	orderMatchChan   chan Order
}

// NewOrderMatchingEngine initializes a new OrderMatchingEngine instance
func NewOrderMatchingEngine(clientURL, tradingPair string, ledgerMgr *ledger.LedgerManager, posMgr *speculation.PositionManager, txMgr *transactions.TransactionManager) (*OrderMatchingEngine, error) {
	client, err := rpc.Dial(clientURL)
	if err != nil {
		return nil, err
	}

	return &OrderMatchingEngine{
		client: client,
		orderBook: &OrderBook{
			buyOrders:  []Order{},
			sellOrders: []Order{},
		},
		ledgerManager:   ledgerMgr,
		positionManager: posMgr,
		transactionMgr:  txMgr,
		tradingPair:     tradingPair,
		orderMatchChan:  make(chan Order, 100),
	}, nil
}

// StartOrderMatching starts the order matching process
func (ome *OrderMatchingEngine) StartOrderMatching() {
	go func() {
		for order := range ome.orderMatchChan {
			ome.orderBook.mutex.Lock()
			ome.matchOrder(order)
			ome.orderBook.mutex.Unlock()
		}
	}()
}

// PlaceOrder places a new order in the order book
func (ome *OrderMatchingEngine) PlaceOrder(order Order) error {
	ome.orderMatchChan <- order
	return nil
}

// matchOrder matches the given order with the best available opposite orders
func (ome *OrderMatchingEngine) matchOrder(order Order) {
	if order.OrderType == BuyOrder {
		ome.matchBuyOrder(order)
	} else {
		ome.matchSellOrder(order)
	}
}

// matchBuyOrder matches a buy order with the best available sell orders
func (ome *OrderMatchingEngine) matchBuyOrder(buyOrder Order) {
	var matchedOrders []Order
	for i, sellOrder := range ome.orderBook.sellOrders {
		if buyOrder.Price.Cmp(sellOrder.Price) >= 0 {
			matchedOrders = append(matchedOrders, sellOrder)
			if buyOrder.Amount.Cmp(sellOrder.Amount) <= 0 {
				ome.orderBook.sellOrders = append(ome.orderBook.sellOrders[:i], ome.orderBook.sellOrders[i+1:]...)
				buyOrder.Amount = big.NewInt(0)
				break
			} else {
				buyOrder.Amount = new(big.Int).Sub(buyOrder.Amount, sellOrder.Amount)
				ome.orderBook.sellOrders = append(ome.orderBook.sellOrders[:i], ome.orderBook.sellOrders[i+1:]...)
			}
		}
	}

	if buyOrder.Amount.Cmp(big.NewInt(0)) > 0 {
		ome.orderBook.buyOrders = append(ome.orderBook.buyOrders, buyOrder)
	}

	for _, matchedOrder := range matchedOrders {
		ome.executeTrade(buyOrder, matchedOrder)
	}
}

// matchSellOrder matches a sell order with the best available buy orders
func (ome *OrderMatchingEngine) matchSellOrder(sellOrder Order) {
	var matchedOrders []Order
	for i, buyOrder := range ome.orderBook.buyOrders {
		if sellOrder.Price.Cmp(buyOrder.Price) <= 0 {
			matchedOrders = append(matchedOrders, buyOrder)
			if sellOrder.Amount.Cmp(buyOrder.Amount) <= 0 {
				ome.orderBook.buyOrders = append(ome.orderBook.buyOrders[:i], ome.orderBook.buyOrders[i+1:]...)
				sellOrder.Amount = big.NewInt(0)
				break
			} else {
				sellOrder.Amount = new(big.Int).Sub(sellOrder.Amount, buyOrder.Amount)
				ome.orderBook.buyOrders = append(ome.orderBook.buyOrders[:i], ome.orderBook.buyOrders[i+1:]...)
			}
		}
	}

	if sellOrder.Amount.Cmp(big.NewInt(0)) > 0 {
		ome.orderBook.sellOrders = append(ome.orderBook.sellOrders, sellOrder)
	}

	for _, matchedOrder := range matchedOrders {
		ome.executeTrade(matchedOrder, sellOrder)
	}
}

// executeTrade executes a trade between a buy and a sell order
func (ome *OrderMatchingEngine) executeTrade(buyOrder, sellOrder Order) {
	// Create transaction
	tx, err := ome.transactionMgr.CreateTransaction(buyOrder.Trader, sellOrder.Trader, sellOrder.Price, sellOrder.Amount)
	if err != nil {
		log.Printf("Failed to create transaction: %v", err)
		return
	}

	// Record transaction in ledger
	err = ome.ledgerManager.RecordTransaction(tx)
	if err != nil {
		log.Printf("Failed to record transaction in ledger: %v", err)
		return
	}

	// Update positions
	err = ome.positionManager.UpdatePosition(buyOrder.Trader, buyOrder.Amount, buyOrder.Price, "buy")
	if err != nil {
		log.Printf("Failed to update buy position: %v", err)
		return
	}

	err = ome.positionManager.UpdatePosition(sellOrder.Trader, sellOrder.Amount, sellOrder.Price, "sell")
	if err != nil {
		log.Printf("Failed to update sell position: %v", err)
		return
	}

	log.Printf("Trade executed: %v bought from %v at price %v for amount %v", buyOrder.Trader.Hex(), sellOrder.Trader.Hex(), sellOrder.Price, sellOrder.Amount)
}

// CancelOrder cancels an existing order
func (ome *OrderMatchingEngine) CancelOrder(orderID string) error {
	ome.orderBook.mutex.Lock()
	defer ome.orderBook.mutex.Unlock()

	for i, order := range ome.orderBook.buyOrders {
		if order.OrderID == orderID {
			ome.orderBook.buyOrders = append(ome.orderBook.buyOrders[:i], ome.orderBook.buyOrders[i+1:]...)
			return nil
		}
	}

	for i, order := range ome.orderBook.sellOrders {
		if order.OrderID == orderID {
			ome.orderBook.sellOrders = append(ome.orderBook.sellOrders[:i], ome.orderBook.sellOrders[i+1:]...)
			return nil
		}
	}

	return errors.New("order not found")
}

// FetchOrderBook fetches the current order book
func (ome *OrderMatchingEngine) FetchOrderBook() ([]Order, []Order) {
	ome.orderBook.mutex.Lock()
	defer ome.orderBook.mutex.Unlock()

	return ome.orderBook.buyOrders, ome.orderBook.sellOrders
}

// generateOrderID generates a unique order ID
func generateOrderID() string {
	return common.Bytes2Hex([]byte(time.Now().String()))
}
