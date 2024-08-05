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
	MarketOrder  OrderType = "market"
	LimitOrder   OrderType = "limit"
	StopLossOrder OrderType = "stop-loss"
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

// TradingOptionsEngine handles different trading options on the DEX
type TradingOptionsEngine struct {
	client           *rpc.Client
	orderBook        *OrderBook
	ledgerManager    *ledger.LedgerManager
	positionManager  *speculation.PositionManager
	transactionMgr   *transactions.TransactionManager
	tradingPair      string
	orderMatchChan   chan Order
}

// NewTradingOptionsEngine initializes a new TradingOptionsEngine instance
func NewTradingOptionsEngine(clientURL, tradingPair string, ledgerMgr *ledger.LedgerManager, posMgr *speculation.PositionManager, txMgr *transactions.TransactionManager) (*TradingOptionsEngine, error) {
	client, err := rpc.Dial(clientURL)
	if err != nil {
		return nil, err
	}

	return &TradingOptionsEngine{
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
func (toe *TradingOptionsEngine) StartOrderMatching() {
	go func() {
		for order := range toe.orderMatchChan {
			toe.orderBook.mutex.Lock()
			toe.matchOrder(order)
			toe.orderBook.mutex.Unlock()
		}
	}()
}

// PlaceOrder places a new order in the order book
func (toe *TradingOptionsEngine) PlaceOrder(order Order) error {
	toe.orderMatchChan <- order
	return nil
}

// matchOrder matches the given order with the best available opposite orders
func (toe *TradingOptionsEngine) matchOrder(order Order) {
	if order.OrderType == MarketOrder || order.OrderType == LimitOrder {
		if order.OrderType == MarketOrder {
			toe.matchMarketOrder(order)
		} else {
			if order.Amount.Cmp(big.NewInt(0)) > 0 {
				if order.OrderType == LimitOrder {
					toe.matchLimitOrder(order)
				}
			}
		}
	}
}

// matchMarketOrder matches a market order with the best available orders
func (toe *TradingOptionsEngine) matchMarketOrder(marketOrder Order) {
	if marketOrder.OrderType == MarketOrder {
		if marketOrder.Amount.Cmp(big.NewInt(0)) > 0 {
			toe.matchLimitOrder(marketOrder)
		}
	}
}

// matchLimitOrder matches a limit order with the best available opposite orders
func (toe *TradingOptionsEngine) matchLimitOrder(limitOrder Order) {
	var matchedOrders []Order
	if limitOrder.OrderType == LimitOrder {
		if limitOrder.Amount.Cmp(big.NewInt(0)) > 0 {
			for i, sellOrder := range toe.orderBook.sellOrders {
				if limitOrder.Price.Cmp(sellOrder.Price) >= 0 {
					matchedOrders = append(matchedOrders, sellOrder)
					if limitOrder.Amount.Cmp(sellOrder.Amount) <= 0 {
						toe.orderBook.sellOrders = append(toe.orderBook.sellOrders[:i], toe.orderBook.sellOrders[i+1:]...)
						limitOrder.Amount = big.NewInt(0)
						break
					} else {
						limitOrder.Amount = new(big.Int).Sub(limitOrder.Amount, sellOrder.Amount)
						toe.orderBook.sellOrders = append(toe.orderBook.sellOrders[:i], toe.orderBook.sellOrders[i+1:]...)
					}
				}
			}

			if limitOrder.Amount.Cmp(big.NewInt(0)) > 0 {
				toe.orderBook.buyOrders = append(toe.orderBook.buyOrders, limitOrder)
			}

			for _, matchedOrder := range matchedOrders {
				toe.executeTrade(limitOrder, matchedOrder)
			}
		}
	}
}

// matchStopLossOrder matches a stop-loss order with the best available orders
func (toe *TradingOptionsEngine) matchStopLossOrder(stopLossOrder Order) {
	var matchedOrders []Order
	for i, buyOrder := range toe.orderBook.buyOrders {
		if stopLossOrder.Price.Cmp(buyOrder.Price) <= 0 {
			matchedOrders = append(matchedOrders, buyOrder)
			if stopLossOrder.Amount.Cmp(buyOrder.Amount) <= 0 {
				toe.orderBook.buyOrders = append(toe.orderBook.buyOrders[:i], toe.orderBook.buyOrders[i+1:]...)
				stopLossOrder.Amount = big.NewInt(0)
				break
			} else {
				stopLossOrder.Amount = new(big.Int).Sub(stopLossOrder.Amount, buyOrder.Amount)
				toe.orderBook.buyOrders = append(toe.orderBook.buyOrders[:i], toe.orderBook.buyOrders[i+1:]...)
			}
		}
	}

	if stopLossOrder.Amount.Cmp(big.NewInt(0)) > 0 {
		toe.orderBook.sellOrders = append(toe.orderBook.sellOrders, stopLossOrder)
	}

	for _, matchedOrder := range matchedOrders {
		toe.executeTrade(matchedOrder, stopLossOrder)
	}
}

// executeTrade executes a trade between a buy and a sell order
func (toe *TradingOptionsEngine) executeTrade(buyOrder, sellOrder Order) {
	// Create transaction
	tx, err := toe.transactionMgr.CreateTransaction(buyOrder.Trader, sellOrder.Trader, sellOrder.Price, sellOrder.Amount)
	if err != nil {
		log.Printf("Failed to create transaction: %v", err)
		return
	}

	// Record transaction in ledger
	err = toe.ledgerManager.RecordTransaction(tx)
	if err != nil {
		log.Printf("Failed to record transaction in ledger: %v", err)
		return
	}

	// Update positions
	err = toe.positionManager.UpdatePosition(buyOrder.Trader, buyOrder.Amount, buyOrder.Price, "buy")
	if err != nil {
		log.Printf("Failed to update buy position: %v", err)
		return
	}

	err = toe.positionManager.UpdatePosition(sellOrder.Trader, sellOrder.Amount, sellOrder.Price, "sell")
	if err != nil {
		log.Printf("Failed to update sell position: %v", err)
		return
	}

	log.Printf("Trade executed: %v bought from %v at price %v for amount %v", buyOrder.Trader.Hex(), sellOrder.Trader.Hex(), sellOrder.Price, sellOrder.Amount)
}

// CancelOrder cancels an existing order
func (toe *TradingOptionsEngine) CancelOrder(orderID string) error {
	toe.orderBook.mutex.Lock()
	defer toe.orderBook.mutex.Unlock()

	for i, order := range toe.orderBook.buyOrders {
		if order.OrderID == orderID {
			toe.orderBook.buyOrders = append(toe.orderBook.buyOrders[:i], toe.orderBook.buyOrders[i+1:]...)
			return nil
		}
	}

	for i, order := range toe.orderBook.sellOrders {
		if order.OrderID == orderID {
			toe.orderBook.sellOrders = append(toe.orderBook.sellOrders[:i], toe.orderBook.sellOrders[i+1:]...)
			return nil
		}
	}

	return errors.New("order not found")
}

// FetchOrderBook fetches the current order book
func (toe *TradingOptionsEngine) FetchOrderBook() ([]Order, []Order) {
	toe.orderBook.mutex.Lock()
	defer toe.orderBook.mutex.Unlock()

	return toe.orderBook.buyOrders, toe.orderBook.sellOrders
}

// generateOrderID generates a unique order ID
func generateOrderID() string {
	return common.Bytes2Hex([]byte(time.Now().String()))
}
