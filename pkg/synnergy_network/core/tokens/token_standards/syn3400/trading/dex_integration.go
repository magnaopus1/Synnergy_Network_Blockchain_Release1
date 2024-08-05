package trading

import (
	"encoding/json"
	"errors"
	"log"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/speculation"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/transactions"
)

// DEXIntegration handles integration with decentralized exchanges (DEX).
type DEXIntegration struct {
	client           *rpc.Client
	orderBook        map[string][]Order
	orderBookMutex   sync.Mutex
	ledgerManager    *ledger.LedgerManager
	positionManager  *speculation.PositionManager
	transactionMgr   *transactions.TransactionManager
	baseCurrency     string
	quoteCurrency    string
	tradingPair      string
	orderBookChannel chan Order
}

// Order represents a DEX order.
type Order struct {
	OrderID      string
	Trader       common.Address
	OrderType    string
	Price        *big.Int
	Amount       *big.Int
	Timestamp    time.Time
	Signature    string
}

// NewDEXIntegration initializes a new DEXIntegration instance.
func NewDEXIntegration(clientURL, baseCurrency, quoteCurrency string, ledgerMgr *ledger.LedgerManager, posMgr *speculation.PositionManager, txMgr *transactions.TransactionManager) (*DEXIntegration, error) {
	client, err := rpc.Dial(clientURL)
	if err != nil {
		return nil, err
	}

	tradingPair := baseCurrency + "-" + quoteCurrency

	return &DEXIntegration{
		client:           client,
		orderBook:        make(map[string][]Order),
		ledgerManager:    ledgerMgr,
		positionManager:  posMgr,
		transactionMgr:   txMgr,
		baseCurrency:     baseCurrency,
		quoteCurrency:    quoteCurrency,
		tradingPair:      tradingPair,
		orderBookChannel: make(chan Order, 100),
	}, nil
}

// StartOrderBookListener starts listening for new orders.
func (dex *DEXIntegration) StartOrderBookListener() {
	go func() {
		for order := range dex.orderBookChannel {
			dex.orderBookMutex.Lock()
			dex.orderBook[dex.tradingPair] = append(dex.orderBook[dex.tradingPair], order)
			dex.orderBookMutex.Unlock()

			dex.matchOrders()
		}
	}()
}

// PlaceOrder places a new order on the DEX.
func (dex *DEXIntegration) PlaceOrder(order Order) error {
	dex.orderBookChannel <- order
	return nil
}

// matchOrders matches and executes orders from the order book.
func (dex *DEXIntegration) matchOrders() {
	dex.orderBookMutex.Lock()
	defer dex.orderBookMutex.Unlock()

	buyOrders := dex.getOrdersByType("buy")
	sellOrders := dex.getOrdersByType("sell")

	for _, buyOrder := range buyOrders {
		for _, sellOrder := range sellOrders {
			if buyOrder.Price.Cmp(sellOrder.Price) >= 0 && buyOrder.Amount.Cmp(sellOrder.Amount) >= 0 {
				dex.executeTrade(buyOrder, sellOrder)
			}
		}
	}
}

// getOrdersByType returns orders of a specific type (buy/sell).
func (dex *DEXIntegration) getOrdersByType(orderType string) []Order {
	var orders []Order
	for _, order := range dex.orderBook[dex.tradingPair] {
		if order.OrderType == orderType {
			orders = append(orders, order)
		}
	}
	return orders
}

// executeTrade executes a trade between two orders.
func (dex *DEXIntegration) executeTrade(buyOrder, sellOrder Order) {
	// Create and execute transaction
	tx := transactions.NewTransaction(buyOrder.Trader, sellOrder.Trader, sellOrder.Amount, dex.baseCurrency, dex.quoteCurrency, buyOrder.Price)
	if err := dex.transactionMgr.ExecuteTransaction(tx); err != nil {
		log.Println("Error executing transaction:", err)
		return
	}

	// Update position manager
	dex.positionManager.UpdatePosition(buyOrder.Trader, dex.tradingPair, buyOrder.Amount, "buy")
	dex.positionManager.UpdatePosition(sellOrder.Trader, dex.tradingPair, sellOrder.Amount, "sell")

	// Remove executed orders from order book
	dex.removeOrder(buyOrder.OrderID)
	dex.removeOrder(sellOrder.OrderID)

	log.Printf("Trade executed: Buy Order %s, Sell Order %s", buyOrder.OrderID, sellOrder.OrderID)
}

// removeOrder removes an order from the order book.
func (dex *DEXIntegration) removeOrder(orderID string) {
	for i, order := range dex.orderBook[dex.tradingPair] {
		if order.OrderID == orderID {
			dex.orderBook[dex.tradingPair] = append(dex.orderBook[dex.tradingPair][:i], dex.orderBook[dex.tradingPair][i+1:]...)
			break
		}
	}
}

// FetchOrderBook fetches the current order book from the DEX.
func (dex *DEXIntegration) FetchOrderBook() ([]Order, error) {
	dex.orderBookMutex.Lock()
	defer dex.orderBookMutex.Unlock()

	return dex.orderBook[dex.tradingPair], nil
}

// SyncOrderBook syncs the order book with the DEX.
func (dex *DEXIntegration) SyncOrderBook() error {
	resp, err := http.Get("https://api.dex.example.com/orderbook/" + dex.tradingPair)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var orders []Order
	if err := json.NewDecoder(resp.Body).Decode(&orders); err != nil {
		return err
	}

	dex.orderBookMutex.Lock()
	dex.orderBook[dex.tradingPair] = orders
	dex.orderBookMutex.Unlock()

	return nil
}

// CancelOrder cancels an existing order on the DEX.
func (dex *DEXIntegration) CancelOrder(orderID string) error {
	dex.orderBookMutex.Lock()
	defer dex.orderBookMutex.Unlock()

	for i, order := range dex.orderBook[dex.tradingPair] {
		if order.OrderID == orderID {
			dex.orderBook[dex.tradingPair] = append(dex.orderBook[dex.tradingPair][:i], dex.orderBook[dex.tradingPair][i+1:]...)
			return nil
		}
	}

	return errors.New("order not found")
}
