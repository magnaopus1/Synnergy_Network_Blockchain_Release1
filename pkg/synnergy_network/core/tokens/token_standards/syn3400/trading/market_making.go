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

// MarketMaker handles automated market making on the DEX.
type MarketMaker struct {
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
	spread           *big.Int
}

// NewMarketMaker initializes a new MarketMaker instance.
func NewMarketMaker(clientURL, baseCurrency, quoteCurrency string, ledgerMgr *ledger.LedgerManager, posMgr *speculation.PositionManager, txMgr *transactions.TransactionManager, spread *big.Int) (*MarketMaker, error) {
	client, err := rpc.Dial(clientURL)
	if err != nil {
		return nil, err
	}

	tradingPair := baseCurrency + "-" + quoteCurrency

	return &MarketMaker{
		client:           client,
		orderBook:        make(map[string][]Order),
		ledgerManager:    ledgerMgr,
		positionManager:  posMgr,
		transactionMgr:   txMgr,
		baseCurrency:     baseCurrency,
		quoteCurrency:    quoteCurrency,
		tradingPair:      tradingPair,
		orderBookChannel: make(chan Order, 100),
		spread:           spread,
	}, nil
}

// StartMarketMaking starts the market making process.
func (mm *MarketMaker) StartMarketMaking() {
	go func() {
		for order := range mm.orderBookChannel {
			mm.orderBookMutex.Lock()
			mm.orderBook[mm.tradingPair] = append(mm.orderBook[mm.tradingPair], order)
			mm.orderBookMutex.Unlock()

			mm.makeMarket()
		}
	}()
}

// PlaceOrder places a new order in the market.
func (mm *MarketMaker) PlaceOrder(order Order) error {
	mm.orderBookChannel <- order
	return nil
}

// makeMarket creates and places buy and sell orders to provide liquidity.
func (mm *MarketMaker) makeMarket() {
	mm.orderBookMutex.Lock()
	defer mm.orderBookMutex.Unlock()

	buyOrders := mm.getOrdersByType("buy")
	sellOrders := mm.getOrdersByType("sell")

	if len(buyOrders) == 0 && len(sellOrders) == 0 {
		mm.placeInitialOrders()
		return
	}

	bestBuyPrice := mm.getBestPrice(buyOrders)
	bestSellPrice := mm.getBestPrice(sellOrders)

	if bestBuyPrice != nil && bestSellPrice != nil && bestBuyPrice.Cmp(bestSellPrice) >= 0 {
		return
	}

	mm.placeNewOrders(bestBuyPrice, bestSellPrice)
}

// placeInitialOrders places initial buy and sell orders.
func (mm *MarketMaker) placeInitialOrders() {
	initialBuyOrder := Order{
		OrderID:   generateOrderID(),
		Trader:    common.HexToAddress("0x0"),
		OrderType: "buy",
		Price:     big.NewInt(1000),
		Amount:    big.NewInt(10),
		Timestamp: time.Now(),
	}
	initialSellOrder := Order{
		OrderID:   generateOrderID(),
		Trader:    common.HexToAddress("0x0"),
		OrderType: "sell",
		Price:     big.NewInt(1100),
		Amount:    big.NewInt(10),
		Timestamp: time.Now(),
	}

	mm.orderBook[mm.tradingPair] = append(mm.orderBook[mm.tradingPair], initialBuyOrder, initialSellOrder)
}

// placeNewOrders places new buy and sell orders based on the current best prices.
func (mm *MarketMaker) placeNewOrders(bestBuyPrice, bestSellPrice *big.Int) {
	newBuyOrder := Order{
		OrderID:   generateOrderID(),
		Trader:    common.HexToAddress("0x0"),
		OrderType: "buy",
		Price:     new(big.Int).Sub(bestBuyPrice, mm.spread),
		Amount:    big.NewInt(10),
		Timestamp: time.Now(),
	}
	newSellOrder := Order{
		OrderID:   generateOrderID(),
		Trader:    common.HexToAddress("0x0"),
		OrderType: "sell",
		Price:     new(big.Int).Add(bestSellPrice, mm.spread),
		Amount:    big.NewInt(10),
		Timestamp: time.Now(),
	}

	mm.orderBook[mm.tradingPair] = append(mm.orderBook[mm.tradingPair], newBuyOrder, newSellOrder)
}

// getOrdersByType returns orders of a specific type (buy/sell).
func (mm *MarketMaker) getOrdersByType(orderType string) []Order {
	var orders []Order
	for _, order := range mm.orderBook[mm.tradingPair] {
		if order.OrderType == orderType {
			orders = append(orders, order)
		}
	}
	return orders
}

// getBestPrice returns the best price for a given set of orders.
func (mm *MarketMaker) getBestPrice(orders []Order) *big.Int {
	if len(orders) == 0 {
		return nil
	}

	bestPrice := orders[0].Price
	for _, order := range orders {
		if order.Price.Cmp(bestPrice) < 0 {
			bestPrice = order.Price
		}
	}
	return bestPrice
}

// FetchOrderBook fetches the current order book.
func (mm *MarketMaker) FetchOrderBook() ([]Order, error) {
	mm.orderBookMutex.Lock()
	defer mm.orderBookMutex.Unlock()

	return mm.orderBook[mm.tradingPair], nil
}

// CancelOrder cancels an existing order.
func (mm *MarketMaker) CancelOrder(orderID string) error {
	mm.orderBookMutex.Lock()
	defer mm.orderBookMutex.Unlock()

	for i, order := range mm.orderBook[mm.tradingPair] {
		if order.OrderID == orderID {
			mm.orderBook[mm.tradingPair] = append(mm.orderBook[mm.tradingPair][:i], mm.orderBook[mm.tradingPair][i+1:]...)
			return nil
		}
	}

	return errors.New("order not found")
}

// generateOrderID generates a unique order ID.
func generateOrderID() string {
	return common.Bytes2Hex([]byte(time.Now().String()))
}
