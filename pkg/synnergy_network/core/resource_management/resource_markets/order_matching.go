package resource_markets

import (
    "fmt"
    "sync"
    "time"
    "github.com/synnergy_network/core/auditing"
    "github.com/synnergy_network/core/data_analytics"
    "github.com/synnergy_network/core/resource_security"
)

// OrderType defines the type of order: Buy or Sell
type OrderType string

const (
    BuyOrder  OrderType = "BUY"
    SellOrder OrderType = "SELL"
)

// Order represents a market order
type Order struct {
    OrderID     string
    ResourceID  string
    Type        OrderType
    Quantity    float64
    Price       float64
    Timestamp   time.Time
}

// OrderBook maintains lists of buy and sell orders
type OrderBook struct {
    BuyOrders  []*Order
    SellOrders []*Order
    mu         sync.RWMutex
}

// NewOrderBook initializes a new order book
func NewOrderBook() *OrderBook {
    return &OrderBook{
        BuyOrders:  []*Order{},
        SellOrders: []*Order{},
    }
}

// AddOrder adds a new order to the order book
func (ob *OrderBook) AddOrder(order *Order) {
    ob.mu.Lock()
    defer ob.mu.Unlock()

    switch order.Type {
    case BuyOrder:
        ob.BuyOrders = append(ob.BuyOrders, order)
    case SellOrder:
        ob.SellOrders = append(ob.SellOrders, order)
    }

    auditing.LogOrderPlacement(order)
    ob.matchOrders()
}

// matchOrders matches buy and sell orders
func (ob *OrderBook) matchOrders() {
    ob.mu.Lock()
    defer ob.mu.Unlock()

    for i := 0; i < len(ob.BuyOrders); i++ {
        buyOrder := ob.BuyOrders[i]
        for j := 0; j < len(ob.SellOrders); j++ {
            sellOrder := ob.SellOrders[j]
            if buyOrder.Price >= sellOrder.Price && buyOrder.Quantity == sellOrder.Quantity {
                ob.executeTrade(buyOrder, sellOrder)
                // Remove matched orders from the order book
                ob.BuyOrders = append(ob.BuyOrders[:i], ob.BuyOrders[i+1:]...)
                ob.SellOrders = append(ob.SellOrders[:j], ob.SellOrders[j+1:]...)
                break
            }
        }
    }
}

// executeTrade executes a trade between a buy and sell order
func (ob *OrderBook) executeTrade(buyOrder, sellOrder *Order) {
    // Record the trade for auditing and analytics
    auditing.LogTradeExecution(buyOrder, sellOrder)
    // Further processing, such as transferring resources or payments, can be implemented here
    fmt.Printf("Executed trade: BuyOrder %s matched with SellOrder %s\n", buyOrder.OrderID, sellOrder.OrderID)
}

// SecureOrders secures the order data
func (ob *OrderBook) SecureOrders() {
    for _, order := range ob.BuyOrders {
        encryptedOrder := resource_security.EncryptData(order)
        // Securely store or handle encrypted order data
        _ = encryptedOrder
    }
    for _, order := range ob.SellOrders {
        encryptedOrder := resource_security.EncryptData(order)
        // Securely store or handle encrypted order data
        _ = encryptedOrder
    }
}

// Further enhancements and features can be added as needed
