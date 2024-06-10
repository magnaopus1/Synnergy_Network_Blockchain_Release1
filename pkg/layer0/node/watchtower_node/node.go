package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/synthron_blockchain_final/pkg/layer0/node/common"
	"github.com/synthron_blockchain_final/pkg/layer0/node/security"
)

// WatchtowerNode represents the structure of a watchtower node.
type WatchtowerNode struct {
	NodeID       string
	IPAddress    string
	Port         int
	Security     *security.SecurityManager
	Transactions chan common.Transaction
	Alerts       chan common.Alert
	StopChan     chan bool
}

// NewWatchtowerNode creates a new instance of WatchtowerNode.
func NewWatchtowerNode(nodeID string, ipAddress string, port int) *WatchtowerNode {
	return &WatchtowerNode{
		NodeID:       nodeID,
		IPAddress:    ipAddress,
		Port:         port,
		Security:     security.NewSecurityManager(),
		Transactions: make(chan common.Transaction, 100),
		Alerts:       make(chan common.Alert, 100),
		StopChan:     make(chan bool),
	}
}

// Start initializes the watchtower node operations.
func (wn *WatchtowerNode) Start() {
	log.Println("Starting Watchtower Node...")
	wn.Security.Initialize()
	go wn.monitorTransactions()
	go wn.listenForConnections()
	go wn.handleAlerts()
}

// Stop gracefully shuts down the watchtower node.
func (wn *WatchtowerNode) Stop() {
	log.Println("Stopping Watchtower Node...")
	close(wn.StopChan)
}

// monitorTransactions continuously monitors transactions for irregularities.
func (wn *WatchtowerNode) monitorTransactions() {
	for {
		select {
		case transaction := <-wn.Transactions:
			if err := wn.Security.ValidateTransaction(transaction); err != nil {
				alert := common.Alert{
					Timestamp:  time.Now(),
					Severity:   common.Critical,
					Message:    fmt.Sprintf("Transaction validation failed: %v", err),
					Transaction: transaction,
				}
				wn.Alerts <- alert
			}
		case <-wn.StopChan:
			return
		}
	}
}

// listenForConnections handles incoming connections from other nodes.
func (wn *WatchtowerNode) listenForConnections() {
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", wn.IPAddress, wn.Port))
	if err != nil {
		log.Fatalf("Error starting TCP listener: %v", err)
	}
	defer listener.Close()

	for {
		select {
		case <-wn.StopChan:
			return
		default:
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("Error accepting connection: %v", err)
				continue
			}
			go wn.handleConnection(conn)
		}
	}
}

// handleConnection processes a single incoming connection.
func (wn *WatchtowerNode) handleConnection(conn net.Conn) {
	defer conn.Close()
	decoder := common.NewTransactionDecoder(conn)
	for {
		transaction, err := decoder.Decode()
		if err != nil {
			if err != common.ErrNoMoreTransactions {
				log.Printf("Error decoding transaction: %v", err)
			}
			break
		}
		wn.Transactions <- transaction
	}
}

// handleAlerts processes alerts and takes necessary actions.
func (wn *WatchtowerNode) handleAlerts() {
	for {
		select {
		case alert := <-wn.Alerts:
			log.Printf("ALERT: %v", alert)
			// Implement further alert handling mechanisms here
		case <-wn.StopChan:
			return
		}
	}
}

func main() {
	nodeID := "watchtower-001"
	ipAddress := "127.0.0.1"
	port := 8080

	node := NewWatchtowerNode(nodeID, ipAddress, port)
	go node.Start()

	// Ensure the node runs until an interrupt signal is received
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c

	node.Stop()
}
