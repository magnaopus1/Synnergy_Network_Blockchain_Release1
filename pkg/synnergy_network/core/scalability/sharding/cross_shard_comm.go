package sharding

import (
	"encoding/json"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Shard represents a blockchain shard handling a subset of transactions.
type Shard struct {
	ID           int
	NodeRegistry []string // List of node addresses
}

// Transaction represents a blockchain transaction that may span multiple shards.
type Transaction struct {
	ID          string
	Data        interface{}
	ShardOrigin int
	ShardTarget int
}

// CrossShardMessage encapsulates a transaction and its routing information.
type CrossShardMessage struct {
	Transaction *Transaction
	Type        string // Type could be "commit", "rollback", etc.
}

// CrossShardCommunicator provides functionalities for handling cross-shard transactions.
type CrossShardCommunicator struct {
	Shards map[int]*Shard
	lock   sync.RWMutex
	conn   map[string]*websocket.Conn
}

// NewCrossShardCommunicator initializes a new CrossShardCommunicator with predefined shards.
func NewCrossShardCommunicator(shards map[int]*Shard) *CrossShardCommunicator {
	return &CrossShardCommunicator{
		Shards: shards,
		conn:   make(map[string]*websocket.Conn),
	}
}

// sendMessage sends a CrossShardMessage to the target shard node.
func (csc *CrossShardCommunicator) sendMessage(msg *CrossShardMessage, targetNode string) error {
	conn, ok := csc.conn[targetNode]
	if !ok {
		var err error
		conn, _, err = websocket.DefaultDialer.Dial("ws://"+targetNode, nil)
		if err != nil {
			return err
		}
		csc.conn[targetNode] = conn
	}
	message, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return conn.WriteMessage(websocket.TextMessage, message)
}

// handleIncomingMessages listens for incoming cross-shard messages.
func (csc *CrossShardCommunicator) handleIncomingMessages() {
	for _, shard := range csc.Shards {
		for _, node := range shard.NodeRegistry {
			go func(node string) {
				for {
					conn, ok := csc.conn[node]
					if !ok {
						continue
					}
					_, message, err := conn.ReadMessage()
					if err != nil {
						continue // Handle errors appropriately.
					}
					var msg CrossShardMessage
					if err := json.Unmarshal(message, &msg); err != nil {
						continue // Handle JSON errors.
					}
					// Process message based on type.
				}
			}(node)
		}
	}
}

// CommitTransaction handles the logic to commit a transaction across shards.
func (csc *CrossShardCommunicator) CommitTransaction(tx *Transaction) error {
	targetShard, exists := csc.Shards[tx.ShardTarget]
	if !exists {
		return errors.New("target shard does not exist")
	}

	msg := &CrossShardMessage{
		Transaction: tx,
		Type:        "commit",
	}

	for _, node := range targetShard.NodeRegistry {
		if err := csc.sendMessage(msg, node); err != nil {
			return err
		}
	}
	return nil
}

// Initialize and run the communicator in your blockchain network setup.
func main() {
	shards := map[int]*Shard{
		1: {ID: 1, NodeRegistry: []string{"localhost:8001"}},
		2: {ID: 2, NodeRegistry: []string{"localhost:8002"}},
	}
	csc := NewCrossShardCommunicator(shards)
	go csc.handleIncomingMessages() // Start handling incoming messages

	// Simulate a cross-shard transaction
	tx := &Transaction{ID: "tx100", ShardOrigin: 1, ShardTarget: 2}
	if err := csc.CommitTransaction(tx); err != nil {
		panic(err)
	}
}
