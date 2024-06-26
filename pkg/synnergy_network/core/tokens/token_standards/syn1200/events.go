package syn1200

import (
	"log"
	"sync"
	"time"
)

// Event represents a generic interface for events in the SYN1200 token ecosystem.
type Event interface {
	Timestamp() time.Time
	Type() string
	Details() string
}

// BlockchainLinkedEvent is triggered when a new blockchain is linked to the token.
type BlockchainLinkedEvent struct {
	TokenID    string
	Blockchain string
	EventTime  time.Time
}

// AtomicSwapInitiatedEvent is triggered when an atomic swap is initiated.
type AtomicSwapInitiatedEvent struct {
	TokenID     string
	SwapID      string
	PartnerChain string
	EventTime   time.Time
}

// AtomicSwapCompletedEvent is triggered when an atomic swap is completed.
type AtomicSwapCompletedEvent struct {
	TokenID     string
	SwapID      string
	EventTime   time.Time
}

func (e *BlockchainLinkedEvent) Timestamp() time.Time {
	return e.EventTime
}

func (e *BlockchainLinkedEvent) Type() string {
	return "BlockchainLinked"
}

func (e *BlockchainLinkedEvent) Details() string {
	return "Blockchain " + e.Blockchain + " linked to token " + e.TokenID
}

func (e *AtomicSwapInitiatedEvent) Timestamp() time.Time {
	return e.EventTime
}

func (e *AtomicSwapInitiatedEvent) Type() string {
	return "AtomicSwapInitiated"
}

func (e *AtomicSwapInitiatedEvent) Details() string {
	return "Atomic swap " + e.SwapID + " initiated with " + e.PartnerChain
}

func (e *AtomicSwapCompletedEvent) Timestamp() time.Time {
	return e.EventTime
}

func (e *AtomicSwapCompletedEvent) Type() string {
	return "AtomicSwapCompleted"
}

func (e *AtomicSwapCompletedEvent) Details() string {
	return "Atomic swap " + e.SwapID + " completed"
}

// EventLogger logs and retrieves events.
type EventLogger struct {
	events []Event
	mutex  sync.Mutex
}

// NewEventLogger creates a new event logger.
func NewEventLogger() *EventLogger {
	return &EventLogger{}
}

// LogEvent logs a new event.
func (logger *EventLogger) LogEvent(event Event) {
	logger.mutex.Lock()
	defer logger.mutex.Unlock()

	logger.events = append(logger.events, event)
	log.Printf("Event logged: %s", event.Details())
}

// GetEvents returns all logged events.
func (logger *EventLogger) GetEvents() []Event {
	logger.mutex.Lock()
	defer logger.mutex.Unlock()

	return logger.events
}

// Example of logging and retrieving events.
func ExampleEventLogging() {
	logger := NewEventLogger()
	logger.LogEvent(&BlockchainLinkedEvent{TokenID: "token123", Blockchain: "Ethereum", EventTime: time.Now()})
	logger.LogEvent(&AtomicSwapInitiatedEvent{TokenID: "token123", SwapID: "swap001", PartnerChain: "BinanceChain", EventTime: time.Now()})
	logger.LogEvent(&AtomicSwapCompletedEvent{TokenID: "token123", SwapID: "swap001", EventTime: time.Now()})

	for _, event := range logger.GetEvents() {
		log.Println(event.Details())
	}
}
