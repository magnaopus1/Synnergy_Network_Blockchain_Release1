package messaging

import (
	"container/heap"
	"fmt"
	"log"
	"sync"
	"time"
)

// MessageType defines the type of message
type MessageType int

const (
	// ConsensusMessage is a message related to consensus updates
	ConsensusMessage MessageType = iota
	// TransactionMessage is a message related to transactions
	TransactionMessage
	// GeneralMessage is a general message type
	GeneralMessage
)

// PriorityMessage wraps a message with its priority and type
type PriorityMessage struct {
	Message    []byte
	Priority   int
	Timestamp  time.Time
	MessageType MessageType
	index      int // Index of the item in the heap
}

// MessageQueue is a priority queue for messages
type MessageQueue []*PriorityMessage

func (mq MessageQueue) Len() int { return len(mq) }

func (mq MessageQueue) Less(i, j int) bool {
	if mq[i].Priority == mq[j].Priority {
		return mq[i].Timestamp.Before(mq[j].Timestamp)
	}
	return mq[i].Priority > mq[j].Priority
}

func (mq MessageQueue) Swap(i, j int) {
	mq[i], mq[j] = mq[j], mq[i]
	mq[i].index = i
	mq[j].index = j
}

func (mq *MessageQueue) Push(x interface{}) {
	n := len(*mq)
	item := x.(*PriorityMessage)
	item.index = n
	*mq = append(*mq, item)
}

func (mq *MessageQueue) Pop() interface{} {
	old := *mq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil  // avoid memory leak
	item.index = -1 // for safety
	*mq = old[0 : n-1]
	return item
}

// Update modifies the priority and value of a PriorityMessage in the queue.
func (mq *MessageQueue) Update(item *PriorityMessage, message []byte, priority int) {
	item.Message = message
	item.Priority = priority
	heap.Fix(mq, item.index)
}

// PriorityMessageHandler handles message prioritization and processing
type PriorityMessageHandler struct {
	messageQueue *MessageQueue
	mutex        sync.Mutex
	processingWG sync.WaitGroup
	stopChan     chan struct{}
}

// NewPriorityMessageHandler creates a new PriorityMessageHandler instance
func NewPriorityMessageHandler() *PriorityMessageHandler {
	mq := &MessageQueue{}
	heap.Init(mq)
	return &PriorityMessageHandler{
		messageQueue: mq,
		stopChan:     make(chan struct{}),
	}
}

// AddMessage adds a message to the queue with the specified priority and type
func (pmh *PriorityMessageHandler) AddMessage(message []byte, priority int, messageType MessageType) {
	pmh.mutex.Lock()
	defer pmh.mutex.Unlock()

	timestamp := time.Now()
	msg := &PriorityMessage{
		Message:    message,
		Priority:   priority,
		Timestamp:  timestamp,
		MessageType: messageType,
	}
	heap.Push(pmh.messageQueue, msg)
}

// StartProcessing starts processing messages from the queue
func (pmh *PriorityMessageHandler) StartProcessing() {
	pmh.processingWG.Add(1)
	go func() {
		defer pmh.processingWG.Done()
		for {
			select {
			case <-pmh.stopChan:
				return
			default:
				pmh.processNextMessage()
			}
		}
	}()
}

// StopProcessing stops the message processing
func (pmh *PriorityMessageHandler) StopProcessing() {
	close(pmh.stopChan)
	pmh.processingWG.Wait()
}

// processNextMessage processes the next message in the queue
func (pmh *PriorityMessageHandler) processNextMessage() {
	pmh.mutex.Lock()
	defer pmh.mutex.Unlock()

	if pmh.messageQueue.Len() == 0 {
		return
	}

	msg := heap.Pop(pmh.messageQueue).(*PriorityMessage)
	pmh.handleMessage(msg)
}

// handleMessage handles the processing of a single message
func (pmh *PriorityMessageHandler) handleMessage(msg *PriorityMessage) {
	// Implement your message handling logic here based on the message type
	switch msg.MessageType {
	case ConsensusMessage:
		log.Printf("Processing Consensus Message: %s", string(msg.Message))
	case TransactionMessage:
		log.Printf("Processing Transaction Message: %s", string(msg.Message))
	case GeneralMessage:
		log.Printf("Processing General Message: %s", string(msg.Message))
	default:
		log.Printf("Unknown Message Type: %s", string(msg.Message))
	}
}

// Example usage
func main() {
	handler := NewPriorityMessageHandler()
	handler.AddMessage([]byte("Transaction 1"), 10, TransactionMessage)
	handler.AddMessage([]byte("Consensus Update 1"), 20, ConsensusMessage)
	handler.AddMessage([]byte("General Info 1"), 5, GeneralMessage)

	handler.StartProcessing()

	// Simulate adding more messages
	handler.AddMessage([]byte("Transaction 2"), 15, TransactionMessage)
	handler.AddMessage([]byte("Consensus Update 2"), 25, ConsensusMessage)

	// Let it process for a while
	time.Sleep(2 * time.Second)

	handler.StopProcessing()
	fmt.Println("Stopped processing messages")
}
