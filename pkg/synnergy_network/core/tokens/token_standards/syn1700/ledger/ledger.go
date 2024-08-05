package ledger

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn1700/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn1700/security"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn1700/transactions"
)

// Ledger represents the blockchain ledger for SYN1700 tokens
type Ledger struct {
	mu              sync.Mutex
	Events          map[string]assets.EventMetadata
	Tickets         map[string]assets.TicketMetadata
	OwnershipRecords map[string][]assets.OwnershipRecord
	EventLogs       map[string][]assets.EventLog
	ComplianceRecords map[string][]assets.ComplianceRecord
	TransactionPool []*transactions.Transaction
	Blocks          []*Block
}

// Block represents a block in the blockchain
type Block struct {
	Timestamp    time.Time
	Transactions []*transactions.Transaction
	PrevHash     string
	Hash         string
	Nonce        int
}

// NewLedger creates a new ledger instance
func NewLedger() *Ledger {
	return &Ledger{
		Events:           make(map[string]assets.EventMetadata),
		Tickets:          make(map[string]assets.TicketMetadata),
		OwnershipRecords: make(map[string][]assets.OwnershipRecord),
		EventLogs:        make(map[string][]assets.EventLog),
		ComplianceRecords: make(map[string][]assets.ComplianceRecord),
		TransactionPool:  []*transactions.Transaction{},
		Blocks:           []*Block{},
	}
}

// AddEvent adds a new event to the ledger
func (l *Ledger) AddEvent(event assets.EventMetadata) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if _, exists := l.Events[event.EventID]; exists {
		return errors.New("event already exists")
	}
	l.Events[event.EventID] = event

	l.EventLogs[event.EventID] = append(l.EventLogs[event.EventID], assets.EventLog{
		EventID:   event.EventID,
		Activity:  "Event Created",
		Timestamp: time.Now(),
	})

	return nil
}

// AddTicket adds a new ticket to the ledger
func (l *Ledger) AddTicket(ticket assets.TicketMetadata) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if _, exists := l.Tickets[ticket.TicketID]; exists {
		return errors.New("ticket already exists")
	}
	l.Tickets[ticket.TicketID] = ticket

	l.OwnershipRecords[ticket.TicketID] = append(l.OwnershipRecords[ticket.TicketID], assets.OwnershipRecord{
		TicketID:  ticket.TicketID,
		OwnerID:   ticket.EventID,
		Timestamp: time.Now(),
	})

	l.EventLogs[ticket.EventID] = append(l.EventLogs[ticket.EventID], assets.EventLog{
		EventID:   ticket.EventID,
		Activity:  "Ticket Created",
		Timestamp: time.Now(),
	})

	return nil
}

// TransferTicket transfers a ticket to a new owner
func (l *Ledger) TransferTicket(ticketID, newOwnerID string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	ticket, exists := l.Tickets[ticketID]
	if !exists {
		return errors.New("ticket does not exist")
	}

	ownershipRecords, exists := l.OwnershipRecords[ticketID]
	if !exists || len(ownershipRecords) == 0 {
		return errors.New("ownership records do not exist")
	}

	currentOwnerID := ownershipRecords[len(ownershipRecords)-1].OwnerID
	if currentOwnerID == newOwnerID {
		return errors.New("new owner is the same as the current owner")
	}

	l.OwnershipRecords[ticketID] = append(l.OwnershipRecords[ticketID], assets.OwnershipRecord{
		TicketID:  ticketID,
		OwnerID:   newOwnerID,
		Timestamp: time.Now(),
	})

	l.EventLogs[ticket.EventID] = append(l.EventLogs[ticket.EventID], assets.EventLog{
		EventID:   ticket.EventID,
		Activity:  "Ticket Transferred",
		Timestamp: time.Now(),
	})

	return nil
}

// AddComplianceRecord adds a compliance record to the ledger
func (l *Ledger) AddComplianceRecord(eventID, complianceDetails string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if _, exists := l.Events[eventID]; !exists {
		return errors.New("event does not exist")
	}

	l.ComplianceRecords[eventID] = append(l.ComplianceRecords[eventID], assets.ComplianceRecord{
		EventID:          eventID,
		ComplianceDetails: complianceDetails,
		Timestamp:        time.Now(),
	})

	l.EventLogs[eventID] = append(l.EventLogs[eventID], assets.EventLog{
		EventID:   eventID,
		Activity:  "Compliance Record Added",
		Timestamp: time.Now(),
	})

	return nil
}

// CreateTransaction creates a new transaction and adds it to the transaction pool
func (l *Ledger) CreateTransaction(tx *transactions.Transaction) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	tx.ID = uuid.New().String()
	l.TransactionPool = append(l.TransactionPool, tx)

	return nil
}

// AddBlock adds a new block to the blockchain
func (l *Ledger) AddBlock(block *Block) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Calculate the previous hash
	if len(l.Blocks) > 0 {
		block.PrevHash = l.Blocks[len(l.Blocks)-1].Hash
	} else {
		block.PrevHash = ""
	}

	// Mine the block to find the nonce and hash
	for {
		block.Timestamp = time.Now()
		block.Nonce++
		block.Hash = security.CalculateHash(block)
		if security.ValidatePoW(block.Hash) {
			break
		}
	}

	l.Blocks = append(l.Blocks, block)
	l.TransactionPool = []*transactions.Transaction{} // Clear the transaction pool

	return nil
}

// GetEvent retrieves an event by ID
func (l *Ledger) GetEvent(eventID string) (assets.EventMetadata, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	event, exists := l.Events[eventID]
	if !exists {
		return assets.EventMetadata{}, errors.New("event not found")
	}
	return event, nil
}

// GetTicket retrieves a ticket by ID
func (l *Ledger) GetTicket(ticketID string) (assets.TicketMetadata, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	ticket, exists := l.Tickets[ticketID]
	if !exists {
		return assets.TicketMetadata{}, errors.New("ticket not found")
	}
	return ticket, nil
}

// GetOwnershipRecords retrieves ownership records for a ticket
func (l *Ledger) GetOwnershipRecords(ticketID string) ([]assets.OwnershipRecord, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	records, exists := l.OwnershipRecords[ticketID]
	if !exists {
		return nil, errors.New("ownership records not found")
	}
	return records, nil
}

// GetEventLogs retrieves event logs for an event
func (l *Ledger) GetEventLogs(eventID string) ([]assets.EventLog, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	logs, exists := l.EventLogs[eventID]
	if !exists {
		return nil, errors.New("event logs not found")
	}
	return logs, nil
}

// GetComplianceRecords retrieves compliance records for an event
func (l *Ledger) GetComplianceRecords(eventID string) ([]assets.ComplianceRecord, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	records, exists := l.ComplianceRecords[eventID]
	if !exists {
		return nil, errors.New("compliance records not found")
	}
	return records, nil
}

// SerializeLedger serializes the ledger to JSON
func (l *Ledger) SerializeLedger() (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	data, err := json.Marshal(l)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// DeserializeLedger deserializes the ledger from JSON
func (l *Ledger) DeserializeLedger(data string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	err := json.Unmarshal([]byte(data), l)
	if err != nil {
		return err
	}
	return nil
}
