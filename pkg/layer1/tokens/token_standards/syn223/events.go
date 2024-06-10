package syn223

import (
	"log"
)

// TokenEvent represents a generic interface for token-related events.
type TokenEvent interface {
	Emit()
}

// TransferEvent is emitted whenever tokens are transferred.
type TransferEvent struct {
	From    string
	To      string
	Amount  uint64
}

// ApprovalEvent is emitted whenever an approval is set.
type ApprovalEvent struct {
	Owner   string
	Spender string
	Amount  uint64
}

// Emit logs the details of a TransferEvent.
func (e *TransferEvent) Emit() {
	log.Printf("TransferEvent: %d tokens transferred from %s to %s", e.Amount, e.From, e.To)
}

// Emit logs the details of an ApprovalEvent.
func (e *ApprovalEvent) Emit() {
	log.Printf("ApprovalEvent: Approval of %d tokens from %s to %s", e.Amount, e.Owner, e.Spender)
}

// NewTransferEvent creates a new instance of TransferEvent.
func NewTransferEvent(from string, to string, amount uint64) *TransferEvent {
	return &TransferEvent{
		From:    from,
		To:      to,
		Amount:  amount,
	}
}

// NewApprovalEvent creates a new instance of ApprovalEvent.
func NewApprovalEvent(owner string, spender string, amount uint64) *ApprovalEvent {
	return &ApprovalEvent{
		Owner:   owner,
		Spender: spender,
		Amount:  amount,
	}
}
