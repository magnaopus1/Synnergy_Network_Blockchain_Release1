package transactions

import (
	"fmt"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/core/tokens/token_standards/syn721/ledger"
	"github.com/synnergy_network_blockchain/core/tokens/token_standards/syn721/security"
)

// OwnershipTransferManager manages ownership transfers for SYN721 tokens
type OwnershipTransferManager struct {
	ledger          *ledger.Ledger
	securityManager *security.SecurityManager
	mutex           sync.Mutex
}

// NewOwnershipTransferManager initializes a new OwnershipTransferManager
func NewOwnershipTransferManager(ledger *ledger.Ledger, securityManager *security.SecurityManager) *OwnershipTransferManager {
	return &OwnershipTransferManager{
		ledger:          ledger,
		securityManager: securityManager,
	}
}

// TransferOwnership transfers the ownership of a SYN721 token to a new owner
func (otm *OwnershipTransferManager) TransferOwnership(tokenID, currentOwner, newOwner string) error {
	otm.mutex.Lock()
	defer otm.mutex.Unlock()

	token, err := otm.ledger.GetToken(tokenID)
	if err != nil {
		return err
	}

	if token.Owner != currentOwner {
		return fmt.Errorf("current owner does not match")
	}

	if currentOwner == newOwner {
		return fmt.Errorf("new owner is the same as current owner")
	}

	err = otm.ledger.TransferOwnership(tokenID, newOwner)
	if err != nil {
		return err
	}

	err = otm.recordOwnershipChange(tokenID, currentOwner, newOwner)
	if err != nil {
		return err
	}

	return nil
}

// ApproveTransfer approves the transfer of a SYN721 token to a new owner
func (otm *OwnershipTransferManager) ApproveTransfer(tokenID, currentOwner, approvedAddress string) error {
	otm.mutex.Lock()
	defer otm.mutex.Unlock()

	token, err := otm.ledger.GetToken(tokenID)
	if err != nil {
		return err
	}

	if token.Owner != currentOwner {
		return fmt.Errorf("current owner does not match")
	}

	err = otm.securityManager.GrantPermission(currentOwner, approvedAddress, "transfer", tokenID)
	if err != nil {
		return err
	}

	return nil
}

// RevokeTransferApproval revokes the transfer approval of a SYN721 token
func (otm *OwnershipTransferManager) RevokeTransferApproval(tokenID, currentOwner, approvedAddress string) error {
	otm.mutex.Lock()
	defer otm.mutex.Unlock()

	token, err := otm.ledger.GetToken(tokenID)
	if err != nil {
		return err
	}

	if token.Owner != currentOwner {
		return fmt.Errorf("current owner does not match")
	}

	err = otm.securityManager.RevokePermission(currentOwner, approvedAddress, "transfer", tokenID)
	if err != nil {
		return err
	}

	return nil
}

// GetOwnershipTransferHistory retrieves the ownership transfer history for a SYN721 token
func (otm *OwnershipTransferManager) GetOwnershipTransferHistory(tokenID string) ([]ledger.OwnershipChange, error) {
	otm.mutex.Lock()
	defer otm.mutex.Unlock()

	history, err := otm.ledger.GetOwnershipHistory(tokenID)
	if err != nil {
		return nil, err
	}

	return history, nil
}

// recordOwnershipChange records an ownership change in the ledger
func (otm *OwnershipTransferManager) recordOwnershipChange(tokenID, oldOwner, newOwner string) error {
	change := ledger.OwnershipChange{
		Timestamp: time.Now(),
		OldOwner:  oldOwner,
		NewOwner:  newOwner,
	}

	err := otm.ledger.RecordOwnershipChange(tokenID, change)
	if err != nil {
		return err
	}

	return nil
}
