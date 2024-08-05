package transactions

import (
	"errors"
	"fmt"

	"github.com/synnergy_network/core/tokens/token_standards/syn223/ledger"
	"github.com/synnergy_network/core/tokens/token_standards/syn223/security"
	"github.com/synnergy_network/core/tokens/token_standards/syn223/utils"
)

type OwnershipTransfer struct {
	Ledger        *ledger.Ledger
	AccessControl *security.AccessControl
}

// NewOwnershipTransfer initializes a new OwnershipTransfer instance.
func NewOwnershipTransfer(ledger *ledger.Ledger, accessControl *security.AccessControl) *OwnershipTransfer {
	return &OwnershipTransfer{
		Ledger:        ledger,
		AccessControl: accessControl,
	}
}

// TransferOwnership represents the details of an ownership transfer.
type TransferOwnership struct {
	CurrentOwner string
	NewOwner     string
	TokenID      string
	AuthKey      string
}

// ExecuteOwnershipTransfer handles the process of transferring ownership of a token.
func (ot *OwnershipTransfer) ExecuteOwnershipTransfer(transfer TransferOwnership) error {
	// Verify ownership and authorization
	if err := ot.verifyOwnership(transfer); err != nil {
		return err
	}

	// Check authorization
	if !ot.AccessControl.IsAuthorized(transfer.AuthKey) {
		return errors.New("unauthorized access")
	}

	// Perform the transfer
	if err := ot.performTransfer(transfer); err != nil {
		return err
	}

	// Log the transfer
	return ot.logTransfer(transfer)
}

func (ot *OwnershipTransfer) verifyOwnership(transfer TransferOwnership) error {
	// Verify that the current owner owns the token
	owner, err := ot.Ledger.GetTokenOwner(transfer.TokenID)
	if err != nil {
		return fmt.Errorf("failed to get token owner for token %s: %v", transfer.TokenID, err)
	}

	if owner != transfer.CurrentOwner {
		return fmt.Errorf("current owner %s does not own token %s", transfer.CurrentOwner, transfer.TokenID)
	}

	// Verify new owner address is valid
	if !ot.Ledger.IsValidAddress(transfer.NewOwner) {
		return fmt.Errorf("invalid new owner address %s", transfer.NewOwner)
	}

	return nil
}

func (ot *OwnershipTransfer) performTransfer(transfer TransferOwnership) error {
	// Update the owner of the token in the ledger
	if err := ot.Ledger.UpdateTokenOwner(transfer.TokenID, transfer.NewOwner); err != nil {
		return fmt.Errorf("failed to update token owner for token %s: %v", transfer.TokenID, err)
	}

	return nil
}

func (ot *OwnershipTransfer) logTransfer(transfer TransferOwnership) error {
	logEntry := ledger.OwnershipLog{
		CurrentOwner: transfer.CurrentOwner,
		NewOwner:     transfer.NewOwner,
		TokenID:      transfer.TokenID,
	}

	return ot.Ledger.LogOwnershipTransfer(logEntry)
}
