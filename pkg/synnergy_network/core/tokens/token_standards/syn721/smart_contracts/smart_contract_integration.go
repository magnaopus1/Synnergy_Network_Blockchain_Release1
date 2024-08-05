package smart_contracts

import (
	"fmt"
	"sync"
	"time"
	
	"github.com/synnergy_network_blockchain/core/tokens/token_standards/syn721/assets"
	"github.com/synnergy_network_blockchain/core/tokens/token_standards/syn721/ledger"
	"github.com/synnergy_network_blockchain/core/tokens/token_standards/syn721/security"
)

// Syn721SmartContract represents a smart contract for managing SYN721 tokens
type Syn721SmartContract struct {
	contractAddress string
	ledger          *ledger.Ledger
	securityManager *security.SecurityManager
	mutex           sync.Mutex
}

// NewSyn721SmartContract initializes a new Syn721SmartContract
func NewSyn721SmartContract(contractAddress string, ledger *ledger.Ledger, securityManager *security.SecurityManager) *Syn721SmartContract {
	return &Syn721SmartContract{
		contractAddress: contractAddress,
		ledger:          ledger,
		securityManager: securityManager,
	}
}

// MintToken mints a new SYN721 token
func (sc *Syn721SmartContract) MintToken(owner string, metadata assets.Metadata, valuation assets.Valuation) (string, error) {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	tokenID, err := sc.ledger.GenerateTokenID()
	if err != nil {
		return "", err
	}

	token := assets.Syn721Token{
		ID:        tokenID,
		Owner:     owner,
		Metadata:  metadata,
		Valuation: valuation,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	err = sc.ledger.AddToken(token)
	if err != nil {
		return "", err
	}

	return tokenID, nil
}

// TransferToken transfers a SYN721 token to a new owner
func (sc *Syn721SmartContract) TransferToken(tokenID, newOwner string) error {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	token, err := sc.ledger.GetToken(tokenID)
	if err != nil {
		return err
	}

	if token.Owner == newOwner {
		return fmt.Errorf("new owner is the same as current owner")
	}

	err = sc.ledger.TransferOwnership(tokenID, newOwner)
	if err != nil {
		return err
	}

	return nil
}

// BurnToken burns a SYN721 token, removing it from circulation
func (sc *Syn721SmartContract) BurnToken(tokenID string) error {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	err := sc.ledger.RemoveToken(tokenID)
	if err != nil {
		return err
	}

	return nil
}

// UpdateMetadata updates the metadata of a SYN721 token
func (sc *Syn721SmartContract) UpdateMetadata(tokenID string, newMetadata assets.Metadata) error {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	err := sc.ledger.UpdateTokenMetadata(tokenID, newMetadata)
	if err != nil {
		return err
	}

	return nil
}

// UpdateValuation updates the valuation of a SYN721 token
func (sc *Syn721SmartContract) UpdateValuation(tokenID string, newValuation assets.Valuation) error {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	err := sc.ledger.UpdateTokenValuation(tokenID, newValuation)
	if err != nil {
		return err
	}

	return nil
}

// Approve approves an address to manage a SYN721 token
func (sc *Syn721SmartContract) Approve(tokenID, approvedAddress string) error {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	token, err := sc.ledger.GetToken(tokenID)
	if err != nil {
		return err
	}

	err = sc.securityManager.GrantPermission(token.Owner, approvedAddress, "manage", tokenID)
	if err != nil {
		return err
	}

	return nil
}

// Revoke revokes an address's permission to manage a SYN721 token
func (sc *Syn721SmartContract) Revoke(tokenID, revokedAddress string) error {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	token, err := sc.ledger.GetToken(tokenID)
	if err != nil {
		return err
	}

	err = sc.securityManager.RevokePermission(token.Owner, revokedAddress, "manage", tokenID)
	if err != nil {
		return err
	}

	return nil
}

// GetToken retrieves a SYN721 token by its ID
func (sc *Syn721SmartContract) GetToken(tokenID string) (assets.Syn721Token, error) {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	token, err := sc.ledger.GetToken(tokenID)
	if err != nil {
		return assets.Syn721Token{}, err
	}

	return token, nil
}

// GetTokenHistory retrieves the ownership history of a SYN721 token
func (sc *Syn721SmartContract) GetTokenHistory(tokenID string) ([]ledger.OwnershipChange, error) {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	history, err := sc.ledger.GetOwnershipHistory(tokenID)
	if err != nil {
		return nil, err
	}

	return history, nil
}

// GetTokenValuationHistory retrieves the valuation history of a SYN721 token
func (sc *Syn721SmartContract) GetTokenValuationHistory(tokenID string) ([]ledger.ValuationChange, error) {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	history, err := sc.ledger.GetValuationHistory(tokenID)
	if err != nil {
		return nil, err
	}

	return history, nil
}
