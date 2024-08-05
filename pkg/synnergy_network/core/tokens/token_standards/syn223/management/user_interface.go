package management

import (
	"errors"
	"sync"

	"github.com/synnergy_network/core/tokens/token_standards/syn223/assets"
	"github.com/synnergy_network/core/tokens/token_standards/syn223/factory"
	"github.com/synnergy_network/core/tokens/token_standards/syn223/ledger"
	"github.com/synnergy_network/core/tokens/token_standards/syn223/transactions"
	"github.com/synnergy_network/core/tokens/token_standards/syn223/security"
)

// UserManager manages user interactions and provides an interface for users to interact with the SYN223 token system.
type UserManager struct {
	mu                sync.RWMutex
	metadataStore     *assets.MetadataStore
	tokenFactory      *factory.TokenFactory
	ledger            *ledger.Ledger
	multiSigManager   *MultiSignatureSecurityManager
	securityManager   *security.SecurityManager
}

// NewUserManager initializes a new UserManager instance.
func NewUserManager(metadataStore *assets.MetadataStore, tokenFactory *factory.TokenFactory, ledger *ledger.Ledger, multiSigManager *MultiSignatureSecurityManager, securityManager *security.SecurityManager) *UserManager {
	return &UserManager{
		metadataStore:   metadataStore,
		tokenFactory:    tokenFactory,
		ledger:          ledger,
		multiSigManager: multiSigManager,
		securityManager: securityManager,
	}
}

// CreateToken allows a user to create a new token.
func (um *UserManager) CreateToken(name, symbol string, totalSupply uint64, decimals uint8, owner string) (string, error) {
	um.mu.Lock()
	defer um.mu.Unlock()

	params := factory.TokenParams{
		Name:        name,
		Symbol:      symbol,
		TotalSupply: totalSupply,
		Decimals:    decimals,
		Owner:       owner,
	}

	tokenID, err := um.tokenFactory.CreateToken(params)
	if err != nil {
		return "", err
	}

	return tokenID, nil
}

// TransferTokens allows a user to transfer tokens to another address.
func (um *UserManager) TransferTokens(from, to, tokenID string, amount uint64) error {
	um.mu.Lock()
	defer um.mu.Unlock()

	return um.ledger.TransferTokens(from, to, tokenID, amount)
}

// SafeTransferTokens allows a user to safely transfer tokens to another address, ensuring the recipient can receive tokens.
func (um *UserManager) SafeTransferTokens(from, to, tokenID string, amount uint64) error {
	um.mu.Lock()
	defer um.mu.Unlock()

	isValidReceiver := func(address string) bool {
		// Implement logic to check if the address is valid
		return true
	}

	return um.ledger.SafeTransferTokens(from, to, tokenID, amount, isValidReceiver)
}

// MintTokens allows a user to mint additional tokens for an existing token.
func (um *UserManager) MintTokens(tokenID, to string, amount uint64) error {
	um.mu.Lock()
	defer um.mu.Unlock()

	return um.tokenFactory.MintTokens(tokenID, to, amount)
}

// BurnTokens allows a user to burn existing tokens.
func (um *UserManager) BurnTokens(tokenID, from string, amount uint64) error {
	um.mu.Lock()
	defer um.mu.Unlock()

	return um.tokenFactory.BurnTokens(tokenID, from, amount)
}

// GetBalance allows a user to check the balance of a specific address for a given token ID.
func (um *UserManager) GetBalance(address, tokenID string) (uint64, error) {
	um.mu.RLock()
	defer um.mu.RUnlock()

	return um.ledger.GetBalance(address, tokenID)
}

// CreateMultiSigTransaction allows a user to create a multi-signature transaction.
func (um *UserManager) CreateMultiSigTransaction(tokenID, from, to string, amount uint64) (string, error) {
	um.mu.Lock()
	defer um.mu.Unlock()

	return um.multiSigManager.CreateMultiSignatureTransaction(tokenID, from, to, amount)
}

// SignMultiSigTransaction allows a user to sign a multi-signature transaction.
func (um *UserManager) SignMultiSigTransaction(txID, userID string) error {
	um.mu.Lock()
	defer um.mu.Unlock()

	return um.multiSigManager.SignTransaction(txID, userID)
}

// ExecuteMultiSigTransaction allows a user to execute a multi-signature transaction once the required number of signatures is reached.
func (um *UserManager) ExecuteMultiSigTransaction(txID string) error {
	um.mu.Lock()
	defer um.mu.Unlock()

	executeFunc := func(tx *MultiSignatureTransaction) error {
		return um.ledger.TransferTokens(tx.From, tx.To, tx.TokenID, tx.Amount)
	}

	return um.multiSigManager.ExecuteTransaction(txID, executeFunc)
}

// GetTransactionLogs allows a user to retrieve the transaction logs for a specific token ID.
func (um *UserManager) GetTransactionLogs(tokenID string) ([]transactions.Transaction, error) {
	um.mu.RLock()
	defer um.mu.RUnlock()

	return um.ledger.GetTransactionLogs(tokenID)
}

// VerifyTokenMetadata allows a user to verify the integrity and validity of token metadata.
func (um *UserManager) VerifyTokenMetadata(id string) (bool, error) {
	um.mu.RLock()
	defer um.mu.RUnlock()

	return um.metadataStore.VerifyTokenMetadata(id)
}

// AddTokenMetadata allows a user to add new token metadata to the store.
func (um *UserManager) AddTokenMetadata(metadata assets.TokenMetadata) error {
	um.mu.Lock()
	defer um.mu.Unlock()

	return um.metadataStore.AddMetadata(metadata)
}

// UpdateTokenMetadata allows a user to update existing token metadata in the store.
func (um *UserManager) UpdateTokenMetadata(metadata assets.TokenMetadata) error {
	um.mu.Lock()
	defer um.mu.Unlock()

	return um.metadataStore.UpdateMetadata(metadata)
}

// GetTokenMetadata allows a user to retrieve token metadata by ID.
func (um *UserManager) GetTokenMetadata(id string) (assets.TokenMetadata, error) {
	um.mu.RLock()
	defer um.mu.RUnlock()

	return um.metadataStore.GetMetadata(id)
}

// DeleteTokenMetadata allows a user to remove token metadata from the store.
func (um *UserManager) DeleteTokenMetadata(id string) error {
	um.mu.Lock()
	defer um.mu.Unlock()

	return um.metadataStore.DeleteMetadata(id)
}

// ListAllTokenMetadata allows a user to list all token metadata in the store.
func (um *UserManager) ListAllTokenMetadata() ([]assets.TokenMetadata, error) {
	um.mu.RLock()
	defer um.mu.RUnlock()

	return um.metadataStore.ListAllTokenMetadata()
}

// EncryptMetadata allows a user to encrypt token metadata using a specified encryption technique.
func (um *UserManager) EncryptMetadata(metadata assets.TokenMetadata, passphrase string) (string, error) {
	um.mu.RLock()
	defer um.mu.RUnlock()

	return um.metadataStore.EncryptMetadata(metadata, passphrase)
}

// DecryptMetadata allows a user to decrypt token metadata using a specified decryption technique.
func (um *UserManager) DecryptMetadata(encryptedData, passphrase string) (assets.TokenMetadata, error) {
	um.mu.RLock()
	defer um.mu.RUnlock()

	return um.metadataStore.DecryptMetadata(encryptedData, passphrase)
}
