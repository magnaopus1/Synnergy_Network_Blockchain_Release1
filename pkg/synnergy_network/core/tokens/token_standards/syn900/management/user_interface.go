package management

import (
	"errors"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn900/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn900/events"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn900/factory"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn900/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn900/transactions"
)

// UserManager manages user interfaces and interactions within the SYN900 ecosystem
type UserManager struct {
	ledger          *ledger.Ledger
	eventLogger     *events.EventLogger
	tokenFactory    *factory.TokenFactory
	identityStorage *assets.IdentityMetadata
}

// NewUserManager initializes a new UserManager
func NewUserManager(ledger *ledger.Ledger, eventLogger *events.EventLogger, tokenFactory *factory.TokenFactory, identityStorage *assets.IdentityMetadata) *UserManager {
	return &UserManager{
		ledger:          ledger,
		eventLogger:     eventLogger,
		tokenFactory:    tokenFactory,
		identityStorage: identityStorage,
	}
}

// RegisterUser registers a new user and creates their identity token
func (um *UserManager) RegisterUser(userInfo assets.IdentityMetadata) (string, error) {
	tokenID, err := um.tokenFactory.CreateToken(userInfo)
	if err != nil {
		return "", err
	}

	err = um.ledger.StoreIdentity(tokenID, userInfo)
	if err != nil {
		return "", err
	}

	err = um.eventLogger.LogEvent("User Registered", tokenID, "User registration successful")
	if err != nil {
		return "", err
	}

	return tokenID, nil
}

// UpdateUser updates existing user information
func (um *UserManager) UpdateUser(tokenID string, newUserInfo assets.IdentityMetadata) error {
	existingUser, err := um.ledger.GetIdentity(tokenID)
	if err != nil {
		return err
	}

	// Check for differences and apply updates
	if newUserInfo.FullName != "" {
		existingUser.FullName = newUserInfo.FullName
	}
	if newUserInfo.DateOfBirth != "" {
		existingUser.DateOfBirth = newUserInfo.DateOfBirth
	}
	if newUserInfo.Nationality != "" {
		existingUser.Nationality = newUserInfo.Nationality
	}
	if newUserInfo.PhotographHash != "" {
		existingUser.PhotographHash = newUserInfo.PhotographHash
	}
	if newUserInfo.PhysicalAddress != "" {
		existingUser.PhysicalAddress = newUserInfo.PhysicalAddress
	}

	err = um.ledger.StoreIdentity(tokenID, *existingUser)
	if err != nil {
		return err
	}

	err = um.eventLogger.LogEvent("User Updated", tokenID, "User information updated")
	if err != nil {
		return err
	}

	return nil
}

// GetUser retrieves user information by token ID
func (um *UserManager) GetUser(tokenID string) (*assets.IdentityMetadata, error) {
	userInfo, err := um.ledger.GetIdentity(tokenID)
	if err != nil {
		return nil, err
	}
	return userInfo, nil
}

// DeleteUser removes a user and their associated identity token
func (um *UserManager) DeleteUser(tokenID string) error {
	err := um.ledger.DeleteIdentity(tokenID)
	if err != nil {
		return err
	}

	err = um.eventLogger.LogEvent("User Deleted", tokenID, "User and identity token deleted")
	if err != nil {
		return err
	}

	return nil
}

// TransferToken transfers a user's identity token to another address
func (um *UserManager) TransferToken(tokenID string, newOwnerAddress string) error {
	userInfo, err := um.ledger.GetIdentity(tokenID)
	if err != nil {
		return err
	}

	if userInfo == nil {
		return errors.New("identity token not found")
	}

	userInfo.OwnerAddress = newOwnerAddress

	err = um.ledger.StoreIdentity(tokenID, *userInfo)
	if err != nil {
		return err
	}

	err = um.eventLogger.LogEvent("Token Transferred", tokenID, "Token transferred to new owner: "+newOwnerAddress)
	if err != nil {
		return err
	}

	return nil
}

// GetUserHistory retrieves the event history for a user by token ID
func (um *UserManager) GetUserHistory(tokenID string) ([]events.Event, error) {
	history, err := um.eventLogger.GetEventsByTokenID(tokenID)
	if err != nil {
		return nil, err
	}
	return history, nil
}

// AuthenticateUser handles multi-factor authentication for a user
func (um *UserManager) AuthenticateUser(tokenID string, factors ...string) (bool, error) {
	// Placeholder for multi-factor authentication logic
	// For simplicity, let's assume that if at least one factor matches, authentication is successful
	userInfo, err := um.ledger.GetIdentity(tokenID)
	if err != nil {
		return false, err
	}

	for _, factor := range factors {
		if factor == userInfo.FullName || factor == userInfo.DateOfBirth || factor == userInfo.Nationality {
			err = um.eventLogger.LogEvent("User Authenticated", tokenID, "User authenticated successfully")
			if err != nil {
				return false, err
			}
			return true, nil
		}
	}

	return false, errors.New("authentication failed")
}

// ValidateTransaction handles the validation of a transaction involving a user's identity token
func (um *UserManager) ValidateTransaction(transaction transactions.Transaction) (bool, error) {
	// Placeholder for transaction validation logic
	// For simplicity, let's assume that if the transaction's token ID exists in the ledger, it is valid
	_, err := um.ledger.GetIdentity(transaction.TokenID)
	if err != nil {
		return false, err
	}

	err = um.eventLogger.LogEvent("Transaction Validated", transaction.TokenID, "Transaction validated successfully")
	if err != nil {
		return false, err
	}

	return true, nil
}
