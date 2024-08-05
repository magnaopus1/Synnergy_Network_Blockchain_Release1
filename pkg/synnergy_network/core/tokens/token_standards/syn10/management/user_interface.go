package management

import (
	"errors"
	"fmt"
	"time"

	"github.com/synnergy_network_blockchain/core/tokens/syn10/compliance"
	"github.com/synnergy_network_blockchain/core/tokens/syn10/ledger"
	"github.com/synnergy_network_blockchain/core/tokens/syn10/security"
	"github.com/synnergy_network_blockchain/core/tokens/syn10/smart_contracts"
	"github.com/synnergy_network_blockchain/core/tokens/syn10/storage"
	"github.com/synnergy_network_blockchain/core/tokens/syn10/transactions"
)

// UserInterface provides functionalities for end-users to interact with the blockchain.
type UserInterface struct {
	store            storage.Storage
	ledger           ledger.Ledger
	compliance       compliance.ComplianceManager
	contractManager  *SmartContractManager
	transactionManager transactions.TransactionManager
}

// NewUserInterface initializes a new UserInterface.
func NewUserInterface(store storage.Storage, ledger ledger.Ledger, compliance compliance.ComplianceManager, contractManager *SmartContractManager, transactionManager transactions.TransactionManager) *UserInterface {
	return &UserInterface{
		store:            store,
		ledger:           ledger,
		compliance:       compliance,
		contractManager:  contractManager,
		transactionManager: transactionManager,
	}
}

// ViewBalance allows users to view their balance for a specific token.
func (ui *UserInterface) ViewBalance(userID, tokenID string) (float64, error) {
	balance, err := ui.ledger.GetBalance(userID, tokenID)
	if err != nil {
		return 0, err
	}
	return balance, nil
}

// TransferTokens allows users to transfer tokens to another user.
func (ui *UserInterface) TransferTokens(fromUserID, toUserID, tokenID string, amount float64) (string, error) {
	if amount <= 0 {
		return "", errors.New("amount must be greater than zero")
	}

	if !ui.compliance.VerifyUser(fromUserID) || !ui.compliance.VerifyUser(toUserID) {
		return "", errors.New("user verification failed")
	}

	transactionID, err := ui.transactionManager.CreateTransaction(fromUserID, toUserID, tokenID, amount)
	if err != nil {
		return "", err
	}

	err = ui.ledger.UpdateBalances(fromUserID, toUserID, tokenID, amount)
	if err != nil {
		return "", err
	}

	return transactionID, nil
}

// ViewTransactionHistory allows users to view their transaction history.
func (ui *UserInterface) ViewTransactionHistory(userID string) ([]transactions.Transaction, error) {
	history, err := ui.ledger.GetTransactionHistory(userID)
	if err != nil {
		return nil, err
	}
	return history, nil
}

// ExecuteSmartContract allows users to interact with smart contracts.
func (ui *UserInterface) ExecuteSmartContract(contractID, functionName string, params map[string]interface{}) (interface{}, error) {
	contract, err := ui.contractManager.GetContractDetails(contractID)
	if err != nil {
		return nil, err
	}

	if !ui.compliance.VerifyUser(contract.DeployedAddress) {
		return nil, errors.New("contract owner verification failed")
	}

	result, err := smart_contracts.ExecuteFunction(contract.DeployedAddress, functionName, params)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// ComplianceCheck runs a compliance check for a given user and token.
func (ui *UserInterface) ComplianceCheck(userID, tokenID string) (bool, error) {
	compliant, err := ui.compliance.CheckCompliance(userID, tokenID)
	if err != nil {
		return false, err
	}
	return compliant, nil
}

// GetSmartContractAuditReport retrieves the audit report for a specific smart contract.
func (ui *UserInterface) GetSmartContractAuditReport(contractID string) (security.AuditReport, error) {
	contract, err := ui.contractManager.GetContractDetails(contractID)
	if err != nil {
		return security.AuditReport{}, err
	}

	return contract.AuditReport, nil
}

// generateUserID generates a unique user ID.
func generateUserID(name, email string) string {
	return fmt.Sprintf("%s-%x", name, security.HashString(email))
}

// RegisterUser registers a new user in the system.
func (ui *UserInterface) RegisterUser(name, email string) (string, error) {
	userID := generateUserID(name, email)
	if ui.store.Exists(userID) {
		return "", errors.New("user already exists")
	}

	err := ui.store.Save(userID, map[string]interface{}{
		"name":  name,
		"email": email,
	})
	if err != nil {
		return "", err
	}

	return userID, nil
}

// DeleteUser removes a user from the system.
func (ui *UserInterface) DeleteUser(userID string) error {
	if !ui.store.Exists(userID) {
		return errors.New("user not found")
	}

	err := ui.store.Delete(userID)
	if err != nil {
		return err
	}

	return nil
}
