package factory

import (
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/security"
)

// TokenFactory manages the creation and initialization of SYN3100 tokens.
type TokenFactory struct {
	contractLinking       *assets.ContractLinking
	employmentMetadata    *assets.EmploymentMetadataStore
	ownershipVerification *assets.OwnershipVerificationStore
	transactionLedger     *ledger.TransactionLedger
	secureStorage         *security.SecureStorage
}

// NewTokenFactory initializes a new TokenFactory instance.
func NewTokenFactory() *TokenFactory {
	return &TokenFactory{
		contractLinking:       assets.NewContractLinking(),
		employmentMetadata:    assets.NewEmploymentMetadataStore(),
		ownershipVerification: assets.NewOwnershipVerificationStore(),
		transactionLedger:     ledger.NewTransactionLedger(),
		secureStorage:         security.NewSecureStorage(),
	}
}

// CreateEmploymentContract creates a new employment contract token.
func (tf *TokenFactory) CreateEmploymentContract(metadata assets.EmploymentMetadata) (string, error) {
	if err := assets.ValidateContractMetadata(metadata); err != nil {
		return "", err
	}

	contractID, err := tf.contractLinking.CreateContract(metadata)
	if err != nil {
		return "", err
	}

	eventData := "Employment contract created."
	_, err = tf.transactionLedger.RecordEvent(contractID, metadata.EmployeeID, "ContractCreated", eventData)
	if err != nil {
		return "", err
	}

	return contractID, nil
}

// VerifyOwnership verifies the ownership of a contract.
func (tf *TokenFactory) VerifyOwnership(contractID, employeeID string) (bool, error) {
	isOwner, err := tf.contractLinking.VerifyOwnership(contractID, employeeID)
	if err != nil {
		return false, err
	}

	if isOwner {
		verificationToken, err := tf.ownershipVerification.VerifyOwnership(contractID, employeeID)
		if err != nil {
			return false, err
		}

		eventData := "Ownership verified."
		_, err = tf.transactionLedger.RecordEvent(contractID, employeeID, "OwnershipVerified", eventData)
		if err != nil {
			return false, err
		}
		tf.secureStorage.Store(verificationToken, contractID)
		return true, nil
	}
	return false, errors.New("ownership verification failed")
}

// UpdateEmploymentContract updates an existing employment contract.
func (tf *TokenFactory) UpdateEmploymentContract(contractID string, updatedMetadata assets.EmploymentMetadata) error {
	if err := assets.ValidateContractMetadata(updatedMetadata); err != nil {
		return err
	}

	err := tf.contractLinking.UpdateContract(contractID, updatedMetadata)
	if err != nil {
		return err
	}

	eventData := "Employment contract updated."
	_, err = tf.transactionLedger.RecordEvent(contractID, updatedMetadata.EmployeeID, "ContractUpdated", eventData)
	if err != nil {
		return err
	}

	return nil
}

// DeleteEmploymentContract deletes an employment contract.
func (tf *TokenFactory) DeleteEmploymentContract(contractID, employeeID string) error {
	err := tf.contractLinking.DeleteContract(contractID)
	if err != nil {
		return err
	}

	eventData := "Employment contract deleted."
	_, err = tf.transactionLedger.RecordEvent(contractID, employeeID, "ContractDeleted", eventData)
	if err != nil {
		return err
	}

	return nil
}

// RecordWagePayment records a wage payment event.
func (tf *TokenFactory) RecordWagePayment(contractID, employeeID string, amount float64) (string, error) {
	eventData := "Wage payment made."
	eventID, err := tf.transactionLedger.RecordEvent(contractID, employeeID, "WagePaymentMade", eventData)
	if err != nil {
		return "", err
	}

	return eventID, nil
}

// RecordBenefitGrant records a benefit grant event.
func (tf *TokenFactory) RecordBenefitGrant(contractID, employeeID, benefit string) (string, error) {
	eventData := "Benefit granted: " + benefit
	eventID, err := tf.transactionLedger.RecordEvent(contractID, employeeID, "BenefitGranted", eventData)
	if err != nil {
		return "", err
	}

	return eventID, nil
}

// RecordBonusIssue records a bonus issuance event.
func (tf *TokenFactory) RecordBonusIssue(contractID, employeeID string, bonusAmount float64) (string, error) {
	eventData := "Bonus issued."
	eventID, err := tf.transactionLedger.RecordEvent(contractID, employeeID, "BonusIssued", eventData)
	if err != nil {
		return "", err
	}

	return eventID, nil
}

// RecordPerformanceReview records a performance review event.
func (tf *TokenFactory) RecordPerformanceReview(contractID, employeeID, reviewData string) (string, error) {
	eventData := "Performance review recorded: " + reviewData
	eventID, err := tf.transactionLedger.RecordEvent(contractID, employeeID, "PerformanceReviewed", eventData)
	if err != nil {
		return "", err
	}

	return eventID, nil
}

// EncryptAndStoreContractMetadata encrypts and stores contract metadata securely.
func (tf *TokenFactory) EncryptAndStoreContractMetadata(contractID, password string) (string, error) {
	metadata, err := tf.contractLinking.GetContract(contractID)
	if err != nil {
		return "", err
	}

	encryptedMetadata, err := assets.EncryptContractMetadata(metadata, password)
	if err != nil {
		return "", err
	}

	tf.secureStorage.Store(contractID, encryptedMetadata)
	return encryptedMetadata, nil
}

// DecryptContractMetadata decrypts contract metadata.
func (tf *TokenFactory) DecryptContractMetadata(encryptedData, password string) (assets.EmploymentMetadata, error) {
	metadata, err := assets.DecryptContractMetadata(encryptedData, password)
	if err != nil {
		return assets.EmploymentMetadata{}, err
	}

	return metadata, nil
}

// GenerateComplianceReport generates a compliance report for a specific contract.
func (tf *TokenFactory) GenerateComplianceReport(contractID string) (string, error) {
	events, err := tf.transactionLedger.GetEventsByContract(contractID)
	if err != nil {
		return "", err
	}

	report := "Compliance Report for Contract ID: " + contractID + "\n"
	for _, event := range events {
		report += "Event ID: " + event.EventID + ", Event Type: " + string(event.EventType) + ", Timestamp: " + event.Timestamp.String() + ", Event Data: " + event.EventData + "\n"
	}

	return report, nil
}

// TransferOwnership transfers ownership of an employment contract.
func (tf *TokenFactory) TransferOwnership(contractID, newEmployeeID string) error {
	contract, err := tf.contractLinking.GetContract(contractID)
	if err != nil {
		return err
	}

	contract.EmployeeID = newEmployeeID
	err = tf.contractLinking.UpdateContract(contractID, contract)
	if err != nil {
		return err
	}

	eventData := "Ownership transferred to new employee ID: " + newEmployeeID
	_, err = tf.transactionLedger.RecordEvent(contractID, newEmployeeID, "OwnershipTransferred", eventData)
	if err != nil {
		return err
	}

	return nil
}

// ValidateContract validates an employment contract by ensuring all required fields are correctly populated.
func (tf *TokenFactory) ValidateContract(contractID string) error {
	contract, err := tf.contractLinking.GetContract(contractID)
	if err != nil {
		return err
	}

	return assets.ValidateContractMetadata(contract)
}
