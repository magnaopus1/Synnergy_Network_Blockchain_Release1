package fractional_ownership

import (
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/encryption"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3300/ledger"
)

// InvestmentOption represents an investment option for fractional ownership of an ETF
type InvestmentOption struct {
	OptionID     string    `json:"option_id"`
	ETFID        string    `json:"etf_id"`
	Description  string    `json:"description"`
	MinInvestment float64  `json:"min_investment"`
	MaxInvestment float64  `json:"max_investment"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// InvestmentOptionService provides methods to manage investment options for fractional ownership of ETFs
type InvestmentOptionService struct {
	ledgerService     *ledger.LedgerService
	encryptionService *encryption.EncryptionService
}

// NewInvestmentOptionService creates a new instance of InvestmentOptionService
func NewInvestmentOptionService(ledgerService *ledger.LedgerService, encryptionService *encryption.EncryptionService) *InvestmentOptionService {
	return &InvestmentOptionService{
		ledgerService:     ledgerService,
		encryptionService: encryptionService,
	}
}

// CreateInvestmentOption creates a new investment option for fractional ownership of an ETF
func (s *InvestmentOptionService) CreateInvestmentOption(etfID, description string, minInvestment, maxInvestment float64) (*InvestmentOption, error) {
	if etfID == "" || description == "" || minInvestment <= 0 || maxInvestment <= 0 || minInvestment > maxInvestment {
		return nil, errors.New("invalid input parameters")
	}

	option := &InvestmentOption{
		OptionID:      generateOptionID(etfID, description),
		ETFID:         etfID,
		Description:   description,
		MinInvestment: minInvestment,
		MaxInvestment: maxInvestment,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	// Encrypt the investment option
	encryptedOption, err := s.encryptionService.EncryptData(option)
	if err != nil {
		return nil, err
	}

	// Record the investment option in the ledger
	if err := s.ledgerService.RecordInvestmentOption(encryptedOption); err != nil {
		return nil, err
	}

	return option, nil
}

// UpdateInvestmentOption updates an existing investment option
func (s *InvestmentOptionService) UpdateInvestmentOption(optionID, description string, minInvestment, maxInvestment float64) (*InvestmentOption, error) {
	if optionID == "" || description == "" || minInvestment <= 0 || maxInvestment <= 0 || minInvestment > maxInvestment {
		return nil, errors.New("invalid input parameters")
	}

	// Retrieve the existing option from the ledger
	option, err := s.ledgerService.GetInvestmentOption(optionID)
	if err != nil {
		return nil, err
	}

	// Update the option details
	option.Description = description
	option.MinInvestment = minInvestment
	option.MaxInvestment = maxInvestment
	option.UpdatedAt = time.Now()

	// Encrypt the updated option
	encryptedOption, err := s.encryptionService.EncryptData(option)
	if err != nil {
		return nil, err
	}

	// Update the option in the ledger
	if err := s.ledgerService.UpdateInvestmentOption(optionID, encryptedOption); err != nil {
		return nil, err
	}

	return option, nil
}

// GetInvestmentOption retrieves an investment option by its ID
func (s *InvestmentOptionService) GetInvestmentOption(optionID string) (*InvestmentOption, error) {
	if optionID == "" {
		return nil, errors.New("invalid input parameters")
	}

	// Retrieve the encrypted option from the ledger
	encryptedOption, err := s.ledgerService.GetInvestmentOption(optionID)
	if err != nil {
		return nil, err
	}

	// Decrypt the option
	option, err := s.encryptionService.DecryptData(encryptedOption)
	if err != nil {
		return nil, err
	}

	return option, nil
}

// ListAllInvestmentOptions retrieves all investment options for a given ETF
func (s *InvestmentOptionService) ListAllInvestmentOptions(etfID string) ([]*InvestmentOption, error) {
	if etfID == "" {
		return nil, errors.New("invalid input parameters")
	}

	// Retrieve all encrypted options from the ledger
	encryptedOptions, err := s.ledgerService.GetAllInvestmentOptions(etfID)
	if err != nil {
		return nil, err
	}

	var options []*InvestmentOption
	for _, encryptedOption := range encryptedOptions {
		option, err := s.encryptionService.DecryptData(encryptedOption)
		if err != nil {
			return nil, err
		}
		options = append(options, option)
	}

	return options, nil
}

// generateOptionID generates a unique option ID based on the ETF ID and description
func generateOptionID(etfID, description string) string {
	data := etfID + description + time.Now().String()
	return hash(data)
}

// hash generates a hash of the given data
func hash(data string) string {
	hash := sha256.New()
	hash.Write([]byte(data))
	return hex.EncodeToString(hash.Sum(nil))
}

// EncryptionService handles encryption-related operations
type EncryptionService struct{}

// EncryptData encrypts the given data using the most secure method for the situation
func (e *EncryptionService) EncryptData(data interface{}) (string, error) {
	serializedData, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	encryptedData, err := encryption.Argon2Encrypt(serializedData)
	if err != nil {
		return "", err
	}
	return encryptedData, nil
}

// DecryptData decrypts the given data using the most secure method for the situation
func (e *EncryptionService) DecryptData(encryptedData string) (*InvestmentOption, error) {
	decryptedData, err := encryption.Argon2Decrypt(encryptedData)
	if err != nil {
		return nil, err
	}

	var option InvestmentOption
	if err := json.Unmarshal([]byte(decryptedData), &option); err != nil {
		return nil, err
	}

	return &option, nil
}
