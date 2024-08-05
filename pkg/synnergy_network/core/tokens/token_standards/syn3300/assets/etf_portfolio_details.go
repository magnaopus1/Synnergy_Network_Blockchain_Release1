package assets

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/encryption"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3300/ledger"
)

// ETFPortfolioDetails represents the detailed information of an ETF portfolio
type ETFPortfolioDetails struct {
	ETFID           string    `json:"etf_id"`
	Name            string    `json:"name"`
	TotalShares     int       `json:"total_shares"`
	AvailableShares int       `json:"available_shares"`
	CurrentPrice    float64   `json:"current_price"`
	Holdings        []Holding `json:"holdings"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// Holding represents a single holding in the ETF portfolio
type Holding struct {
	AssetID   string  `json:"asset_id"`
	AssetName string  `json:"asset_name"`
	Quantity  int     `json:"quantity"`
	Value     float64 `json:"value"`
}

// ETFPortfolioService provides methods to manage ETF portfolio details
type ETFPortfolioService struct {
	ledgerService     *ledger.LedgerService
	encryptionService *encryption.EncryptionService
}

// NewETFPortfolioService creates a new instance of ETFPortfolioService
func NewETFPortfolioService(ledgerService *ledger.LedgerService, encryptionService *encryption.EncryptionService) *ETFPortfolioService {
	return &ETFPortfolioService{
		ledgerService:     ledgerService,
		encryptionService: encryptionService,
	}
}

// CreateETFPortfolio creates a new ETF portfolio record
func (s *ETFPortfolioService) CreateETFPortfolio(etfID, name string, totalShares, availableShares int, currentPrice float64, holdings []Holding) (*ETFPortfolioDetails, error) {
	if etfID == "" || name == "" || totalShares <= 0 || availableShares < 0 || currentPrice <= 0 {
		return nil, errors.New("invalid input parameters")
	}

	portfolio := &ETFPortfolioDetails{
		ETFID:           etfID,
		Name:            name,
		TotalShares:     totalShares,
		AvailableShares: availableShares,
		CurrentPrice:    currentPrice,
		Holdings:        holdings,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	encryptedPortfolio, err := s.encryptionService.EncryptData(portfolio)
	if err != nil {
		return nil, err
	}

	if err := s.ledgerService.RecordETFPortfolio(encryptedPortfolio); err != nil {
		return nil, err
	}

	return portfolio, nil
}

// UpdateETFPortfolio updates an existing ETF portfolio record
func (s *ETFPortfolioService) UpdateETFPortfolio(etfID string, availableShares int, currentPrice float64, holdings []Holding) (*ETFPortfolioDetails, error) {
	if etfID == "" || availableShares < 0 || currentPrice <= 0 {
		return nil, errors.New("invalid input parameters")
	}

	encryptedPortfolio, err := s.ledgerService.GetETFPortfolio(etfID)
	if err != nil {
		return nil, err
	}

	portfolio, err := s.encryptionService.DecryptData(encryptedPortfolio)
	if err != nil {
		return nil, err
	}

	portfolio.AvailableShares = availableShares
	portfolio.CurrentPrice = currentPrice
	portfolio.Holdings = holdings
	portfolio.UpdatedAt = time.Now()

	updatedEncryptedPortfolio, err := s.encryptionService.EncryptData(portfolio)
	if err != nil {
		return nil, err
	}

	if err := s.ledgerService.UpdateETFPortfolio(etfID, updatedEncryptedPortfolio); err != nil {
		return nil, err
	}

	return portfolio, nil
}

// GetETFPortfolio retrieves the portfolio details of an ETF by its ID
func (s *ETFPortfolioService) GetETFPortfolio(etfID string) (*ETFPortfolioDetails, error) {
	if etfID == "" {
		return nil, errors.New("invalid input parameters")
	}

	encryptedPortfolio, err := s.ledgerService.GetETFPortfolio(etfID)
	if err != nil {
		return nil, err
	}

	portfolio, err := s.encryptionService.DecryptData(encryptedPortfolio)
	if err != nil {
		return nil, err
	}

	return portfolio, nil
}

// ListAllETFs retrieves a list of all ETFs with their basic details
func (s *ETFPortfolioService) ListAllETFs() ([]*ETFPortfolioDetails, error) {
	encryptedPortfolios, err := s.ledgerService.GetAllETFPortfolios()
	if err != nil {
		return nil, err
	}

	var portfolios []*ETFPortfolioDetails
	for _, encryptedPortfolio := range encryptedPortfolios {
		portfolio, err := s.encryptionService.DecryptData(encryptedPortfolio)
		if err != nil {
			return nil, err
		}
		portfolios = append(portfolios, portfolio)
	}

	return portfolios, nil
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
func (e *EncryptionService) DecryptData(encryptedData string) (*ETFPortfolioDetails, error) {
	decryptedData, err := encryption.Argon2Decrypt(encryptedData)
	if err != nil {
		return nil, err
	}

	var portfolio ETFPortfolioDetails
	if err := json.Unmarshal([]byte(decryptedData), &portfolio); err != nil {
		return nil, err
	}

	return &portfolio, nil
}
