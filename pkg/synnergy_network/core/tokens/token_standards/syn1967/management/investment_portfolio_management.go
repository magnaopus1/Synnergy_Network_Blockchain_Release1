package management

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/argon2"
	"pkg/synnergy_network/core/tokens/token_standards/syn1967/assets"
)

// Investment represents an investment in a particular token
type Investment struct {
	InvestmentID string
	TokenID      string
	Investor     string
	Amount       float64
	InvestedAt   time.Time
}

// Portfolio represents an investor's portfolio
type Portfolio struct {
	Investor    string
	Investments []Investment
}

// InvestmentPortfolioManager manages investment portfolios
type InvestmentPortfolioManager struct {
	portfolios map[string]Portfolio
}

// NewInvestmentPortfolioManager creates a new investment portfolio manager
func NewInvestmentPortfolioManager() *InvestmentPortfolioManager {
	return &InvestmentPortfolioManager{portfolios: make(map[string]Portfolio)}
}

// AddInvestment adds an investment to an investor's portfolio
func (ipm *InvestmentPortfolioManager) AddInvestment(investmentID, tokenID, investor string, amount float64) (Investment, error) {
	investment := Investment{
		InvestmentID: investmentID,
		TokenID:      tokenID,
		Investor:     investor,
		Amount:       amount,
		InvestedAt:   time.Now(),
	}

	portfolio, exists := ipm.portfolios[investor]
	if !exists {
		portfolio = Portfolio{
			Investor:    investor,
			Investments: []Investment{},
		}
	}

	portfolio.Investments = append(portfolio.Investments, investment)
	ipm.portfolios[investor] = portfolio
	return investment, nil
}

// GetPortfolio retrieves an investor's portfolio
func (ipm *InvestmentPortfolioManager) GetPortfolio(investor string) (Portfolio, error) {
	portfolio, exists := ipm.portfolios[investor]
	if !exists {
		return Portfolio{}, errors.New("portfolio not found")
	}
	return portfolio, nil
}

// ListPortfolios lists all portfolios
func (ipm *InvestmentPortfolioManager) ListPortfolios() ([]Portfolio, error) {
	var portfolios []Portfolio
	for _, portfolio := range ipm.portfolios {
		portfolios = append(portfolios, portfolio)
	}
	return portfolios, nil
}

// RemoveInvestment removes an investment from an investor's portfolio
func (ipm *InvestmentPortfolioManager) RemoveInvestment(investor, investmentID string) error {
	portfolio, exists := ipm.portfolios[investor]
	if !exists {
		return errors.New("portfolio not found")
	}

	for i, investment := range portfolio.Investments {
		if investment.InvestmentID == investmentID {
			portfolio.Investments = append(portfolio.Investments[:i], portfolio.Investments[i+1:]...)
			ipm.portfolios[investor] = portfolio
			return nil
		}
	}
	return errors.New("investment not found")
}

// SecureStorage handles secure storage of data
type SecureStorage struct {
	key []byte
}

// NewSecureStorage creates a new secure storage with a key
func NewSecureStorage(password string) *SecureStorage {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		panic(err)
	}

	key := argon2.Key([]byte(password), salt, 3, 32*1024, 4, 32)
	return &SecureStorage{key: key}
}

// Encrypt encrypts data using AES
func (s *SecureStorage) Encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)

	return ciphertext, nil
}

// Decrypt decrypts data using AES
func (s *SecureStorage) Decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}

	if len(data) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}

// SecurePortfolioData securely stores portfolio data
func (ipm *InvestmentPortfolioManager) SecurePortfolioData(secureStorage *SecureStorage) (string, error) {
	jsonData, err := json.Marshal(ipm.portfolios)
	if err != nil {
		return "", err
	}

	encryptedData, err := secureStorage.Encrypt(jsonData)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", encryptedData), nil
}

// RetrievePortfolioData retrieves and decrypts portfolio data
func (ipm *InvestmentPortfolioManager) RetrievePortfolioData(encryptedDataHex string, secureStorage *SecureStorage) error {
	encryptedData, err := hex.DecodeString(encryptedDataHex)
	if err != nil {
		return err
	}

	jsonData, err := secureStorage.Decrypt(encryptedData)
	if err != nil {
		return err
	}

	var portfolios map[string]Portfolio
	err = json.Unmarshal(jsonData, &portfolios)
	if err != nil {
		return err
	}

	ipm.portfolios = portfolios
	return nil
}

// GeneratePortfolioReport generates a report for all portfolios
func (ipm *InvestmentPortfolioManager) GeneratePortfolioReport() (string, error) {
	report := "Portfolio Report\n"
	report += "----------------\n"

	for _, portfolio := range ipm.portfolios {
		report += fmt.Sprintf("Investor: %s\nInvestments:\n", portfolio.Investor)
		for _, investment := range portfolio.Investments {
			report += fmt.Sprintf("  - Investment ID: %s\n    Token ID: %s\n    Amount: %f\n    Invested At: %s\n",
				investment.InvestmentID, investment.TokenID, investment.Amount, investment.InvestedAt.String())
		}
		report += "\n"
	}

	return report, nil
}
