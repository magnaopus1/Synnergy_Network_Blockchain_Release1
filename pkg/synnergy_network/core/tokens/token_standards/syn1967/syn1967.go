package syn1967

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/argon2"
)

// SYN1967Token represents a commodity token with extended attributes for real-world use
type SYN1967Token struct {
	TokenID          string
	CommodityName    string
	Amount           float64
	UnitOfMeasure    string
	PricePerUnit     float64
	IssuedDate       time.Time
	Owner            string
	Certification    string
	Traceability     string
	AuditTrail       []AuditRecord
	Origin           string
	ExpiryDate       time.Time
	CollateralStatus string
	Fractionalized   bool
}

// AuditRecord represents a record of significant events
type AuditRecord struct {
	Timestamp time.Time
	Event     string
	Details   string
}

// SYN1967TokenManager manages SYN1967 tokens
type SYN1967TokenManager struct {
	tokens map[string]SYN1967Token
}

// NewSYN1967TokenManager creates a new token manager
func NewSYN1967TokenManager() *SYN1967TokenManager {
	return &SYN1967TokenManager{tokens: make(map[string]SYN1967Token)}
}

// CreateToken creates a new SYN1967 token
func (m *SYN1967TokenManager) CreateToken(tokenID, commodityName string, amount float64, unitOfMeasure string, pricePerUnit float64, owner, certification, traceability, origin string, expiryDate time.Time, fractionalized bool) (SYN1967Token, error) {
	token := SYN1967Token{
		TokenID:          tokenID,
		CommodityName:    commodityName,
		Amount:           amount,
		UnitOfMeasure:    unitOfMeasure,
		PricePerUnit:     pricePerUnit,
		IssuedDate:       time.Now(),
		Owner:            owner,
		Certification:    certification,
		Traceability:     traceability,
		AuditTrail:       []AuditRecord{},
		Origin:           origin,
		ExpiryDate:       expiryDate,
		CollateralStatus: "active",
		Fractionalized:   fractionalized,
	}

	m.tokens[tokenID] = token
	return token, nil
}

// GetToken retrieves a token by its ID
func (m *SYN1967TokenManager) GetToken(tokenID string) (SYN1967Token, error) {
	token, exists := m.tokens[tokenID]
	if !exists {
		return SYN1967Token{}, errors.New("token not found")
	}
	return token, nil
}

// TransferToken transfers ownership of a token
func (m *SYN1967TokenManager) TransferToken(tokenID, newOwner string) error {
	token, exists := m.tokens[tokenID]
	if !exists {
		return errors.New("token not found")
	}

	token.Owner = newOwner
	token.AuditTrail = append(token.AuditTrail, AuditRecord{
		Timestamp: time.Now(),
		Event:     "Transfer",
		Details:   fmt.Sprintf("Token transferred to %s", newOwner),
	})
	m.tokens[tokenID] = token
	return nil
}

// AdjustPrice adjusts the price of a token based on market conditions
func (m *SYN1967TokenManager) AdjustPrice(tokenID string, newPricePerUnit float64) error {
	token, exists := m.tokens[tokenID]
	if !exists {
		return errors.New("token not found")
	}

	token.PricePerUnit = newPricePerUnit
	token.AuditTrail = append(token.AuditTrail, AuditRecord{
		Timestamp: time.Now(),
		Event:     "Price Adjustment",
		Details:   fmt.Sprintf("Price adjusted to %f", newPricePerUnit),
	})
	m.tokens[tokenID] = token
	return nil
}

// EncodeToJSON encodes a token to JSON
func (m *SYN1967TokenManager) EncodeToJSON(tokenID string) (string, error) {
	token, exists := m.tokens[tokenID]
	if !exists {
		return "", errors.New("token not found")
	}

	jsonData, err := json.Marshal(token)
	if err != nil {
		return "", err
	}

	return string(jsonData), nil
}

// DecodeFromJSON decodes a token from JSON
func (m *SYN1967TokenManager) DecodeFromJSON(jsonData string) (SYN1967Token, error) {
	var token SYN1967Token
	err := json.Unmarshal([]byte(jsonData), &token)
	if err != nil {
		return SYN1967Token{}, err
	}

	m.tokens[token.TokenID] = token
	return token, nil
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

// Transaction represents a transaction
type Transaction struct {
	TxID         string
	TokenID      string
	From         string
	To           string
	Amount       float64
	Timestamp    time.Time
	Signature    string
	Validated    bool
}

// TransactionManager manages transactions
type TransactionManager struct {
	transactions map[string]Transaction
}

// NewTransactionManager creates a new transaction manager
func NewTransactionManager() *TransactionManager {
	return &TransactionManager{transactions: make(map[string]Transaction)}
}

// CreateTransaction creates a new transaction
func (tm *TransactionManager) CreateTransaction(txID, tokenID, from, to string, amount float64, privateKey string) (Transaction, error) {
	tx := Transaction{
		TxID:      txID,
		TokenID:   tokenID,
		From:      from,
		To:        to,
		Amount:    amount,
		Timestamp: time.Now(),
	}

	message := fmt.Sprintf("%s:%s:%s:%f:%s", txID, tokenID, from, amount, to)
	hash := sha256.Sum256([]byte(message))
	signature, err := crypto.Sign(hash[:], privateKey)
	if err != nil {
		return Transaction{}, err
	}

	tx.Signature = fmt.Sprintf("%x", signature)
	tm.transactions[txID] = tx
	return tx, nil
}

// ValidateTransaction validates a transaction
func (tm *TransactionManager) ValidateTransaction(txID string, publicKey string) (bool, error) {
	tx, exists := tm.transactions[txID]
	if !exists {
		return false, errors.New("transaction not found")
	}

	message := fmt.Sprintf("%s:%s:%s:%f:%s", tx.TxID, tx.TokenID, tx.From, tx.Amount, tx.To)
	hash := sha256.Sum256([]byte(message))

	signatureBytes := make([]byte, len(tx.Signature)/2)
	_, err := fmt.Sscanf(tx.Signature, "%x", &signatureBytes)
	if err != nil {
		return false, err
	}

	publicKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return false, err
	}

	pubKey, err := crypto.UnmarshalPubkey(publicKeyBytes)
	if err != nil {
		return false, err
	}

	verified := crypto.VerifySignature(pubKey, hash[:], signatureBytes)
	if !verified {
		return false, errors.New("invalid signature")
	}

	tx.Validated = true
	tm.transactions[txID] = tx
	return true, nil
}
