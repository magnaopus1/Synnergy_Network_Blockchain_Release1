package fee_redistribution

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math/big"
	"sync"

	"golang.org/x/crypto/scrypt"
)

// PublicGoodsFunding defines the structure for managing public goods funding
type PublicGoodsFunding struct {
	sync.Mutex
	totalFunds        *big.Int
	allocatedFunds    map[string]*big.Int
	fundingRecipients map[string]bool
}

// NewPublicGoodsFunding creates a new instance of PublicGoodsFunding
func NewPublicGoodsFunding() *PublicGoodsFunding {
	return &PublicGoodsFunding{
		totalFunds:        big.NewInt(0),
		allocatedFunds:    make(map[string]*big.Int),
		fundingRecipients: make(map[string]bool),
	}
}

// AddRecipient adds a new recipient for public goods funding
func (pgf *PublicGoodsFunding) AddRecipient(address string) {
	pgf.Lock()
	defer pgf.Unlock()

	if !pgf.fundingRecipients[address] {
		pgf.fundingRecipients[address] = true
		pgf.allocatedFunds[address] = big.NewInt(0)
	}
}

// RemoveRecipient removes a recipient from public goods funding
func (pgf *PublicGoodsFunding) RemoveRecipient(address string) {
	pgf.Lock()
	defer pgf.Unlock()

	if pgf.fundingRecipients[address] {
		delete(pgf.fundingRecipients, address)
		delete(pgf.allocatedFunds, address)
	}
}

// AllocateFunds allocates funds from the total pool to the recipients
func (pgf *PublicGoodsFunding) AllocateFunds() error {
	pgf.Lock()
	defer pgf.Unlock()

	if pgf.totalFunds.Cmp(big.NewInt(0)) == 0 {
		return errors.New("total funds pool is empty")
	}

	totalRecipients := len(pgf.fundingRecipients)
	if totalRecipients == 0 {
		return errors.New("no recipients to allocate funds to")
	}

	share := new(big.Int).Div(pgf.totalFunds, big.NewInt(int64(totalRecipients)))
	for address := range pgf.fundingRecipients {
		pgf.allocatedFunds[address].Add(pgf.allocatedFunds[address], share)
	}

	pgf.totalFunds.SetInt64(0)
	return nil
}

// GetAllocatedFunds returns the allocated funds for a specific recipient
func (pgf *PublicGoodsFunding) GetAllocatedFunds(address string) (*big.Int, error) {
	pgf.Lock()
	defer pgf.Unlock()

	funds, exists := pgf.allocatedFunds[address]
	if !exists {
		return nil, errors.New("recipient not found")
	}

	return funds, nil
}

// AddToTotalFunds adds more funds to the total pool
func (pgf *PublicGoodsFunding) AddToTotalFunds(amount *big.Int) {
	pgf.Lock()
	defer pgf.Unlock()

	pgf.totalFunds.Add(pgf.totalFunds, amount)
}

// EncryptFunds encrypts the funds data using Scrypt and AES
func (pgf *PublicGoodsFunding) EncryptFunds(address string, passphrase string) (string, error) {
	pgf.Lock()
	defer pgf.Unlock()

	funds, exists := pgf.allocatedFunds[address]
	if !exists {
		return "", errors.New("recipient not found")
	}

	data := []byte(funds.String())
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return hex.EncodeToString(append(salt, ciphertext...)), nil
}

// DecryptFunds decrypts the funds data using Scrypt and AES
func (pgf *PublicGoodsFunding) DecryptFunds(encryptedData string, passphrase string) (*big.Int, error) {
	data, err := hex.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}

	if len(data) < 16 {
		return nil, errors.New("invalid encrypted data")
	}

	salt := data[:16]
	ciphertext := data[16:]

	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("invalid encrypted data")
	}

	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	funds := new(big.Int)
	funds.SetString(string(plaintext), 10)
	return funds, nil
}
