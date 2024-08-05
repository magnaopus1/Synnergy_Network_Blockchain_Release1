package interoperability

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"sync"

	"golang.org/x/crypto/scrypt"
	"github.com/ethereum/go-ethereum/common"
)

// UnifiedWallet represents a wallet that supports multiple cryptocurrencies and blockchain interactions
type UnifiedWallet struct {
	ID                common.Hash
	OwnerAddress      common.Address
	Wallets           map[string]*IndividualWallet
	EncryptionKey     []byte
	Nonce             *big.Int
	Lock              sync.Mutex
}

// IndividualWallet represents a single cryptocurrency wallet within the unified wallet
type IndividualWallet struct {
	Blockchain        string
	Address           common.Address
	PrivateKey        string
	Balance           *big.Int
}

// NewUnifiedWallet creates a new unified wallet for a specific owner address
func NewUnifiedWallet(ownerAddress common.Address, password string) (*UnifiedWallet, error) {
	nonce := big.NewInt(time.Now().UnixNano())
	id := generateWalletID(ownerAddress, nonce)
	encryptionKey, err := generateEncryptionKey(password, nonce)
	if err != nil {
		return nil, err
	}

	return &UnifiedWallet{
		ID:                id,
		OwnerAddress:      ownerAddress,
		Wallets:           make(map[string]*IndividualWallet),
		EncryptionKey:     encryptionKey,
		Nonce:             nonce,
	}, nil
}

// AddWallet adds an individual wallet to the unified wallet
func (u *UnifiedWallet) AddWallet(blockchain string, address common.Address, privateKey string, balance *big.Int) error {
	u.Lock.Lock()
	defer u.Lock.Unlock()

	encryptedPrivateKey, err := u.encryptPrivateKey(privateKey)
	if err != nil {
		return err
	}

	wallet := &IndividualWallet{
		Blockchain: blockchain,
		Address:    address,
		PrivateKey: encryptedPrivateKey,
		Balance:    balance,
	}

	u.Wallets[blockchain] = wallet
	return nil
}

// GetBalance retrieves the balance of a specific wallet within the unified wallet
func (u *UnifiedWallet) GetBalance(blockchain string) (*big.Int, error) {
	u.Lock.Lock()
	defer u.Lock.Unlock()

	wallet, exists := u.Wallets[blockchain]
	if !exists {
		return nil, errors.New("wallet not found")
	}

	return wallet.Balance, nil
}

// Transfer performs a transfer between wallets within the unified wallet
func (u *UnifiedWallet) Transfer(blockchain string, toAddress common.Address, amount *big.Int) error {
	u.Lock.Lock()
	defer u.Lock.Unlock()

	wallet, exists := u.Wallets[blockchain]
	if !exists {
		return errors.New("wallet not found")
	}

	if wallet.Balance.Cmp(amount) < 0 {
		return errors.New("insufficient balance")
	}

	// Perform the transfer (simulated for this example)
	wallet.Balance.Sub(wallet.Balance, amount)
	// In a real-world scenario, the transfer would involve interacting with the blockchain network

	return nil
}

// DecryptPrivateKey decrypts the private key of a specific wallet
func (u *UnifiedWallet) DecryptPrivateKey(blockchain string, password string) (string, error) {
	u.Lock.Lock()
	defer u.Lock.Unlock()

	wallet, exists := u.Wallets[blockchain]
	if !exists {
		return "", errors.New("wallet not found")
	}

	decryptionKey, err := generateEncryptionKey(password, u.Nonce)
	if err != nil {
		return "", err
	}

	privateKey, err := decrypt(decryptionKey, wallet.PrivateKey)
	if err != nil {
		return "", err
	}

	return privateKey, nil
}

// encryptPrivateKey encrypts a private key using the wallet's encryption key
func (u *UnifiedWallet) encryptPrivateKey(privateKey string) (string, error) {
	return encrypt(u.EncryptionKey, privateKey)
}

// generateWalletID generates a unique ID for the unified wallet
func generateWalletID(ownerAddress common.Address, nonce *big.Int) common.Hash {
	data := ownerAddress.Hex() + nonce.String()
	hash := sha256.Sum256([]byte(data))
	return common.BytesToHash(hash[:])
}

// generateEncryptionKey generates an encryption key using the password and nonce
func generateEncryptionKey(password string, nonce *big.Int) ([]byte, error) {
	salt := nonce.Bytes()
	key, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// encrypt encrypts the plaintext using the provided key
func encrypt(key []byte, plaintext string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(plaintext))

	return hex.EncodeToString(ciphertext), nil
}

// decrypt decrypts the ciphertext using the provided key
func decrypt(key []byte, ciphertext string) (string, error) {
	ciphertextBytes, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(ciphertextBytes) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}

	iv := ciphertextBytes[:aes.BlockSize]
	ciphertextBytes = ciphertextBytes[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertextBytes, ciphertextBytes)

	return string(ciphertextBytes), nil
}
