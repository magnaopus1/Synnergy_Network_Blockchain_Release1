package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"time"

	"golang.org/x/crypto/scrypt"
	"github.com/tyler-smith/go-bip39"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
)

// Wallet represents a blockchain wallet with fields for the private key, address, and balance.
type Wallet struct {
	PrivateKey *ecdsa.PrivateKey
	Address    string
	Balance    float64
}

// NewWallet generates a new wallet with a new ECDSA keypair.
func NewWallet() (*Wallet, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate keypair: %v", err)
	}

	publicKey := append(privateKey.PublicKey.X.Bytes(), privateKey.PublicKey.Y.Bytes()...)
	address := sha256.Sum256(publicKey)
	wallet := &Wallet{
		PrivateKey: privateKey,
		Address:    hex.EncodeToString(address[:]),
		Balance:    0.0,
	}
	return wallet, nil
}

// EncryptData encrypts data using Scrypt for key derivation and AES for encryption.
func EncryptData(data, passphrase string) ([]byte, error) {
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %v", err)
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %v", err)
	}

	ciphertext, err := encryptAES(data, key)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %v", err)
	}

	return append(salt, ciphertext...), nil
}

// DecryptData decrypts data using Scrypt for key derivation and AES for decryption.
func DecryptData(data []byte, passphrase string) (string, error) {
	if len(data) < 32 {
		return "", errors.New("invalid data")
	}

	salt := data[:32]
	ciphertext := data[32:]

	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return "", fmt.Errorf("failed to derive key: %v", err)
	}

	plaintext, err := decryptAES(ciphertext, key)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt data: %v", err)
	}

	return plaintext, nil
}

// MnemonicGeneration generates a 12-word mnemonic phrase for wallet recovery using the BIP39 standard.
func MnemonicGeneration() (string, error) {
	entropy, err := bip39.NewEntropy(128)
	if err != nil {
		return "", fmt.Errorf("failed to generate entropy: %v", err)
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", fmt.Errorf("failed to generate mnemonic: %v", err)
	}

	return mnemonic, nil
}

// WalletRecovery recovers a wallet using a 12-word mnemonic phrase.
func WalletRecovery(mnemonic string) (*Wallet, error) {
	seed := bip39.NewSeed(mnemonic, "")
	privateKey, err := crypto.ToECDSA(seed)
	if err != nil {
		return nil, fmt.Errorf("failed to recover private key: %v", err)
	}

	publicKey := append(privateKey.PublicKey.X.Bytes(), privateKey.PublicKey.Y.Bytes()...)
	address := sha256.Sum256(publicKey)
	wallet := &Wallet{
		PrivateKey: privateKey,
		Address:    hex.EncodeToString(address[:]),
		Balance:    0.0,
	}
	return wallet, nil
}

// HierarchicalDeterministicWallet creates multiple private keys from a single mnemonic phrase.
func HierarchicalDeterministicWallet(mnemonic string, index uint32) (*ecdsa.PrivateKey, error) {
	seed := bip39.NewSeed(mnemonic, "")
	masterKey, _ := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	childKey, err := masterKey.Child(index)
	if err != nil {
		return nil, fmt.Errorf("failed to derive child key: %v", err)
	}

	privateKey, err := childKey.ECPrivKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get EC private key: %v", err)
	}

	return privateKey.ToECDSA(), nil
}

// EncryptMnemonic encrypts the mnemonic phrase with a passphrase.
func EncryptMnemonic(mnemonic, passphrase string) (string, error) {
	encrypted, err := EncryptData(mnemonic, passphrase)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt mnemonic: %v", err)
	}

	return fmt.Sprintf("%x", encrypted), nil
}

// DecryptMnemonic decrypts the mnemonic phrase with a passphrase.
func DecryptMnemonic(encryptedMnemonic, passphrase string) (string, error) {
	encryptedData, err := hex.DecodeString(encryptedMnemonic)
	if err != nil {
		return "", fmt.Errorf("failed to decode encrypted mnemonic: %v", err)
	}

	mnemonic, err := DecryptData(encryptedData, passphrase)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt mnemonic: %v", err)
	}

	return mnemonic, nil
}

// BlockchainRecoveryProtocol is a placeholder for recovering the blockchain state using mnemonic phrases in case of catastrophic data loss.
func BlockchainRecoveryProtocol(mnemonics []string) error {
	// Implement blockchain state recovery logic using mnemonics
	// This is a placeholder function to be filled with actual recovery logic
	return nil
}

// DistributedMnemonicStorage is a placeholder for distributing mnemonic fragments across multiple decentralized storage networks.
func DistributedMnemonicStorage(mnemonic string) ([]string, error) {
	// Implement logic to distribute mnemonic fragments
	// This is a placeholder function to be filled with actual storage logic
	return []string{mnemonic}, nil
}

func encryptAES(plaintext string, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return ciphertext, nil
}

func decryptAES(ciphertext, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// SendTransaction signs and sends a transaction from one wallet to another.
func (w *Wallet) SendTransaction(to string, amount float64) (string, error) {
	if amount <= 0 {
		return "", errors.New("amount must be greater than 0")
	}
	if amount > w.Balance {
		return "", errors.New("insufficient balance")
	}

	hash := sha256.Sum256([]byte(fmt.Sprintf("%s%s%f%s", w.Address, to, amount, time.Now())))
	r, s, err := ecdsa.Sign(rand.Reader, w.PrivateKey, hash[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign transaction: %v", err)
	}

	signature := append(r.Bytes(), s.Bytes()...)

	// Update the wallet balance
	w.Balance -= amount

	txID := hex.EncodeToString(hash[:])
	log.Printf("Transaction %s: %s sent %f to %s", txID, w.Address, amount, to)
	return txID, nil
}

// WalletService manages multiple wallets.
type WalletService struct {
	Wallets map[string]*Wallet
}

// NewWalletService initializes a new wallet service.
func NewWalletService() *WalletService {
	return &WalletService{
		Wallets: make(map[string]*Wallet),
	}
}

// CreateWallet creates a new wallet and adds it to the service.
func (ws *WalletService) CreateWallet() (*Wallet, error) {
	wallet, err := NewWallet()
	if err != nil {
		return nil, err
	}
	ws.Wallets[wallet.Address] = wallet
	return wallet, nil
}

// GetWallet retrieves a wallet by address.
func (ws *WalletService) GetWallet(address string) (*Wallet, error) {
	wallet, exists := ws.Wallets[address]
	if !exists {
		return nil, errors.New("wallet not found")
	}
	return wallet, nil
}

// MultiCurrencySupport enables the wallet to manage and convert between various digital assets.
func (ws *WalletService) MultiCurrencySupport(wallet *Wallet, currency string, amount float64) error {
	// Placeholder function to be implemented with actual logic for multi-currency support
	return nil
}

// RealTimeNotifications sends real-time updates on balance changes and other critical events.
func (ws *WalletService) RealTimeNotifications(wallet *Wallet, event string) error {
	// Placeholder function to be implemented with actual logic for real-time notifications
	return nil
}

