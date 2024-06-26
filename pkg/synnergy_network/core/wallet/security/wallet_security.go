package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"sync"
	"time"

	"github.com/synnergy_network/pkg/layer0/core/blockchain"
	"github.com/synnergy_network/pkg/layer0/core/wallet"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

// WalletSecurityService provides comprehensive security functionalities for wallets
type WalletSecurityService struct {
	blockchainService *blockchain.BlockchainService
	walletService     *wallet.WalletService
	frozenWallets     sync.Map
	alerts            chan string
}

// NewWalletSecurityService initializes and returns a new WalletSecurityService
func NewWalletSecurityService(blockchainService *blockchain.BlockchainService, walletService *wallet.WalletService) *WalletSecurityService {
	return &WalletSecurityService{
		blockchainService: blockchainService,
		walletService:     walletService,
		alerts:            make(chan string, 100),
	}
}

// FreezeWallet freezes a wallet to prevent further transactions
func (wss *WalletSecurityService) FreezeWallet(walletAddress string) error {
	if _, loaded := wss.frozenWallets.LoadOrStore(walletAddress, true); loaded {
		return errors.New("wallet is already frozen")
	}

	wss.blockchainService.AddTransactionFilter(walletAddress, wss.transactionFilter)
	alertMsg := wss.generateAlertMessage(walletAddress, "Wallet has been frozen")
	wss.alerts <- alertMsg
	return nil
}

// UnfreezeWallet unfreezes a wallet to allow transactions
func (wss *WalletSecurityService) UnfreezeWallet(walletAddress string) error {
	if _, loaded := wss.frozenWallets.LoadAndDelete(walletAddress); !loaded {
		return errors.New("wallet is not frozen")
	}

	wss.blockchainService.RemoveTransactionFilter(walletAddress)
	alertMsg := wss.generateAlertMessage(walletAddress, "Wallet has been unfrozen")
	wss.alerts <- alertMsg
	return nil
}

// IsWalletFrozen checks if a wallet is currently frozen
func (wss *WalletSecurityService) IsWalletFrozen(walletAddress string) bool {
	_, frozen := wss.frozenWallets.Load(walletAddress)
	return frozen
}

// transactionFilter is a filter applied to prevent transactions from frozen wallets
func (wss *WalletSecurityService) transactionFilter(tx *blockchain.Transaction) bool {
	if wss.IsWalletFrozen(tx.From) {
		log.Printf("Transaction from frozen wallet %s blocked", tx.From)
		return false
	}
	return true
}

// generateAlertMessage generates an alert message for wallet freezing or unfreezing
func (wss *WalletSecurityService) generateAlertMessage(walletAddress string, action string) string {
	alert := map[string]interface{}{
		"message":   action,
		"wallet":    walletAddress,
		"time":      time.Now(),
		"alertType": "WalletSecurity",
	}
	alertMsg, _ := json.Marshal(alert)
	return string(alertMsg)
}

// GetAlerts returns a channel to listen for freezing/unfreezing alerts
func (wss *WalletSecurityService) GetAlerts() <-chan string {
	return wss.alerts
}

// SecureEncrypt encrypts data using AES with a provided key
func (wss *WalletSecurityService) SecureEncrypt(data []byte, passphrase string) (string, error) {
	key := sha256.Sum256([]byte(passphrase))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)

	return hex.EncodeToString(ciphertext), nil
}

// SecureDecrypt decrypts data using AES with a provided key
func (wss *WalletSecurityService) SecureDecrypt(encrypted string, passphrase string) ([]byte, error) {
	key := sha256.Sum256([]byte(passphrase))
	ciphertext, _ := hex.DecodeString(encrypted)

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}

// GenerateArgon2Key generates a key using Argon2 key derivation function
func (wss *WalletSecurityService) GenerateArgon2Key(password, salt []byte) ([]byte, error) {
	return argon2.IDKey(password, salt, 1, 64*1024, 4, 32), nil
}

// GenerateScryptKey generates a key using Scrypt key derivation function
func (wss *WalletSecurityService) GenerateScryptKey(password, salt []byte) ([]byte, error) {
	return scrypt.Key(password, salt, 1<<15, 8, 1, 32)
}

// WalletService provides methods to manage wallet functionalities
type WalletService struct {
	// ... existing methods and fields
}

// Transaction represents a simplified transaction structure for the blockchain
type Transaction struct {
	From   string
	To     string
	Amount float64
	Time   time.Time
}

// Mnemonic Generation and Recovery
func (wss *WalletSecurityService) GenerateMnemonic() (string, error) {
	entropy, err := bip39.NewEntropy(128)
	if err != nil {
		return "", err
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", err
	}
	return mnemonic, nil
}

func (wss *WalletSecurityService) RecoverFromMnemonic(mnemonic string) ([]byte, error) {
	seed := bip39.NewSeed(mnemonic, "")
	return seed, nil
}

func (wss *WalletSecurityService) GenerateHDWallet(seed []byte) (*wallet.HDWallet, error) {
	hdWallet, err := wallet.NewHDWallet(seed)
	if err != nil {
		return nil, err
	}
	return hdWallet, nil
}

func main() {
	// Simulating dependency initialization
	blockchainService := &blockchain.BlockchainService{}
	walletService := &wallet.WalletService{}
	walletSecurityService := NewWalletSecurityService(blockchainService, walletService)

	// Simulating freezing a wallet
	walletAddress := "address1"
	err := walletSecurityService.FreezeWallet(walletAddress)
	if err != nil {
		log.Printf("Error freezing wallet: %v", err)
	} else {
		log.Printf("Wallet %s has been frozen", walletAddress)
	}

	// Simulating unfreezing a wallet
	err = walletSecurityService.UnfreezeWallet(walletAddress)
	if err != nil {
		log.Printf("Error unfreezing wallet: %v", err)
	} else {
		log.Printf("Wallet %s has been unfrozen", walletAddress)
	}

	// Listening for alerts
	go func() {
		for alert := range walletSecurityService.GetAlerts() {
			log.Printf("Alert: %s", alert)
		}
	}()

	// Example of encryption and decryption
	encrypted, err := walletSecurityService.SecureEncrypt([]byte("Sensitive Data"), "passphrase")
	if err != nil {
		log.Fatalf("Error encrypting data: %v", err)
	}
	log.Printf("Encrypted Data: %s", encrypted)

	decrypted, err := walletSecurityService.SecureDecrypt(encrypted, "passphrase")
	if err != nil {
		log.Fatalf("Error decrypting data: %v", err)
	}
	log.Printf("Decrypted Data: %s", decrypted)

	// Example of generating mnemonic and recovering from it
	mnemonic, err := walletSecurityService.GenerateMnemonic()
	if err != nil {
		log.Fatalf("Error generating mnemonic: %v", err)
	}
	log.Printf("Mnemonic: %s", mnemonic)

	seed, err := walletSecurityService.RecoverFromMnemonic(mnemonic)
	if err != nil {
		log.Fatalf("Error recovering from mnemonic: %v", err)
	}
	log.Printf("Seed: %x", seed)
}
