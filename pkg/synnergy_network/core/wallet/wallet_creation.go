package wallet_creation

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"sync"

	"golang.org/x/crypto/ripemd160"
	"github.com/synnergy_network/blockchain/crypto"
	"github.com/synnergy_network/blockchain/utils"
	"github.com/synnergy_network/cryptography/encryption"
)

// Address represents a wallet address in the Synnergy Network
type Address struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  []byte
	Address    string
}

// Wallet represents a collection of addresses
type Wallet struct {
	mu       sync.Mutex
	addresses map[string]*Address
}

// NewWallet creates a new Wallet
func NewWallet() *Wallet {
	return &Wallet{
		addresses: make(map[string]*Address),
	}
}

// CreateAddress generates a new address and adds it to the wallet
func (w *Wallet) CreateAddress() (*Address, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	privateKey, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	publicKey := append(privateKey.PublicKey.X.Bytes(), privateKey.PublicKey.Y.Bytes()...)
	address, err := generateAddress(publicKey)
	if err != nil {
		return nil, err
	}

	addr := &Address{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		Address:    address,
	}

	w.addresses[address] = addr
	return addr, nil
}

// GetAddress retrieves an address from the wallet by its string representation
func (w *Wallet) GetAddress(address string) (*Address, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	addr, exists := w.addresses[address]
	if !exists {
		return nil, errors.New("address not found")
	}

	return addr, nil
}

// ListAddresses lists all addresses in the wallet
func (w *Wallet) ListAddresses() []string {
	w.mu.Lock()
	defer w.mu.Unlock()

	addressList := make([]string, 0, len(w.addresses))
	for address := range w.addresses {
		addressList = append(addressList, address)
	}
	return addressList
}

// generateAddress creates a wallet address from a public key
func generateAddress(publicKey []byte) (string, error) {
	sha256Hash := sha256.New()
	_, err := sha256Hash.Write(publicKey)
	if err != nil {
		return "", err
	}
	publicSHA256 := sha256Hash.Sum(nil)

	ripemd160Hash := ripemd160.New()
	_, err = ripemd160Hash.Write(publicSHA256)
	if err != nil {
		return "", err
	}
	publicRIPEMD160 := ripemd160Hash.Sum(nil)

	// Encode with a checksum for better address safety
	checksum := checksum(publicRIPEMD160)
	address := hex.EncodeToString(publicRIPEMD160) + hex.EncodeToString(checksum)

	return address, nil
}

// checksum calculates a checksum for a given input
func checksum(input []byte) []byte {
	firstSHA := sha256.Sum256(input)
	secondSHA := sha256.Sum256(firstSHA[:])
	return secondSHA[:4]
}

// EncryptAddress encrypts the private key of an address
func (w *Wallet) EncryptAddress(address, passphrase string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	addr, exists := w.addresses[address]
	if !exists {
		return errors.New("address not found")
	}

	privateKeyBytes := addr.PrivateKey.D.Bytes()
	encryptedKey, err := encryption.Encrypt(privateKeyBytes, passphrase)
	if err != nil {
		return err
	}

	// Store the encrypted private key
	addr.PrivateKey.D = new(big.Int).SetBytes(encryptedKey)
	return nil
}

// DecryptAddress decrypts the private key of an address
func (w *Wallet) DecryptAddress(address, passphrase string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	addr, exists := w.addresses[address]
	if !exists {
		return errors.New("address not found")
	}

	encryptedKey := addr.PrivateKey.D.Bytes()
	decryptedKey, err := encryption.Decrypt(encryptedKey, passphrase)
	if err != nil {
		return err
	}

	// Restore the private key
	addr.PrivateKey.D = new(big.Int).SetBytes(decryptedKey)
	return nil
}
package wallet_creation

import (
    "crypto/ecdsa"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "math/big"
    "time"

    "github.com/synnergy_network/blockchain/token_standards/syn_900"
    "github.com/synnergy_network/crypto"
    "github.com/synnergy_network/transaction"
    "github.com/synnergy_network/wallet"
)

// IDToken represents an identification token
type IDToken struct {
    TokenID        string
    OwnerAddress   string
    CreationTime   time.Time
    LinkedWallet   string
    IsDeposited    bool
}

// NewIDToken creates a new identification token
func NewIDToken(ownerAddress string) (*IDToken, error) {
    tokenID, err := generateTokenID()
    if err != nil {
        return nil, err
    }

    idToken := &IDToken{
        TokenID:      tokenID,
        OwnerAddress: ownerAddress,
        CreationTime: time.Now(),
        IsDeposited:  false,
    }
    return idToken, nil
}

// generateTokenID generates a unique token ID
func generateTokenID() (string, error) {
    privateKey, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
    if err != nil {
        return "", err
    }
    hash := sha256.New()
    _, err = hash.Write(privateKey.D.Bytes())
    if err != nil {
        return "", err
    }
    return hex.EncodeToString(hash.Sum(nil)), nil
}

// DepositIDToken deposits the ID token into the specified wallet
func (token *IDToken) DepositIDToken(walletAddress string) error {
    if token.IsDeposited {
        return errors.New("token already deposited")
    }

    // Create a transaction to deposit the token
    tx, err := createDepositTransaction(token.TokenID, walletAddress)
    if err != nil {
        return err
    }

    // Broadcast the transaction
    err = transaction.Broadcast(tx)
    if err != nil {
        return err
    }

    token.LinkedWallet = walletAddress
    token.IsDeposited = true
    return nil
}

// createDepositTransaction creates a transaction for depositing the ID token
func createDepositTransaction(tokenID, walletAddress string) (*transaction.Transaction, error) {
    tx := &transaction.Transaction{
        From:   "system",
        To:     walletAddress,
        Amount: big.NewInt(0), // ID token deposit, no monetary value
        Data:   []byte(fmt.Sprintf("Deposit ID Token: %s", tokenID)),
        Time:   time.Now().Unix(),
    }

    // Sign the transaction
    err := tx.Sign(crypto.SystemPrivateKey)
    if err != nil {
        return nil, err
    }
    return tx, nil
}

// WithdrawIDToken withdraws the ID token to a safe place
func (token *IDToken) WithdrawIDToken(safeAddress string) error {
    if !token.IsDeposited {
        return errors.New("token not deposited yet")
    }

    // Create a transaction to withdraw the token
    tx, err := createWithdrawTransaction(token.TokenID, safeAddress)
    if err != nil {
        return err
    }

    // Broadcast the transaction
    err = transaction.Broadcast(tx)
    if err != nil {
        return err
    }

    token.LinkedWallet = ""
    token.IsDeposited = false
    return nil
}

// createWithdrawTransaction creates a transaction for withdrawing the ID token
func createWithdrawTransaction(tokenID, safeAddress string) (*transaction.Transaction, error) {
    tx := &transaction.Transaction{
        From:   "system",
        To:     safeAddress,
        Amount: big.NewInt(0), // ID token withdrawal, no monetary value
        Data:   []byte(fmt.Sprintf("Withdraw ID Token: %s", tokenID)),
        Time:   time.Now().Unix(),
    }

    // Sign the transaction
    err := tx.Sign(crypto.SystemPrivateKey)
    if err != nil {
        return nil, err
    }
    return tx, nil
}

// VerifyIDToken verifies the ID token ownership
func VerifyIDToken(tokenID, walletAddress string) (bool, error) {
    // Retrieve token from blockchain
    token, err := syn_900.GetTokenByID(tokenID)
    if err != nil {
        return false, err
    }

    if token.OwnerAddress == walletAddress {
        return true, nil
    }
    return false, nil
}
package wallet_creation

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/x509"
    "encoding/pem"
    "errors"
    "os"

    "golang.org/x/crypto/scrypt"
    "github.com/synnergy_network/blockchain/crypto"
    "github.com/synnergy_network/blockchain/utils"
)

// Keypair contains the private and public key
type Keypair struct {
    PrivateKey *ecdsa.PrivateKey
    PublicKey  *ecdsa.PublicKey
}

// GenerateKeypair generates a new ECDSA keypair
func GenerateKeypair() (*Keypair, error) {
    privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        return nil, err
    }
    return &Keypair{
        PrivateKey: privKey,
        PublicKey:  &privKey.PublicKey,
    }, nil
}

// SaveKeypair saves the private and public keys to files with encryption
func SaveKeypair(keypair *Keypair, privateKeyPath, publicKeyPath, passphrase string) error {
    // Save private key
    privKeyBytes, err := x509.MarshalECPrivateKey(keypair.PrivateKey)
    if err != nil {
        return err
    }

    salt := make([]byte, 16)
    _, err = rand.Read(salt)
    if err != nil {
        return err
    }

    derivedKey, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
    if err != nil {
        return err
    }

    encryptedPrivKey, err := crypto.AESEncrypt(privKeyBytes, derivedKey)
    if err != nil {
        return err
    }

    privKeyBlock := &pem.Block{
        Type:  "EC PRIVATE KEY",
        Bytes: encryptedPrivKey,
    }

    err = os.WriteFile(privateKeyPath, pem.EncodeToMemory(privKeyBlock), 0600)
    if err != nil {
        return err
    }

    // Save public key
    pubKeyBytes, err := x509.MarshalPKIXPublicKey(keypair.PublicKey)
    if err != nil {
        return err
    }

    err = os.WriteFile(publicKeyPath, pubKeyBytes, 0644)
    if err != nil {
        return err
    }

    return nil
}

// LoadKeypair loads the private and public keys from files with decryption
func LoadKeypair(privateKeyPath, publicKeyPath, passphrase string) (*Keypair, error) {
    // Load private key
    privKeyPEM, err := os.ReadFile(privateKeyPath)
    if err != nil {
        return nil, err
    }

    privKeyBlock, _ := pem.Decode(privKeyPEM)
    if privKeyBlock == nil || privKeyBlock.Type != "EC PRIVATE KEY" {
        return nil, errors.New("failed to decode PEM block containing private key")
    }

    salt := privKeyBlock.Bytes[:16]
    encryptedPrivKey := privKeyBlock.Bytes[16:]

    derivedKey, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
    if err != nil {
        return nil, err
    }

    decryptedPrivKey, err := crypto.AESDecrypt(encryptedPrivKey, derivedKey)
    if err != nil {
        return nil, err
    }

    privateKey, err := x509.ParseECPrivateKey(decryptedPrivKey)
    if err != nil {
        return nil, err
    }

    // Load public key
    pubKeyBytes, err := os.ReadFile(publicKeyPath)
    if err != nil {
        return nil, err
    }

    publicKey, err := x509.ParsePKIXPublicKey(pubKeyBytes)
    if err != nil {
        return nil, err
    }

    pubKey, ok := publicKey.(*ecdsa.PublicKey)
    if !ok {
        return nil, errors.New("failed to parse public key")
    }

    return &Keypair{
        PrivateKey: privateKey,
        PublicKey:  pubKey,
    }, nil
}
package wallet_creation

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/synnergy_network/blockchain/crypto"
	"github.com/synnergy_network/blockchain/security"
	"github.com/synnergy_network/wallet/utils"
	"golang.org/x/crypto/pbkdf2"
)

const (
	EntropyBitSize   = 128
	MnemonicWordSize = 12
	WordListPath     = "path/to/wordlist.txt"
)

// MnemonicGenerator provides functionality to generate and manage mnemonic phrases.
type MnemonicGenerator struct {
	wordList []string
}

// NewMnemonicGenerator initializes a new MnemonicGenerator instance.
func NewMnemonicGenerator() *MnemonicGenerator {
	wordList, err := loadWordList(WordListPath)
	if err != nil {
		panic(fmt.Sprintf("failed to load word list: %v", err))
	}
	return &MnemonicGenerator{wordList: wordList}
}

// GenerateMnemonic generates a new mnemonic phrase.
func (mg *MnemonicGenerator) GenerateMnemonic() (string, error) {
	entropy := make([]byte, EntropyBitSize/8)
	if _, err := rand.Read(entropy); err != nil {
		return "", fmt.Errorf("failed to generate entropy: %v", err)
	}

	checksum := calculateChecksum(entropy)
	bits := append(entropy, checksum...)
	binaryMnemonic := bytesToBits(bits)

	var mnemonic []string
	for i := 0; i < MnemonicWordSize; i++ {
		index := bitsToInt(binaryMnemonic[i*11 : (i+1)*11])
		mnemonic = append(mnemonic, mg.wordList[index])
	}

	return strings.Join(mnemonic, " "), nil
}

// loadWordList loads the word list from the specified path.
func loadWordList(path string) ([]string, error) {
	// Implement the function to load the word list from a file.
	// For the sake of example, assume it returns a slice of words.
	return []string{"word1", "word2", /* ... */}, nil
}

// calculateChecksum calculates the checksum for the given entropy.
func calculateChecksum(entropy []byte) []byte {
	hash := sha256.Sum256(entropy)
	return hash[:1] // Use the first byte for the checksum
}

// bytesToBits converts a byte slice to a bit slice.
func bytesToBits(bytes []byte) []bool {
	var bits []bool
	for _, b := range bytes {
		for i := 7; i >= 0; i-- {
			bits = append(bits, b&(1<<i) != 0)
		}
	}
	return bits
}

// bitsToInt converts a bit slice to an integer.
func bitsToInt(bits []bool) int {
	var n int
	for _, bit := range bits {
		n = n<<1 | boolToInt(bit)
	}
	return n
}

// boolToInt converts a boolean value to an integer.
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// MnemonicToSeed converts a mnemonic phrase to a seed.
func MnemonicToSeed(mnemonic, passphrase string) []byte {
	salt := "mnemonic" + passphrase
	return pbkdf2.Key([]byte(mnemonic), []byte(salt), 2048, 64, sha256.New)
}

// SecureMnemonic encrypts the mnemonic using a user-provided passphrase.
func SecureMnemonic(mnemonic, passphrase string) (string, error) {
	salt := generateSalt()
	key := pbkdf2.Key([]byte(passphrase), salt, 4096, 32, sha256.New)
	encryptedMnemonic, err := security.EncryptAES([]byte(mnemonic), key)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt mnemonic: %v", err)
	}
	return fmt.Sprintf("%x:%x", salt, encryptedMnemonic), nil
}

// DecryptMnemonic decrypts the encrypted mnemonic using the provided passphrase.
func DecryptMnemonic(encryptedMnemonic, passphrase string) (string, error) {
	parts := strings.Split(encryptedMnemonic, ":")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid encrypted mnemonic format")
	}
	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("invalid salt format: %v", err)
	}
	encryptedData, err := hex.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("invalid encrypted data format: %v", err)
	}
	key := pbkdf2.Key([]byte(passphrase), salt, 4096, 32, sha256.New)
	decryptedMnemonic, err := security.DecryptAES(encryptedData, key)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt mnemonic: %v", err)
	}
	return string(decryptedMnemonic), nil
}

// generateSalt generates a random salt for encryption.
func generateSalt() []byte {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic(fmt.Sprintf("failed to generate salt: %v", err))
	}
	return salt
}
package wallet_creation

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
	"github.com/synnergy_network/blockchain/logger"
	"github.com/synnergy_network/blockchain/security"
	"github.com/synnergy_network/wallet/storage"
)

// GenerateMnemonic generates a mnemonic phrase using BIP39 standard.
func GenerateMnemonic() (string, error) {
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		logger.Error("Failed to generate entropy for mnemonic: %v", err)
		return "", err
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		logger.Error("Failed to generate mnemonic: %v", err)
		return "", err
	}

	return mnemonic, nil
}

// MnemonicToSeed converts a mnemonic phrase to a seed.
func MnemonicToSeed(mnemonic, passphrase string) []byte {
	return bip39.NewSeed(mnemonic, passphrase)
}

// EncryptMnemonic encrypts a mnemonic phrase using a user-defined passphrase.
func EncryptMnemonic(mnemonic, passphrase string) (string, error) {
	salt := generateSalt()
	key, err := deriveKey(passphrase, salt)
	if err != nil {
		return "", err
	}

	encryptedMnemonic, err := security.EncryptAES([]byte(mnemonic), key)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(encryptedMnemonic) + ":" + hex.EncodeToString(salt), nil
}

// DecryptMnemonic decrypts an encrypted mnemonic phrase using a user-defined passphrase.
func DecryptMnemonic(encryptedMnemonic, passphrase string) (string, error) {
	parts := strings.Split(encryptedMnemonic, ":")
	if len(parts) != 2 {
		return "", errors.New("invalid encrypted mnemonic format")
	}

	encMnemonicBytes, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", err
	}

	salt, err := hex.DecodeString(parts[1])
	if err != nil {
		return "", err
	}

	key, err := deriveKey(passphrase, salt)
	if err != nil {
		return "", err
	}

	decryptedMnemonic, err := security.DecryptAES(encMnemonicBytes, key)
	if err != nil {
		return "", err
	}

	return string(decryptedMnemonic), nil
}

// BackupMnemonic securely stores the mnemonic using decentralized storage.
func BackupMnemonic(mnemonic string) error {
	// Encrypt mnemonic before storing
	encryptedMnemonic, err := EncryptMnemonic(mnemonic, "backupPassphrase")
	if err != nil {
		logger.Error("Failed to encrypt mnemonic for backup: %v", err)
		return err
	}

	// Store encrypted mnemonic
	err = storage.StoreBackup(encryptedMnemonic)
	if err != nil {
		logger.Error("Failed to store mnemonic backup: %v", err)
		return err
	}

	return nil
}

// RetrieveBackup retrieves and decrypts the mnemonic from decentralized storage.
func RetrieveBackup() (string, error) {
	// Retrieve encrypted mnemonic
	encryptedMnemonic, err := storage.RetrieveBackup()
	if err != nil {
		logger.Error("Failed to retrieve mnemonic backup: %v", err)
		return "", err
	}

	// Decrypt mnemonic
	mnemonic, err := DecryptMnemonic(encryptedMnemonic, "backupPassphrase")
	if err != nil {
		logger.Error("Failed to decrypt mnemonic backup: %v", err)
		return "", err
	}

	return mnemonic, nil
}

// generateSalt generates a random salt for key derivation.
func generateSalt() []byte {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		logger.Error("Failed to generate salt: %v", err)
		return nil
	}
	return salt
}

// deriveKey derives a key from the passphrase and salt using PBKDF2.
func deriveKey(passphrase string, salt []byte) ([]byte, error) {
	const keyLen = 32
	key := pbkdf2.Key([]byte(passphrase), salt, 4096, keyLen, sha256.New)
	return key, nil
}

// AltKeyDerive uses scrypt for an alternative key derivation method.
func AltKeyDerive(passphrase string, salt []byte) ([]byte, error) {
	const keyLen = 32
	key, err := scrypt.Key([]byte(passphrase), salt, 1<<15, 8, 1, keyLen)
	if err != nil {
		logger.Error("Failed to derive key using scrypt: %v", err)
		return nil, err
	}
	return key, nil
}
package wallet_creation

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
	"github.com/synnergy_network/blockchain/logger"
	"github.com/synnergy_network/blockchain/security"
	"github.com/synnergy_network/wallet/storage"
)

// GenerateMnemonic generates a mnemonic phrase using BIP39 standard.
func GenerateMnemonic() (string, error) {
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		logger.Error("Failed to generate entropy for mnemonic: %v", err)
		return "", err
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		logger.Error("Failed to generate mnemonic: %v", err)
		return "", err
	}

	return mnemonic, nil
}

// MnemonicToSeed converts a mnemonic phrase to a seed.
func MnemonicToSeed(mnemonic, passphrase string) []byte {
	return bip39.NewSeed(mnemonic, passphrase)
}

// EncryptMnemonic encrypts a mnemonic phrase using a user-defined passphrase.
func EncryptMnemonic(mnemonic, passphrase string) (string, error) {
	salt := generateSalt()
	key, err := deriveKey(passphrase, salt)
	if err != nil {
		return "", err
	}

	encryptedMnemonic, err := security.EncryptAES([]byte(mnemonic), key)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(encryptedMnemonic) + ":" + hex.EncodeToString(salt), nil
}

// DecryptMnemonic decrypts an encrypted mnemonic phrase using a user-defined passphrase.
func DecryptMnemonic(encryptedMnemonic, passphrase string) (string, error) {
	parts := strings.Split(encryptedMnemonic, ":")
	if len(parts) != 2 {
		return "", errors.New("invalid encrypted mnemonic format")
	}

	encMnemonicBytes, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", err
	}

	salt, err := hex.DecodeString(parts[1])
	if err != nil {
		return "", err
	}

	key, err := deriveKey(passphrase, salt)
	if err != nil {
		return "", err
	}

	decryptedMnemonic, err := security.DecryptAES(encMnemonicBytes, key)
	if err != nil {
		return "", err
	}

	return string(decryptedMnemonic), nil
}

// BackupMnemonic securely stores the mnemonic using decentralized storage.
func BackupMnemonic(mnemonic string) error {
	// Encrypt mnemonic before storing
	encryptedMnemonic, err := EncryptMnemonic(mnemonic, "backupPassphrase")
	if err != nil {
		logger.Error("Failed to encrypt mnemonic for backup: %v", err)
		return err
	}

	// Store encrypted mnemonic
	err = storage.StoreBackup(encryptedMnemonic)
	if err != nil {
		logger.Error("Failed to store mnemonic backup: %v", err)
		return err
	}

	return nil
}

// RetrieveBackup retrieves and decrypts the mnemonic from decentralized storage.
func RetrieveBackup() (string, error) {
	// Retrieve encrypted mnemonic
	encryptedMnemonic, err := storage.RetrieveBackup()
	if err != nil {
		logger.Error("Failed to retrieve mnemonic backup: %v", err)
		return "", err
	}

	// Decrypt mnemonic
	mnemonic, err := DecryptMnemonic(encryptedMnemonic, "backupPassphrase")
	if err != nil {
		logger.Error("Failed to decrypt mnemonic backup: %v", err)
		return "", err
	}

	return mnemonic, nil
}

// generateSalt generates a random salt for key derivation.
func generateSalt() []byte {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		logger.Error("Failed to generate salt: %v", err)
		return nil
	}
	return salt
}

// deriveKey derives a key from the passphrase and salt using PBKDF2.
func deriveKey(passphrase string, salt []byte) ([]byte, error) {
	const keyLen = 32
	key := pbkdf2.Key([]byte(passphrase), salt, 4096, keyLen, sha256.New)
	return key, nil
}

// AltKeyDerive uses scrypt for an alternative key derivation method.
func AltKeyDerive(passphrase string, salt []byte) ([]byte, error) {
	const keyLen = 32
	key, err := scrypt.Key([]byte(passphrase), salt, 1<<15, 8, 1, keyLen)
	if err != nil {
		logger.Error("Failed to derive key using scrypt: %v", err)
		return nil, err
	}
	return key, nil
}
package wallet_creation

import (
	"encoding/json"
	"errors"
	"github.com/synnergy_network/blockchain/crypto"
	"github.com/synnergy_network/blockchain/utils"
	"github.com/synnergy_network/file_storage/file_encryption"
	"github.com/synnergy_network/wallet/authentication"
	"github.com/synnergy_network/wallet/display"
	"github.com/synnergy_network/wallet/notifications"
	"github.com/synnergy_network/wallet/storage"
	"sync"
)

// CustomWallet represents a customizable wallet with enhanced features
type CustomWallet struct {
	Address    string
	PrivateKey []byte
	PublicKey  []byte
	Settings   WalletSettings
	mu         sync.Mutex
}

// WalletSettings contains customizable settings for the wallet
type WalletSettings struct {
	AutoBackupEnabled bool
	NotificationPreferences NotificationPreferences
	DisplayPreferences      DisplayPreferences
	SecuritySettings        SecuritySettings
}

// NotificationPreferences represents the notification preferences for the wallet
type NotificationPreferences struct {
	EmailNotifications bool
	PushNotifications  bool
	SMSNotifications   bool
}

// DisplayPreferences represents the display settings for the wallet
type DisplayPreferences struct {
	Theme       string
	Currency    string
	TimeFormat  string
	Language    string
}

// SecuritySettings represents the security settings for the wallet
type SecuritySettings struct {
	MultiFactorAuthEnabled bool
	BiometricAuthEnabled   bool
	Passphrase             string
}

// NewCustomWallet creates a new customizable wallet with default settings
func NewCustomWallet() (*CustomWallet, error) {
	privKey, pubKey, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	address := utils.GenerateAddress(pubKey)
	defaultSettings := WalletSettings{
		AutoBackupEnabled: true,
		NotificationPreferences: NotificationPreferences{
			EmailNotifications: true,
			PushNotifications:  true,
			SMSNotifications:   false,
		},
		DisplayPreferences: DisplayPreferences{
			Theme:      "light",
			Currency:   "USD",
			TimeFormat: "24h",
			Language:   "en",
		},
		SecuritySettings: SecuritySettings{
			MultiFactorAuthEnabled: true,
			BiometricAuthEnabled:   true,
			Passphrase:             "",
		},
	}
	return &CustomWallet{
		Address:    address,
		PrivateKey: privKey,
		PublicKey:  pubKey,
		Settings:   defaultSettings,
	}, nil
}

// UpdateSettings updates the wallet settings
func (cw *CustomWallet) UpdateSettings(newSettings WalletSettings) error {
	cw.mu.Lock()
	defer cw.mu.Unlock()

	// Validate new settings
	if newSettings.DisplayPreferences.Currency == "" || newSettings.DisplayPreferences.Theme == "" {
		return errors.New("invalid display settings")
	}
	if newSettings.SecuritySettings.Passphrase != "" {
		hashedPass, err := crypto.HashPassword(newSettings.SecuritySettings.Passphrase)
		if err != nil {
			return err
		}
		newSettings.SecuritySettings.Passphrase = hashedPass
	}
	cw.Settings = newSettings
	return nil
}

// GetSettings retrieves the current wallet settings
func (cw *CustomWallet) GetSettings() WalletSettings {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	return cw.Settings
}

// EnableAutoBackup enables or disables automatic backups for the wallet
func (cw *CustomWallet) EnableAutoBackup(enable bool) {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	cw.Settings.AutoBackupEnabled = enable
}

// BackupWallet creates a backup of the wallet data
func (cw *CustomWallet) BackupWallet(backupPath string) error {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	walletData, err := json.Marshal(cw)
	if err != nil {
		return err
	}
	encryptedData, err := file_encryption.Encrypt(walletData, []byte(cw.Settings.SecuritySettings.Passphrase))
	if err != nil {
		return err
	}
	return storage.SaveToFile(backupPath, encryptedData)
}

// RestoreWallet restores the wallet from a backup file
func (cw *CustomWallet) RestoreWallet(backupPath, passphrase string) error {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	encryptedData, err := storage.LoadFromFile(backupPath)
	if err != nil {
		return err
	}
	decryptedData, err := file_encryption.Decrypt(encryptedData, []byte(passphrase))
	if err != nil {
		return err
	}
	return json.Unmarshal(decryptedData, &cw)
}

// SetNotificationPreferences updates the notification preferences for the wallet
func (cw *CustomWallet) SetNotificationPreferences(prefs NotificationPreferences) {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	cw.Settings.NotificationPreferences = prefs
	notifications.UpdatePreferences(cw.Address, prefs.EmailNotifications, prefs.PushNotifications, prefs.SMSNotifications)
}

// SetDisplayPreferences updates the display preferences for the wallet
func (cw *CustomWallet) SetDisplayPreferences(prefs DisplayPreferences) {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	cw.Settings.DisplayPreferences = prefs
	display.ApplySettings(prefs.Theme, prefs.Currency, prefs.TimeFormat, prefs.Language)
}

// EnableMultiFactorAuth enables or disables multi-factor authentication
func (cw *CustomWallet) EnableMultiFactorAuth(enable bool) {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	cw.Settings.SecuritySettings.MultiFactorAuthEnabled = enable
	authentication.ConfigureMFA(cw.Address, enable)
}

// EnableBiometricAuth enables or disables biometric authentication
func (cw *CustomWallet) EnableBiometricAuth(enable bool) {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	cw.Settings.SecuritySettings.BiometricAuthEnabled = enable
	authentication.ConfigureBiometricAuth(cw.Address, enable)
}
package wallet_creation

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/synnergy_network/blockchain/crypto"
	"github.com/synnergy_network/blockchain/utils"
	"github.com/synnergy_network/cryptography/encryption"
	"github.com/synnergy_network/cryptography/hash"
	"github.com/synnergy_network/cryptography/keys"
	"github.com/synnergy_network/cryptography/signature"
	"github.com/synnergy_network/storage/files"
	"github.com/synnergy_network/wallet/security"
	"golang.org/x/crypto/scrypt"
	"log"
	"os"
	"strings"
)

const (
	SaltSize       = 32
	KeySize        = 32
	MnemonicLength = 12
)

type Wallet struct {
	PrivateKey  string
	PublicKey   string
	Address     string
	Mnemonic    string
	EncryptedPK string
}

// GenerateSalt generates a new salt for key derivation.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

// DeriveKey derives a key from the password using scrypt.
func DeriveKey(password, salt []byte) ([]byte, error) {
	return scrypt.Key(password, salt, 32768, 8, 1, KeySize)
}

// GenerateMnemonic generates a new mnemonic phrase for wallet recovery.
func GenerateMnemonic() (string, error) {
	entropy := make([]byte, MnemonicLength)
	_, err := rand.Read(entropy)
	if err != nil {
		return "", err
	}
	mnemonic, err := crypto.NewMnemonic(entropy)
	if err != nil {
		return "", err
	}
	return mnemonic, nil
}

// GenerateKeypair generates a new ECDSA keypair.
func GenerateKeypair() (string, string, error) {
	privateKey, publicKey, err := keys.GenerateECDSAKeypair()
	if err != nil {
		return "", "", err
	}
	return privateKey, publicKey, nil
}

// EncryptPrivateKey encrypts the private key using AES.
func EncryptPrivateKey(privateKey, passphrase string) (string, error) {
	salt, err := GenerateSalt()
	if err != nil {
		return "", err
	}
	key, err := DeriveKey([]byte(passphrase), salt)
	if err != nil {
		return "", err
	}
	encryptedPK, err := encryption.AESEncrypt([]byte(privateKey), key)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(salt) + ":" + hex.EncodeToString(encryptedPK), nil
}

// DecryptPrivateKey decrypts the private key using AES.
func DecryptPrivateKey(encryptedPK, passphrase string) (string, error) {
	parts := strings.Split(encryptedPK, ":")
	if len(parts) != 2 {
		return "", errors.New("invalid encrypted private key format")
	}
	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", err
	}
	key, err := DeriveKey([]byte(passphrase), salt)
	if err != nil {
		return "", err
	}
	encryptedKey, err := hex.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	decryptedPK, err := encryption.AESDecrypt(encryptedKey, key)
	if err != nil {
		return "", err
	}
	return string(decryptedPK), nil
}

// CreateWallet initializes a new wallet with a mnemonic phrase, keypair, and encrypted private key.
func CreateWallet(passphrase string) (*Wallet, error) {
	mnemonic, err := GenerateMnemonic()
	if err != nil {
		return nil, err
	}

	privateKey, publicKey, err := GenerateKeypair()
	if err != nil {
		return nil, err
	}

	address := GenerateAddress(publicKey)
	encryptedPK, err := EncryptPrivateKey(privateKey, passphrase)
	if err != nil {
		return nil, err
	}

	return &Wallet{
		PrivateKey:  privateKey,
		PublicKey:   publicKey,
		Address:     address,
		Mnemonic:    mnemonic,
		EncryptedPK: encryptedPK,
	}, nil
}

// GenerateAddress generates a wallet address from the public key.
func GenerateAddress(publicKey string) string {
	hash := sha256.Sum256([]byte(publicKey))
	return hex.EncodeToString(hash[:])
}

// SaveWallet saves the wallet to a secure file.
func SaveWallet(wallet *Wallet, filePath string) error {
	data := []byte(wallet.Mnemonic + "\n" + wallet.EncryptedPK + "\n" + wallet.Address)
	return files.SaveFile(filePath, data)
}

// LoadWallet loads a wallet from a secure file.
func LoadWallet(filePath, passphrase string) (*Wallet, error) {
	data, err := files.LoadFile(filePath)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(string(data), "\n")
	if len(parts) != 3 {
		return nil, errors.New("invalid wallet file format")
	}
	mnemonic := parts[0]
	encryptedPK := parts[1]
	address := parts[2]
	privateKey, err := DecryptPrivateKey(encryptedPK, passphrase)
	if err != nil {
		return nil, err
	}
	publicKey := keys.GetPublicKey(privateKey)
	return &Wallet{
		PrivateKey:  privateKey,
		PublicKey:   publicKey,
		Address:     address,
		Mnemonic:    mnemonic,
		EncryptedPK: encryptedPK,
	}, nil
}

// RecoverWallet recovers a wallet using a mnemonic phrase and passphrase.
func RecoverWallet(mnemonic, passphrase string) (*Wallet, error) {
	seed := crypto.MnemonicToSeed(mnemonic, passphrase)
	privateKey, publicKey, err := keys.GenerateECDSAKeypairFromSeed(seed)
	if err != nil {
		return nil, err
	}
	address := GenerateAddress(publicKey)
	encryptedPK, err := EncryptPrivateKey(privateKey, passphrase)
	if err != nil {
		return nil, err
	}
	return &Wallet{
		PrivateKey:  privateKey,
		PublicKey:   publicKey,
		Address:     address,
		Mnemonic:    mnemonic,
		EncryptedPK: encryptedPK,
	}, nil
}
