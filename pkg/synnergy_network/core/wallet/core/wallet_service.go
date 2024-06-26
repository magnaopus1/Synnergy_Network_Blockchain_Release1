package core

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/miguelmota/go-solidity-sha3"
	"golang.org/x/crypto/scrypt"
	bip39 "github.com/tyler-smith/go-bip39"
	hdkeychain "github.com/btcsuite/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"golang.org/x/crypto/argon2"
	"github.com/google/uuid"
	"encoding/json"
	"github.com/gorilla/mux"
	"net/http"
)

type WalletService struct {
	Wallets map[string]*Wallet
}

type Wallet struct {
	PrivateKey *ecdsa.PrivateKey
	Address    string
	Balance    float64
}

type Transaction struct {
	From      string
	To        string
	Amount    float64
	Timestamp time.Time
}

func NewWalletService() *WalletService {
	return &WalletService{
		Wallets: make(map[string]*Wallet),
	}
}

func (ws *WalletService) CreateWallet() (*Wallet, error) {
	privateKey, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate keypair: %v", err)
	}

	address := crypto.PubkeyToAddress(privateKey.PublicKey).Hex()
	wallet := &Wallet{
		PrivateKey: privateKey,
		Address:    address,
		Balance:    0.0,
	}
	ws.Wallets[address] = wallet
	return wallet, nil
}

func (ws *WalletService) GetWallet(address string) (*Wallet, error) {
	wallet, exists := ws.Wallets[address]
	if !exists {
		return nil, errors.New("wallet not found")
	}
	return wallet, nil
}

func (ws *WalletService) SendTransaction(from, to string, amount float64) (string, error) {
	fromWallet, err := ws.GetWallet(from)
	if err != nil {
		return "", err
	}
	if amount <= 0 {
		return "", errors.New("amount must be greater than 0")
	}
	if amount > fromWallet.Balance {
		return "", errors.New("insufficient balance")
	}

	tx := &Transaction{
		From:      from,
		To:        to,
		Amount:    amount,
		Timestamp: time.Now(),
	}
	hash := sha256.Sum256([]byte(fmt.Sprintf("%s%s%f%s", from, to, amount, tx.Timestamp)))
	signature, err := crypto.Sign(hash[:], fromWallet.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign transaction: %v", err)
	}

	toWallet, err := ws.GetWallet(to)
	if err != nil {
		return "", err
	}

	fromWallet.Balance -= amount
	toWallet.Balance += amount

	txID := hex.EncodeToString(hash[:])
	log.Printf("Transaction %s: %s sent %f to %s", txID, from, amount, to)
	return txID, nil
}

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

func WalletRecovery(mnemonic string) (*Wallet, error) {
	seed := bip39.NewSeed(mnemonic, "")
	privateKey, err := crypto.ToECDSA(seed)
	if err != nil {
		return nil, fmt.Errorf("failed to recover private key: %v", err)
	}

	address := crypto.PubkeyToAddress(privateKey.PublicKey).Hex()
	wallet := &Wallet{
		PrivateKey: privateKey,
		Address:    address,
		Balance:    0.0,
	}
	return wallet, nil
}

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

func EncryptMnemonic(mnemonic, passphrase string) (string, error) {
	encrypted, err := EncryptData(mnemonic, passphrase)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt mnemonic: %v", err)
	}

	return fmt.Sprintf("%x", encrypted), nil
}

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

func BlockchainRecoveryProtocol(mnemonics []string) error {
	// Implement blockchain state recovery logic using mnemonics
	// This is a placeholder function to be filled with actual recovery logic
	return nil
}

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

// API Handlers

func (ws *WalletService) CreateWalletHandler(w http.ResponseWriter, r *http.Request) {
	wallet, err := ws.CreateWallet()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	walletJSON, err := json.Marshal(wallet)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(walletJSON)
}

func (ws *WalletService) GetWalletHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	address := vars["address"]

	wallet, err := ws.GetWallet(address)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	walletJSON, err := json.Marshal(wallet)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(walletJSON)
}

func (ws *WalletService) SendTransactionHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	from := vars["from"]
	to := vars["to"]
	amount := vars["amount"]

	amountFloat, err := strconv.ParseFloat(amount, 64)
	if err != nil {
		http.Error(w, "Invalid amount", http.StatusBadRequest)
		return
	}

	txID, err := ws.SendTransaction(from, to, amountFloat)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(txID))
}

func main() {
	r := mux.NewRouter()
	ws := NewWalletService()

	r.HandleFunc("/wallets", ws.CreateWalletHandler).Methods("POST")
	r.HandleFunc("/wallets/{address}", ws.GetWalletHandler).Methods("GET")
	r.HandleFunc("/wallets/{from}/send/{to}/{amount}", ws.SendTransactionHandler).Methods("POST")

	log.Fatal(http.ListenAndServe(":8080", r))
}
