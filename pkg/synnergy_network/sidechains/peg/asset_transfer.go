package peg

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"sync"
	"log"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/crypto"
)

// AssetTransfer represents the asset transfer mechanism.
type AssetTransfer struct {
	assets map[string]*Asset
	mutex  sync.Mutex
	logger *log.Logger
}

// NewAssetTransfer creates a new instance of AssetTransfer.
func NewAssetTransfer(logger *log.Logger) *AssetTransfer {
	return &AssetTransfer{
		assets: make(map[string]*Asset),
		logger: logger,
	}
}

// TransferAsset transfers the specified amount of the asset from one owner to another.
func (at *AssetTransfer) TransferAsset(name string, from string, to string, amount *big.Int) (string, error) {
	at.mutex.Lock()
	defer at.mutex.Unlock()

	asset, exists := at.assets[name]
	if !exists {
		return "", errors.New("asset not found")
	}

	if asset.Balance[from].Cmp(amount) < 0 {
		return "", errors.New("insufficient balance")
	}

	asset.Balance[from].Sub(asset.Balance[from], amount)
	if _, exists := asset.Balance[to]; !exists {
		asset.Balance[to] = big.NewInt(0)
	}
	asset.Balance[to].Add(asset.Balance[to], amount)

	transferID, err := generateTransferID(name, from, to, amount)
	if err != nil {
		return "", err
	}

	transfer := &AssetTransferRecord{
		ID:        transferID,
		AssetName: name,
		From:      from,
		To:        to,
		Amount:    amount,
		Timestamp: time.Now(),
	}

	asset.TransferHistory = append(asset.TransferHistory, transfer)

	at.logger.Println("Asset transferred:", transfer)
	return transferID, nil
}

// generateTransferID generates a unique ID for the asset transfer using its details.
func generateTransferID(name, from, to string, amount *big.Int) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := sha256.New()
	hash.Write([]byte(name))
	hash.Write([]byte(from))
	hash.Write([]byte(to))
	hash.Write(amount.Bytes())
	hash.Write(salt)
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// Asset represents an asset within the Synnergy Network.
type Asset struct {
	ID             string
	Name           string
	TotalSupply    *big.Int
	Owner          string
	InitialSupply  *big.Int
	Balance        map[string]*big.Int
	TransferHistory []*AssetTransferRecord
}

// AssetTransferRecord represents a record of an asset transfer.
type AssetTransferRecord struct {
	ID        string
	AssetName string
	From      string
	To        string
	Amount    *big.Int
	Timestamp time.Time
}

// CryptoUtils provides cryptographic utilities for the Synnergy Network.
type CryptoUtils struct{}

// GenerateKeyPair generates a new public-private key pair.
func (cu *CryptoUtils) GenerateKeyPair() (string, string, error) {
	privateKey, err := crypto.GeneratePrivateKey()
	if err != nil {
		return "", "", err
	}

	publicKey := crypto.GeneratePublicKey(privateKey)
	return privateKey, publicKey, nil
}

// EncryptData encrypts data using the specified key.
func (cu *CryptoUtils) EncryptData(key, data string) (string, error) {
	encryptedData, err := crypto.EncryptAES(key, data)
	if err != nil {
		return "", err
	}
	return encryptedData, nil
}

// DecryptData decrypts data using the specified key.
func (cu *CryptoUtils) DecryptData(key, encryptedData string) (string, error) {
	decryptedData, err := crypto.DecryptAES(key, encryptedData)
	if err != nil {
		return "", err
	}
	return decryptedData, nil
}
