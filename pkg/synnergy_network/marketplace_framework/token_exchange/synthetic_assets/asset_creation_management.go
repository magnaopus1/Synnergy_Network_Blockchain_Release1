package synthetic_assets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rpc"
)

// SyntheticAsset represents a synthetic asset in the blockchain network.
type SyntheticAsset struct {
	AssetID      string
	Name         string
	Symbol       string
	TotalSupply  *big.Int
	Owner        common.Address
	MetadataURI  string
	CreationDate time.Time
}

// AssetManager handles the creation, transfer, and management of synthetic assets.
type AssetManager struct {
	Assets map[string]SyntheticAsset
	Client *rpc.Client
	Auth   *bind.TransactOpts
	mu     sync.Mutex
}

// NewAssetManager initializes a new AssetManager.
func NewAssetManager(privateKey string, client *rpc.Client) (*AssetManager, error) {
	auth, err := bind.NewTransactorWithChainID(strings.NewReader(privateKey), nil)
	if err != nil {
		return nil, err
	}

	return &AssetManager{
		Assets: make(map[string]SyntheticAsset),
		Client: client,
		Auth:   auth,
	}, nil
}

// CreateAsset creates a new synthetic asset.
func (am *AssetManager) CreateAsset(assetID, name, symbol string, totalSupply *big.Int, owner common.Address, metadataURI string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	if _, exists := am.Assets[assetID]; exists {
		return errors.New("asset already exists")
	}

	am.Assets[assetID] = SyntheticAsset{
		AssetID:      assetID,
		Name:         name,
		Symbol:       symbol,
		TotalSupply:  totalSupply,
		Owner:        owner,
		MetadataURI:  metadataURI,
		CreationDate: time.Now(),
	}

	return nil
}

// TransferAsset transfers ownership of a synthetic asset.
func (am *AssetManager) TransferAsset(assetID string, from, to common.Address) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	asset, exists := am.Assets[assetID]
	if !exists {
		return errors.New("asset not found")
	}

	if asset.Owner != from {
		return errors.New("transfer not authorized by the owner")
	}

	asset.Owner = to
	am.Assets[assetID] = asset
	return nil
}

// GetAsset retrieves a synthetic asset by its ID.
func (am *AssetManager) GetAsset(assetID string) (SyntheticAsset, error) {
	am.mu.Lock()
	defer am.mu.Unlock()

	asset, exists := am.Assets[assetID]
	if !exists {
		return SyntheticAsset{}, errors.New("asset not found")
	}

	return asset, nil
}

// UpdateAssetMetadata updates the metadata URI of a synthetic asset.
func (am *AssetManager) UpdateAssetMetadata(assetID, metadataURI string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	asset, exists := am.Assets[assetID]
	if !exists {
		return errors.New("asset not found")
	}

	asset.MetadataURI = metadataURI
	am.Assets[assetID] = asset
	return nil
}

// SecureData encrypts data using AES-GCM with a key derived from a passphrase using scrypt.
func SecureData(data []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

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

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return append(salt, ciphertext...), nil
}

// DecryptData decrypts data encrypted with SecureData.
func DecryptData(encryptedData []byte, passphrase string) ([]byte, error) {
	if len(encryptedData) < 16 {
		return nil, errors.New("invalid data")
	}

	salt := encryptedData[:16]
	ciphertext := encryptedData[16:]

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
		return nil, errors.New("invalid data")
	}

	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Argon2Hash creates a hash using Argon2.
func Argon2Hash(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
}

// VerifyArgon2Hash verifies a password against an Argon2 hash.
func VerifyArgon2Hash(password, hash, salt []byte) bool {
	return hex.EncodeToString(Argon2Hash(password, salt)) == hex.EncodeToString(hash)
}

// ScryptHash creates a hash using scrypt.
func ScryptHash(password, salt []byte) ([]byte, error) {
	return scrypt.Key(password, salt, 32768, 8, 1, 32)
}

// VerifyScryptHash verifies a password against a scrypt hash.
func VerifyScryptHash(password, hash, salt []byte) (bool, error) {
	computedHash, err := ScryptHash(password, salt)
	if err != nil {
		return false, err
	}
	return hex.EncodeToString(computedHash) == hex.EncodeToString(hash), nil
}

// Integration with CLI, SDK, and interfaces can be added as necessary to avoid circular dependencies.
