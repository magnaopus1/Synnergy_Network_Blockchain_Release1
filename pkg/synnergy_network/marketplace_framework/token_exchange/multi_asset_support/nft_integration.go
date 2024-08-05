package multi_asset_support

import (
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/scrypt"
)

// NFT represents a non-fungible token in the system.
type NFT struct {
	TokenID      *big.Int
	MetadataURI  string
	Owner        common.Address
	ContractAddr common.Address
}

// NFTManager manages NFTs in the system.
type NFTManager struct {
	NFTs           map[string]NFT
	Client         *rpc.Client
	Auth           *bind.TransactOpts
	ContractAddr   common.Address
	mu             sync.Mutex
}

// NewNFTManager creates a new instance of NFTManager.
func NewNFTManager(contractAddress, privateKey string, client *rpc.Client) (*NFTManager, error) {
	auth, err := bind.NewTransactorWithChainID(strings.NewReader(privateKey), nil)
	if err != nil {
		return nil, err
	}

	return &NFTManager{
		NFTs:         make(map[string]NFT),
		Client:       client,
		Auth:         auth,
		ContractAddr: common.HexToAddress(contractAddress),
	}, nil
}

// MintNFT mints a new NFT and adds it to the system.
func (nm *NFTManager) MintNFT(tokenID *big.Int, metadataURI string, owner common.Address) error {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	tokenIDStr := tokenID.String()
	if _, exists := nm.NFTs[tokenIDStr]; exists {
		return errors.New("NFT already exists")
	}

	nm.NFTs[tokenIDStr] = NFT{
		TokenID:     tokenID,
		MetadataURI: metadataURI,
		Owner:       owner,
		ContractAddr: nm.ContractAddr,
	}

	return nil
}

// TransferNFT transfers an NFT from one owner to another.
func (nm *NFTManager) TransferNFT(tokenID *big.Int, from, to common.Address) error {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	tokenIDStr := tokenID.String()
	nft, exists := nm.NFTs[tokenIDStr]
	if !exists {
		return errors.New("NFT not found")
	}

	if nft.Owner != from {
		return errors.New("transfer not authorized by the owner")
	}

	nft.Owner = to
	nm.NFTs[tokenIDStr] = nft
	return nil
}

// GetNFT retrieves an NFT from the system.
func (nm *NFTManager) GetNFT(tokenID *big.Int) (NFT, error) {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	tokenIDStr := tokenID.String()
	if nft, exists := nm.NFTs[tokenIDStr]; exists {
		return nft, nil
	}

	return NFT{}, errors.New("NFT not found")
}

// UpdateNFTMetadata updates the metadata URI of an existing NFT.
func (nm *NFTManager) UpdateNFTMetadata(tokenID *big.Int, metadataURI string) error {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	tokenIDStr := tokenID.String()
	nft, exists := nm.NFTs[tokenIDStr]
	if !exists {
		return errors.New("NFT not found")
	}

	nft.MetadataURI = metadataURI
	nm.NFTs[tokenIDStr] = nft
	return nil
}

// SaveNFTsToFile saves the current state of NFTs to a file.
func (nm *NFTManager) SaveNFTsToFile(filename string) error {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	data, err := json.MarshalIndent(nm.NFTs, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

// LoadNFTsFromFile loads NFTs from a file.
func (nm *NFTManager) LoadNFTsFromFile(filename string) error {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	var nfts map[string]NFT
	if err := json.Unmarshal(data, &nfts); err != nil {
		return err
	}

	nm.NFTs = nfts
	return nil
}

// SecureData encrypts data using scrypt for key derivation and AES for encryption.
func SecureData(data []byte, passphrase string) ([]byte, error) {
	salt := []byte("some_salt")
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

	return gcm.Seal(nonce, nonce, data, nil), nil
}

// MonitorNFTs periodically monitors and updates NFT data.
func (nm *NFTManager) MonitorNFTs(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			nm.mu.Lock()
			for tokenIDStr, nft := range nm.NFTs {
				newOwner := fetchLatestOwnerFromBlockchain(nft.ContractAddr, nft.TokenID)
				nft.Owner = newOwner
				nm.NFTs[tokenIDStr] = nft
				fmt.Printf("Updated owner for NFT %s\n", tokenIDStr)
			}
			nm.mu.Unlock()
		}
	}
}

func fetchLatestOwnerFromBlockchain(contractAddr common.Address, tokenID *big.Int) common.Address {
	// Simulate fetching data from the blockchain
	return common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
}
