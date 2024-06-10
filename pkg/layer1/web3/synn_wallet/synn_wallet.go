package syn_wallet

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// SynWallet represents a Synthron wallet.
type SynWallet struct {
	address common.Address
	key     *ecdsa.PrivateKey
}

// NewSynWallet generates a new Synthron wallet.
func NewSynWallet() (*SynWallet, error) {
	key, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	address := crypto.PubkeyToAddress(key.PublicKey)
	return &SynWallet{
		address: address,
		key:     key,
	}, nil
}

// GetAddress returns the wallet's address.
func (sw *SynWallet) GetAddress() common.Address {
	return sw.address
}

// SignTransaction signs a transaction with the wallet's private key.
func (sw *SynWallet) SignTransaction(txData []byte) ([]byte, error) {
	signature, err := crypto.Sign(crypto.Keccak256(txData), sw.key)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// ExportPrivateKey exports the wallet's private key in JSON format.
func (sw *SynWallet) ExportPrivateKey(password string) ([]byte, error) {
	ks := keystore.NewKeyStore("", keystore.StandardScryptN, keystore.StandardScryptP)
	account := ks.NewAccount(sw.key, password)
	return ks.Export(account, password, password)
}

// LoadWalletFromPrivateKey loads a Synthron wallet from a private key.
func LoadWalletFromPrivateKey(privateKeyStr, password string) (*SynWallet, error) {
	ks := keystore.NewKeyStore("", keystore.StandardScryptN, keystore.StandardScryptP)
	keyJSON := []byte(privateKeyStr)
	key, err := ks.Import(keyJSON, password, password)
	if err != nil {
		return nil, err
	}

	address := key.Address
	return &SynWallet{
		address: address,
		key:     key.PrivateKey,
	}, nil
}

// Example usage:
func main() {
	// Create a new Synthron wallet
	wallet, err := NewSynWallet()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Wallet Address: %s\n", wallet.GetAddress().Hex())

	// Sign a transaction data
	txData := []byte("Transaction data to sign")
	signature, err := wallet.SignTransaction(txData)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Transaction Signature: %x\n", signature)

	// Export and load wallet from private key (for persistence)
	privateKeyStr, err := wallet.ExportPrivateKey("your_password")
	if err != nil {
		log.Fatal(err)
	}

	loadedWallet, err := LoadWalletFromPrivateKey(string(privateKeyStr), "your_password")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Loaded Wallet Address: %s\n", loadedWallet.GetAddress().Hex())
}
