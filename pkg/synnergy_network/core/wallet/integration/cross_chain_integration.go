package integration

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/crypto"
)

// CrossChainWallet represents a wallet with cross-chain capabilities.
type CrossChainWallet struct {
	privateKey *ecdsa.PrivateKey
	PublicKey  ecdsa.PublicKey
	Address    string
	Chains     map[string]*Chain // Supports multiple chains
	mutex      sync.RWMutex
}

// Chain represents a blockchain with its own balance and address.
type Chain struct {
	Name    string
	Address string
	Balance *big.Int
}

// NewCrossChainWallet generates a new CrossChainWallet.
func NewCrossChainWallet() (*CrossChainWallet, error) {
	privateKey, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	publicKey := privateKey.PublicKey
	address := crypto.PubkeyToAddress(publicKey).Hex()

	return &CrossChainWallet{
		privateKey: privateKey,
		PublicKey:  publicKey,
		Address:    address,
		Chains:     make(map[string]*Chain),
	}, nil
}

// AddChain adds a new blockchain to the wallet.
func (w *CrossChainWallet) AddChain(name string, address string) error {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	if _, exists := w.Chains[name]; exists {
		return fmt.Errorf("chain %s already exists", name)
	}

	w.Chains[name] = &Chain{
		Name:    name,
		Address: address,
		Balance: big.NewInt(0),
	}

	return nil
}

// GetBalance returns the balance for a specific blockchain.
func (w *CrossChainWallet) GetBalance(chainName string) (*big.Int, error) {
	w.mutex.RLock()
	defer w.mutex.RUnlock()

	chain, exists := w.Chains[chainName]
	if !exists {
		return nil, fmt.Errorf("chain %s not found", chainName)
	}

	return new(big.Int).Set(chain.Balance), nil
}

// UpdateBalance updates the balance for a specific blockchain.
func (w *CrossChainWallet) UpdateBalance(chainName string, balance *big.Int) error {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	chain, exists := w.Chains[chainName]
	if !exists {
		return fmt.Errorf("chain %s not found", chainName)
	}

	chain.Balance.Set(balance)
	return nil
}

// SignTransaction signs a transaction for a specific blockchain.
func (w *CrossChainWallet) SignTransaction(chainName string, txHash []byte) ([]byte, error) {
	w.mutex.RLock()
	defer w.mutex.RUnlock()

	chain, exists := w.Chains[chainName]
	if !exists {
		return nil, fmt.Errorf("chain %s not found", chainName)
	}

	r, s, err := ecdsa.Sign(rand.Reader, w.privateKey, txHash)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %v", err)
	}

	signature := append(r.Bytes(), s.Bytes()...)
	chain.Balance.Sub(chain.Balance, big.NewInt(1)) // Deduct transaction fee (example logic)

	return signature, nil
}

// VerifyTransaction verifies a signed transaction.
func (w *CrossChainWallet) VerifyTransaction(chainName string, txHash, signature []byte) (bool, error) {
	w.mutex.RLock()
	defer w.mutex.RUnlock()

	chain, exists := w.Chains[chainName]
	if !exists {
		return false, fmt.Errorf("chain %s not found", chainName)
	}

	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])

	valid := ecdsa.Verify(&w.PublicKey, txHash, r, s)
	if !valid {
		return false, errors.New("invalid signature")
	}

	// Update chain's balance to reflect the verification success (example logic)
	chain.Balance.Add(chain.Balance, big.NewInt(1))

	return true, nil
}

// TransferFunds transfers funds between two blockchains within the wallet.
func (w *CrossChainWallet) TransferFunds(fromChain, toChain string, amount *big.Int) error {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	from, exists := w.Chains[fromChain]
	if !exists {
		return fmt.Errorf("source chain %s not found", fromChain)
	}

	to, exists := w.Chains[toChain]
	if !exists {
		return fmt.Errorf("destination chain %s not found", toChain)
	}

	if from.Balance.Cmp(amount) < 0 {
		return fmt.Errorf("insufficient funds in chain %s", fromChain)
	}

	from.Balance.Sub(from.Balance, amount)
	to.Balance.Add(to.Balance, amount)

	return nil
}

func main() {
	// Example usage
	wallet, err := NewCrossChainWallet()
	if err != nil {
		fmt.Println("Error creating wallet:", err)
		return
	}

	fmt.Println("New wallet address:", wallet.Address)

	err = wallet.AddChain("Ethereum", "0x...")
	if err != nil {
		fmt.Println("Error adding Ethereum chain:", err)
		return
	}

	err = wallet.AddChain("BinanceSmartChain", "0x...")
	if err != nil {
		fmt.Println("Error adding Binance Smart Chain:", err)
		return
	}

	wallet.UpdateBalance("Ethereum", big.NewInt(1000))
	wallet.UpdateBalance("BinanceSmartChain", big.NewInt(500))

	fmt.Println("Ethereum balance:", wallet.GetBalance("Ethereum"))
	fmt.Println("Binance Smart Chain balance:", wallet.GetBalance("BinanceSmartChain"))

	err = wallet.TransferFunds("Ethereum", "BinanceSmartChain", big.NewInt(100))
	if err != nil {
		fmt.Println("Error transferring funds:", err)
		return
	}

	fmt.Println("Balances after transfer:")
	fmt.Println("Ethereum balance:", wallet.GetBalance("Ethereum"))
	fmt.Println("Binance Smart Chain balance:", wallet.GetBalance("BinanceSmartChain"))
}
