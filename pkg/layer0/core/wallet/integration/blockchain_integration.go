package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/miguelmota/go-solidity-sha3"
)

// Wallet represents a blockchain wallet.
type Wallet struct {
	privateKey *ecdsa.PrivateKey
	PublicKey  ecdsa.PublicKey
	Address    string
}

// NewWallet generates a new Wallet.
func NewWallet() (*Wallet, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	publicKey := privateKey.PublicKey
	address := publicKeyToAddress(&publicKey)

	return &Wallet{
		privateKey: privateKey,
		PublicKey:  publicKey,
		Address:    address,
	}, nil
}

// publicKeyToAddress generates an address from a public key.
func publicKeyToAddress(pubKey *ecdsa.PublicKey) string {
	pubKeyBytes := crypto.FromECDSAPub(pubKey)
	hash := crypto.Keccak256Hash(pubKeyBytes[1:])
	return hex.EncodeToString(hash.Bytes()[12:])
}

// SignMessage signs a message with the wallet's private key.
func (w *Wallet) SignMessage(msg []byte) (r, s *big.Int, err error) {
	hash := sha256.Sum256(msg)
	r, s, err = ecdsa.Sign(rand.Reader, w.privateKey, hash[:])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign message: %v", err)
	}
	return r, s, nil
}

// VerifySignature verifies a message signature.
func (w *Wallet) VerifySignature(msg []byte, r, s *big.Int) bool {
	hash := sha256.Sum256(msg)
	return ecdsa.Verify(&w.PublicKey, hash[:], r, s)
}

// BalanceManager manages the balance of wallets.
type BalanceManager struct {
	balances map[string]*big.Int
	mutex    sync.RWMutex
}

// NewBalanceManager creates a new BalanceManager.
func NewBalanceManager() *BalanceManager {
	return &BalanceManager{
		balances: make(map[string]*big.Int),
	}
}

// GetBalance returns the balance of a wallet address.
func (bm *BalanceManager) GetBalance(address string) *big.Int {
	bm.mutex.RLock()
	defer bm.mutex.RUnlock()

	balance, exists := bm.balances[address]
	if !exists {
		return big.NewInt(0)
	}
	return new(big.Int).Set(balance)
}

// SetBalance sets the balance of a wallet address.
func (bm *BalanceManager) SetBalance(address string, balance *big.Int) {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()

	bm.balances[address] = new(big.Int).Set(balance)
}

// AddBalance adds an amount to a wallet's balance.
func (bm *BalanceManager) AddBalance(address string, amount *big.Int) {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()

	if _, exists := bm.balances[address]; !exists {
		bm.balances[address] = new(big.Int)
	}
	bm.balances[address].Add(bm.balances[address], amount)
}

// SubtractBalance subtracts an amount from a wallet's balance.
func (bm *BalanceManager) SubtractBalance(address string, amount *big.Int) error {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()

	if _, exists := bm.balances[address]; !exists {
		return errors.New("wallet address not found")
	}
	if bm.balances[address].Cmp(amount) < 0 {
		return errors.New("insufficient funds")
	}
	bm.balances[address].Sub(bm.balances[address], amount)
	return nil
}

// Transaction represents a blockchain transaction.
type Transaction struct {
	From      string
	To        string
	Amount    *big.Int
	Signature []byte
}

// NewTransaction creates a new transaction.
func NewTransaction(from, to string, amount *big.Int, wallet *Wallet) (*Transaction, error) {
	tx := &Transaction{
		From:   from,
		To:     to,
		Amount: amount,
	}

	signature, err := wallet.SignMessage(tx.hash())
	if err != nil {
		return nil, err
	}
	tx.Signature = signature

	return tx, nil
}

// hash generates a hash of the transaction.
func (tx *Transaction) hash() []byte {
	data := fmt.Sprintf("%s%s%s", tx.From, tx.To, tx.Amount.String())
	hash := solsha3.SoliditySHA3(
		[]string{"address", "address", "uint256"},
		[]interface{}{tx.From, tx.To, tx.Amount},
	)
	return hash
}

// Verify verifies the transaction's signature.
func (tx *Transaction) Verify(wallet *Wallet) bool {
	return wallet.VerifySignature(tx.hash(), tx.Signature)
}

// Blockchain represents the blockchain.
type Blockchain struct {
	transactions []*Transaction
	balanceMgr   *BalanceManager
	mutex        sync.Mutex
}

// NewBlockchain creates a new Blockchain.
func NewBlockchain() *Blockchain {
	return &Blockchain{
		transactions: make([]*Transaction, 0),
		balanceMgr:   NewBalanceManager(),
	}
}

// AddTransaction adds a transaction to the blockchain.
func (bc *Blockchain) AddTransaction(tx *Transaction) error {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	// Verify the transaction
	fromWallet := Wallet{Address: tx.From}
	if !tx.Verify(&fromWallet) {
		return errors.New("invalid transaction signature")
	}

	// Check balances
	if err := bc.balanceMgr.SubtractBalance(tx.From, tx.Amount); err != nil {
		return err
	}
	bc.balanceMgr.AddBalance(tx.To, tx.Amount)

	// Add transaction to the blockchain
	bc.transactions = append(bc.transactions, tx)
	return nil
}

// GetTransactions returns all transactions in the blockchain.
func (bc *Blockchain) GetTransactions() []*Transaction {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	return bc.transactions
}

// GetBalance returns the balance of a wallet address.
func (bc *Blockchain) GetBalance(address string) *big.Int {
	return bc.balanceMgr.GetBalance(address)
}

func main() {
	// Example usage
	wallet, err := NewWallet()
	if err != nil {
		fmt.Println("Error creating wallet:", err)
		return
	}

	fmt.Println("New wallet address:", wallet.Address)

	bc := NewBlockchain()
	bc.balanceMgr.SetBalance(wallet.Address, big.NewInt(1000))

	fmt.Println("Initial balance:", bc.GetBalance(wallet.Address))

	recipientWallet, _ := NewWallet()
	tx, err := NewTransaction(wallet.Address, recipientWallet.Address, big.NewInt(100), wallet)
	if err != nil {
		fmt.Println("Error creating transaction:", err)
		return
	}

	err = bc.AddTransaction(tx)
	if err != nil {
		fmt.Println("Error adding transaction:", err)
		return
	}

	fmt.Println("Balance after transaction:", bc.GetBalance(wallet.Address))
	fmt.Println("Recipient balance after transaction:", bc.GetBalance(recipientWallet.Address))
}
