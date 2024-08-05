package exchange_protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rpc"
)

type AtomicSwap struct {
	ContractAddress common.Address
	PrivateKey      string
	Client          *rpc.Client
}

type Swap struct {
	SecretHash   common.Hash
	Secret       common.Hash
	Amount       int64
	Recipient    common.Address
	Expiration   time.Time
	Completed    bool
	Initiator    common.Address
}

var swaps = make(map[common.Hash]*Swap)

func NewAtomicSwap(contractAddress, privateKey string, client *rpc.Client) *AtomicSwap {
	return &AtomicSwap{
		ContractAddress: common.HexToAddress(contractAddress),
		PrivateKey:      privateKey,
		Client:          client,
	}
}

func (as *AtomicSwap) InitiateSwap(secret, recipient string, amount int64, expiration time.Time) (common.Hash, error) {
	secretHash := sha256.Sum256([]byte(secret))
	swap := &Swap{
		SecretHash:   common.BytesToHash(secretHash[:]),
		Amount:       amount,
		Recipient:    common.HexToAddress(recipient),
		Expiration:   expiration,
		Completed:    false,
		Initiator:    crypto.PubkeyToAddress(*crypto.ToECDSAUnsafe(common.FromHex(as.PrivateKey))),
	}

	swaps[common.BytesToHash(secretHash[:])] = swap
	return common.BytesToHash(secretHash[:]), nil
}

func (as *AtomicSwap) RedeemSwap(secret string) (bool, error) {
	secretHash := sha256.Sum256([]byte(secret))
	swap, exists := swaps[common.BytesToHash(secretHash[:])]
	if !exists {
		return false, errors.New("swap not found")
	}

	if swap.Completed {
		return false, errors.New("swap already completed")
	}

	if time.Now().After(swap.Expiration) {
		return false, errors.New("swap expired")
	}

	swap.Secret = common.BytesToHash([]byte(secret))
	swap.Completed = true
	return true, nil
}

func (as *AtomicSwap) RefundSwap(secretHash string) (bool, error) {
	hash := common.HexToHash(secretHash)
	swap, exists := swaps[hash]
	if !exists {
		return false, errors.New("swap not found")
	}

	if swap.Completed {
		return false, errors.New("swap already completed")
	}

	if time.Now().Before(swap.Expiration) {
		return false, errors.New("swap not yet expired")
	}

	delete(swaps, hash)
	return true, nil
}

func (as *AtomicSwap) GetSwapDetails(secretHash string) (*Swap, error) {
	hash := common.HexToHash(secretHash)
	swap, exists := swaps[hash]
	if !exists {
		return nil, errors.New("swap not found")
	}
	return swap, nil
}

func (as *AtomicSwap) HashLock(secret string) common.Hash {
	hash := sha256.Sum256([]byte(secret))
	return common.BytesToHash(hash[:])
}

func (as *AtomicSwap) VerifyHashLock(secret, hashLock string) bool {
	hash := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(hash[:]) == hashLock
}

func (as *AtomicSwap) EncodeSwapDetails(swap *Swap) (string, error) {
	data, err := abi.Arguments{
		{Type: abi.Bytes32},
		{Type: abi.Address},
		{Type: abi.Uint256},
		{Type: abi.Uint256},
	}.Pack(
		swap.SecretHash,
		swap.Recipient,
		big.NewInt(swap.Amount),
		big.NewInt(swap.Expiration.Unix()),
	)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}

func (as *AtomicSwap) DecodeSwapDetails(encodedData string) (*Swap, error) {
	data, err := hex.DecodeString(encodedData)
	if err != nil {
		return nil, err
	}
	args, err := abi.Arguments{
		{Type: abi.Bytes32},
		{Type: abi.Address},
		{Type: abi.Uint256},
		{Type: abi.Uint256},
	}.Unpack(data)
	if err != nil {
		return nil, err
	}
	return &Swap{
		SecretHash: args[0].(common.Hash),
		Recipient:  args[1].(common.Address),
		Amount:     args[2].(*big.Int).Int64(),
		Expiration: time.Unix(args[3].(*big.Int).Int64(), 0),
	}, nil
}

func (as *AtomicSwap) validateSecret(secret string) error {
	if len(secret) == 0 {
		return errors.New("secret cannot be empty")
	}
	return nil
}

func (as *AtomicSwap) validateAddress(address string) error {
	if !common.IsHexAddress(address) {
		return errors.New("invalid Ethereum address")
	}
	return nil
}

func (as *AtomicSwap) validateAmount(amount int64) error {
	if amount <= 0 {
		return errors.New("amount must be greater than zero")
	}
	return nil
}

func (as *AtomicSwap) validateExpiration(expiration time.Time) error {
	if expiration.Before(time.Now()) {
		return errors.New("expiration must be in the future")
	}
	return nil
}

func main() {
	client, err := rpc.Dial("http://localhost:8545")
	if err != nil {
		fmt.Println("Failed to connect to the Ethereum client:", err)
		return
	}
	defer client.Close()

	privateKey := "YOUR_PRIVATE_KEY"
	contractAddress := "YOUR_CONTRACT_ADDRESS"
	swap := NewAtomicSwap(contractAddress, privateKey, client)

	secret := "mysecret"
	recipient := "0xRecipientAddress"
	amount := int64(100)
	expiration := time.Now().Add(time.Hour * 24)

	secretHash, err := swap.InitiateSwap(secret, recipient, amount, expiration)
	if err != nil {
		fmt.Println("Failed to initiate swap:", err)
		return
	}

	fmt.Println("Swap initiated with secret hash:", secretHash.Hex())

	redeemed, err := swap.RedeemSwap(secret)
	if err != nil {
		fmt.Println("Failed to redeem swap:", err)
		return
	}

	fmt.Println("Swap redeemed:", redeemed)
}
