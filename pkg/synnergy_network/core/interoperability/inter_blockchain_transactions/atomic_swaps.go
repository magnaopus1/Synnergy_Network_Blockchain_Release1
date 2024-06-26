package interblockchaintransactions

import (
    "crypto/rand"
    "fmt"
    "math/big"
    "time"

    "synthron-blockchain/pkg/blockchain"
    "synthron-blockchain/pkg/cryptography"
)

// AtomicSwap represents the data structure for an atomic swap transaction.
type AtomicSwap struct {
    ID               string
    Initiator        string
    Participant      string
    InitiatorAsset   blockchain.Asset
    ParticipantAsset blockchain.Asset
    SecretHash       []byte
    Secret           []byte
    TimeLock         time.Time
    State            SwapState
}

// SwapState defines the state of the atomic swap.
type SwapState int

const (
    Created SwapState = iota
    Responded
    Redeemed
    Refunded
)

// AtomicSwapService manages atomic swap transactions.
type AtomicSwapService struct {
    BlockchainHandler blockchain.Handler
}

// NewAtomicSwapService creates a new atomic swap service.
func NewAtomicSwapService(handler blockchain.Handler) *AtomicSwapService {
    return &AtomicSwapService{
        BlockchainHandler: handler,
    }
}

// InitiateSwap starts a new atomic swap transaction.
func (service *AtomicSwapService) InitiateSwap(initiator, participant string, initiatorAsset, participantAsset blockchain.Asset) (*AtomicSwap, error) {
    secret, err := generateSecret()
    if err != nil {
        return nil, fmt.Errorf("error generating secret: %w", err)
    }

    secretHash := cryptography.Hash(secret)
    swap := &AtomicSwap{
        ID:               generateID(),
        Initiator:        initiator,
        Participant:      participant,
        InitiatorAsset:   initiatorAsset,
        ParticipantAsset: participantAsset,
        SecretHash:       secretHash,
        Secret:           secret,
        TimeLock:         time.Now().Add(24 * time.Hour), // 24-hour timelock
        State:            Created,
    }

    // Register the swap on both blockchains
    err = service.BlockchainHandler.InitiateSwap(swap)
    if err != nil {
        return nil, fmt.Errorf("failed to initiate swap on the blockchain: %w", err)
    }

    return swap, nil
}

// CompleteSwap completes the atomic swap by revealing the secret.
func (service *AtomicSwapService) CompleteSwap(swapID string, secret []byte) error {
    swap, err := service.BlockchainHandler.GetSwapDetails(swapID)
    if err != nil {
        return fmt.Errorf("failed to get swap details: %w", err)
    }

    if !cryptography.VerifyHash(secret, swap.SecretHash) {
        return fmt.Errorf("invalid secret for the swap")
    }

    err = service.BlockchainHandler.CompleteSwap(swap, secret)
    if err != nil {
        return fmt.Errorf("failed to complete swap on the blockchain: %w", err)
    }

    swap.State = Redeemed
    return nil
}

// generateSecret creates a new random secret for the atomic swap.
func generateSecret() ([]byte, error) {
    secret := make([]byte, 32) // 256-bit secret
    _, err := rand.Read(secret)
    if err != nil {
        return nil, err
    }
    return secret, nil
}

// generateID creates a unique identifier for the swap.
func generateID() string {
    id := big.NewInt(0)
    id, _ = rand.Int(rand.Reader, big.NewInt(1e18))
    return id.Text(16) // hexadecimal
}

// Example usage of the atomic swap service
func main() {
    handler := blockchain.NewBlockchainHandler()
    service := NewAtomicSwapService(handler)

    initiatorAsset := blockchain.Asset{Blockchain: "Ethereum", Amount: 100, Symbol: "ETH"}
    participantAsset := blockchain.Asset{Blockchain: "Binance Smart Chain", Amount: 5000, Symbol: "BNB"}

    swap, err := service.InitiateSwap("0xInitiatorAddress", "0xParticipantAddress", initiatorAsset, participantAsset)
    if err != nil {
        fmt.Println("Failed to initiate swap:", err)
        return
    }
    fmt.Printf("Swap initiated successfully: %+v\n", swap)

    err = service.CompleteSwap(swap.ID, swap.Secret)
    if err != nil {
        fmt.Println("Failed to complete swap:", err)
        return
    }
    fmt.Println("Swap completed successfully")
}
