package syn1200

import (
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "log"
    "sync"
    "time"
)

// InteroperableToken represents a token capable of operating across different blockchain platforms.
type InteroperableToken struct {
    ID                string
    Name              string
    Symbol            string
    Supply            uint64
    Owner             map[string]uint64
    LinkedBlockchains map[string]bool
    CreationDate      time.Time
    AtomicSwapDetails []AtomicSwap
    mutex             sync.Mutex
}

// AtomicSwap details the components of an atomic swap between blockchains.
type AtomicSwap struct {
    PartnerChain string
    SwapID       string
    Initiated    time.Time
    Completed    time.Time
    Status       string
}

// NewInteroperableToken initializes a new token with the capability to interact across multiple blockchains.
func NewInteroperableToken(id, name, symbol string, owner string, initialSupply uint64, linkedChains []string) *InteroperableToken {
    token := &InteroperableToken{
        ID:                id,
        Name:              name,
        Symbol:            symbol,
        Supply:            initialSupply,
        Owner:             map[string]uint64{owner: initialSupply},
        LinkedBlockchains: make(map[string]bool),
        CreationDate:      time.Now(),
    }

    for _, chain := range linkedChains {
        token.LinkedBlockchains[chain] = true
    }

    log.Printf("New Interoperable Token created: %s (%s), owned by %s", name, symbol, owner)
    return token
}

// LinkBlockchain enables the token to operate on an additional blockchain.
func (t *InteroperableToken) LinkBlockchain(chainName string) error {
    t.mutex.Lock()
    defer t.mutex.Unlock()

    if t.LinkedBlockchains[chainName] {
        return fmt.Errorf("blockchain %s already linked", chainName)
    }

    t.LinkedBlockchains[chainName] = true
    log.Printf("Blockchain %s linked to token %s", chainName, t.ID)
    return nil
}

// InitiateAtomicSwap starts an atomic swap with a specified blockchain.
func (t *InteroperableToken) InitiateAtomicSwap(partnerChain, swapID string) error {
    t.mutex.Lock()
    defer t.mutex.Unlock()

    for _, swap := range t.AtomicSwapDetails {
        if swap.SwapID == swapID {
            return errors.New("atomic swap with this ID already exists")
        }
    }

    newSwap := AtomicSwap{
        PartnerChain: partnerChain,
        SwapID:       swapID,
        Initiated:    time.Now(),
        Status:       "Initiated",
    }
    t.AtomicSwapDetails = append(t.AtomicSwapDetails, newSwap)
    log.Printf("Atomic swap initiated: %s with chain %s", swapID, partnerChain)
    return nil
}

// CompleteAtomicSwap completes a previously initiated swap.
func (t *InteroperableToken) CompleteAtomicSwap(swapID string) error {
    t.mutex.Lock()
    defer t.mutex.Unlock()

    for i, swap := range t.AtomicSwapDetails {
        if swap.SwapID == swapID && swap.Status == "Initiated" {
            t.AtomicSwapDetails[i].Completed = time.Now()
            t.AtomicSwapDetails[i].Status = "Completed"
            log.Printf("Atomic swap %s completed", swapID)
            return nil
        }
    }
    return fmt.Errorf("no initiated atomic swap with ID %s found", swapID)
}

// GetTokenDetails provides a comprehensive view of the token's state and activities.
func (t *InteroperableToken) GetTokenDetails() map[string]interface{} {
    t.mutex.Lock()
    defer t.mutex.Unlock()

    details := map[string]interface{}{
        "ID":                t.ID,
        "Name":              t.Name,
        "Symbol":            t.Symbol,
        "Supply":            t.Supply,
        "Owner":             t.Owner,
        "LinkedBlockchains": t.LinkedBlockchains,
        "CreationDate":      t.CreationDate,
        "AtomicSwapDetails": t.AtomicSwapDetails,
    }
    log.Printf("Details retrieved for token %s", t.ID)
    return details
}

// GenerateTokenID creates a unique token identifier based on the owner and linked chains.
func GenerateTokenID(owner string, chains []string) string {
    data := fmt.Sprintf("%s:%v:%s", owner, chains, time.Now().String())
    hash := sha256.Sum256([]byte(data))
    return hex.EncodeToString(hash[:])
}

// Example of creating and using an interoperable token.
func ExampleUsage() {
    // Creating a new token with multiple blockchain compatibility
    token := NewInteroperableToken(GenerateTokenID("user123", []string{"Ethereum", "Polygon"}), "TokenName", "TKN", "user123", 1000, []string{"Ethereum", "Polygon"})
    if err := token.LinkBlockchain("BinanceChain"); err != nil {
        log.Println("Error linking blockchain:", err)
    }

    // Initiating an atomic swap
    if err := token.InitiateAtomicSwap("BinanceChain", "swap002"); err != nil {
        log.Println("Error initiating atomic swap:", err)
    }

    // Completing an atomic swap
    if err := token.CompleteAtomicSwap("swap002"); err != nil {
        log.Println("Error completing atomic swap:", err)
    }

    // Outputting token details
    fmt.Println(token.GetTokenDetails())
}
