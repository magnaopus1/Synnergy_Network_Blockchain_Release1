package hybrid

import (
    "fmt"
    "math/big"
    "time"
    "crypto/sha256"
    "crypto"
    "encoding/hex"
    "github.com/synnergy_network/core/consensus/proof_of_work"
    "github.com/synnergy_network/core/consensus/proof_of_stake"
    "github.com/synnergy_network/core/consensus/proof_of_history"
)

// HybridConsensusMechanism struct to hold hybrid consensus state
type HybridConsensusMechanism struct {
    CurrentPhase         string
    Difficulty           int
    Validators           []Validator
    NetworkDemand        int
    StakeConcentration   float64
}

// Validator struct to represent a PoS validator
type Validator struct {
    Address string
    Stake   float64
}

// NewHybridConsensusMechanism creates a new hybrid consensus mechanism
func NewHybridConsensusMechanism() *HybridConsensusMechanism {
    return &HybridConsensusMechanism{
        CurrentPhase: "PoW",
        Difficulty:   1,
        Validators:   []Validator{},
    }
}

// MineBlock performs PoW mining for a new block
func (h *HybridConsensusMechanism) MineBlock(transactions []string) {
    fmt.Println("Starting PoW Mining")
    proof_of_work.MineBlock(transactions, h.Difficulty)
}

// OrderTransactions orders transactions using PoH
func (h *HybridConsensusMechanism) OrderTransactions(transactions []string) {
    fmt.Println("Ordering transactions using PoH")
    proof_of_history.OrderTransactions(transactions)
}

// ValidateBlock validates a block using PoS
func (h *HybridConsensusMechanism) ValidateBlock(blockHash string) {
    fmt.Println("Validating block using PoS")
    proof_of_stake.ValidateBlock(blockHash, h.Validators)
}

// AddValidator adds a new validator to the PoS validator set
func (h *HybridConsensusMechanism) AddValidator(address string, stake float64) {
    h.Validators = append(h.Validators, Validator{Address: address, Stake: stake})
}

// CalculateThreshold calculates the threshold for switching consensus mechanisms
func (h *HybridConsensusMechanism) CalculateThreshold() float64 {
    alpha := 0.5
    beta := 0.5
    D := float64(h.NetworkDemand)
    S := h.StakeConcentration

    threshold := alpha*D + beta*S
    return threshold
}

// MonitorNetwork monitors network conditions and switches consensus mechanisms if needed
func (h *HybridConsensusMechanism) MonitorNetwork() {
    for {
        threshold := h.CalculateThreshold()

        if threshold > 0.75 {
            h.SwitchToPoS()
        } else if threshold < 0.25 {
            h.SwitchToPoW()
        } else {
            h.SwitchToPoH()
        }

        time.Sleep(10 * time.Second)
    }
}

// SwitchToPoW switches the consensus mechanism to Proof of Work
func (h *HybridConsensusMechanism) SwitchToPoW() {
    fmt.Println("Switching to Proof of Work")
    h.CurrentPhase = "PoW"
    h.Difficulty = proof_of_work.AdjustDifficulty()
}

// SwitchToPoH switches the consensus mechanism to Proof of History
func (h *HybridConsensusMechanism) SwitchToPoH() {
    fmt.Println("Switching to Proof of History")
    h.CurrentPhase = "PoH"
}

// SwitchToPoS switches the consensus mechanism to Proof of Stake
func (h *HybridConsensusMechanism) SwitchToPoS() {
    fmt.Println("Switching to Proof of Stake")
    h.CurrentPhase = "PoS"
}

// ProofOfWork logic for PoW phase
func ProofOfWork(transactions []string, difficulty int) string {
    nonce := 0
    var hash [32]byte
    var hashInt big.Int
    target := big.NewInt(1)
    target.Lsh(target, uint(256-difficulty))

    for {
        data := transactionsToString(transactions) + fmt.Sprintf("%d", nonce)
        hash = sha256.Sum256([]byte(data))
        hashInt.SetBytes(hash[:])

        if hashInt.Cmp(target) == -1 {
            return fmt.Sprintf("%x", hash)
        } else {
            nonce++
        }
    }
}

// transactionsToString converts transactions to a single string
func transactionsToString(transactions []string) string {
    result := ""
    for _, tx := range transactions {
        result += tx
    }
    return result
}

// ProofOfStake logic for PoS phase
func ProofOfStake(blockHash string, validators []Validator) bool {
    selectedValidator := selectValidator(validators)
    return validateBlock(selectedValidator, blockHash)
}

// selectValidator selects a validator based on stake
func selectValidator(validators []Validator) Validator {
    totalStake := 0.0
    for _, validator := range validators {
        totalStake += validator.Stake
    }

    randomPoint := totalStake * (float64(rand.Intn(100)) / 100.0)
    runningTotal := 0.0
    for _, validator := range validators {
        runningTotal += validator.Stake
        if runningTotal >= randomPoint {
            return validator
        }
    }
    return validators[0]
}

// validateBlock validates a block
func validateBlock(validator Validator, blockHash string) bool {
    hash := sha256.Sum256([]byte(validator.Address + blockHash))
    return hash[0] == 0
}

// ProofOfHistory logic for PoH phase
func ProofOfHistory(transactions []string) string {
    var hash [32]byte
    result := ""
    for _, tx := range transactions {
        hash = sha256.Sum256([]byte(tx))
        result += hex.EncodeToString(hash[:])
    }
    return result
}
