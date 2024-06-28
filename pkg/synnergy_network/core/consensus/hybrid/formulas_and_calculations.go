package hybrid

import (
    "math/big"
    "crypto/sha256"
    "crypto"
    "time"
    "github.com/synnergy_network/core/consensus/proof_of_work"
    "github.com/synnergy_network/core/consensus/proof_of_stake"
    "github.com/synnergy_network/core/consensus/proof_of_history"
)

// ThresholdFormula calculates the threshold for switching consensus mechanisms
func ThresholdFormula(alpha, beta, D, S float64) float64 {
    return alpha*D + beta*S
}

// CalculateNetworkDemand calculates the network demand based on transaction throughput and block time
func CalculateNetworkDemand(transactionsPerBlock int, averageBlockTime time.Duration) float64 {
    return float64(transactionsPerBlock) / averageBlockTime.Seconds()
}

// CalculateStakeConcentration calculates the stake concentration
func CalculateStakeConcentration(stakedCoins, totalCoins float64) float64 {
    return stakedCoins / totalCoins
}

// AdjustDifficulty adjusts the difficulty of PoW based on network hash rate fluctuations
func AdjustDifficulty(currentDifficulty int, hashRateFluctuations float64) int {
    if hashRateFluctuations > 1 {
        return currentDifficulty + 1
    } else if hashRateFluctuations < 1 {
        return currentDifficulty - 1
    }
    return currentDifficulty
}

// SelectValidator selects a validator based on stake
func SelectValidator(validators []proof_of_stake.Validator) proof_of_stake.Validator {
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

// ValidateBlock validates a block using PoS
func ValidateBlock(blockHash string, validators []proof_of_stake.Validator) bool {
    selectedValidator := SelectValidator(validators)
    return proof_of_stake.ValidateBlock(selectedValidator, blockHash)
}

// MineBlock performs PoW mining for a new block
func MineBlock(transactions []string, difficulty int) string {
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

// SwitchConsensusMechanism decides the optimal consensus mechanism based on network conditions
func SwitchConsensusMechanism(alpha, beta float64, transactionsPerBlock int, averageBlockTime time.Duration, stakedCoins, totalCoins float64) string {
    D := CalculateNetworkDemand(transactionsPerBlock, averageBlockTime)
    S := CalculateStakeConcentration(stakedCoins, totalCoins)
    threshold := ThresholdFormula(alpha, beta, D, S)

    if threshold > 0.75 {
        return "PoS"
    } else if threshold < 0.25 {
        return "PoW"
    } else {
        return "PoH"
    }
}
