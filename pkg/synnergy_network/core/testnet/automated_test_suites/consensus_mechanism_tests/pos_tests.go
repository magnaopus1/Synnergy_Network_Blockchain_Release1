package consensus_mechanism_tests

import (
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "time"

    "github.com/synnergy_network/blockchain/core/testnet/consensus"
    "github.com/synnergy_network/blockchain/core/testnet/encryption"
)

// PoHTestResult represents the result of a Proof of History test.
type PoHTestResult struct {
    Success     bool
    Details     string
    Timestamp   time.Time
    BlockHeight int
}

// TestPoHSequence tests the Proof of History sequence generation.
func TestPoHSequence(sequenceLength int) PoHTestResult {
    poh := consensus.NewProofOfHistory()
    sequence := poh.GenerateSequence(sequenceLength)

    if len(sequence) != sequenceLength {
        return PoHTestResult{
            Success:     false,
            Details:     "Generated sequence length mismatch",
            Timestamp:   time.Now(),
            BlockHeight: poh.GetBlockHeight(),
        }
    }

    for i := 1; i < sequenceLength; i++ {
        prevHash := sequence[i-1]
        currHash := sequence[i]
        calculatedHash := sha256.Sum256([]byte(prevHash + string(i)))
        if hex.EncodeToString(calculatedHash[:]) != currHash {
            return PoHTestResult{
                Success:     false,
                Details:     fmt.Sprintf("Hash mismatch at position %d", i),
                Timestamp:   time.Now(),
                BlockHeight: poh.GetBlockHeight(),
            }
        }
    }

    return PoHTestResult{
        Success:     true,
        Details:     "PoH sequence generation successful",
        Timestamp:   time.Now(),
        BlockHeight: poh.GetBlockHeight(),
    }
}

// TestPoHValidation tests the validation of the Proof of History sequence.
func TestPoHValidation(sequence []string) PoHTestResult {
    poh := consensus.NewProofOfHistory()

    for i := 1; i < len(sequence); i++ {
        prevHash := sequence[i-1]
        currHash := sequence[i]
        calculatedHash := sha256.Sum256([]byte(prevHash + string(i)))
        if hex.EncodeToString(calculatedHash[:]) != currHash {
            return PoHTestResult{
                Success:     false,
                Details:     fmt.Sprintf("Validation failed at position %d", i),
                Timestamp:   time.Now(),
                BlockHeight: poh.GetBlockHeight(),
            }
        }
    }

    return PoHTestResult{
        Success:     true,
        Details:     "PoH sequence validation successful",
        Timestamp:   time.Now(),
        BlockHeight: poh.GetBlockHeight(),
    }
}

// TestPoHIntegration integrates PoH with other consensus mechanisms for testing.
func TestPoHIntegration() PoHTestResult {
    poh := consensus.NewProofOfHistory()
    pos := consensus.NewProofOfStake()
    pow := consensus.NewProofOfWork()

    pohSequence := poh.GenerateSequence(10)
    if len(pohSequence) != 10 {
        return PoHTestResult{
            Success:     false,
            Details:     "PoH sequence generation failed",
            Timestamp:   time.Now(),
            BlockHeight: poh.GetBlockHeight(),
        }
    }

    if !pos.ValidateSequence(pohSequence) {
        return PoHTestResult{
            Success:     false,
            Details:     "PoH sequence validation by PoS failed",
            Timestamp:   time.Now(),
            BlockHeight: poh.GetBlockHeight(),
        }
    }

    if !pow.ValidateSequence(pohSequence) {
        return PoHTestResult{
            Success:     false,
            Details:     "PoH sequence validation by PoW failed",
            Timestamp:   time.Now(),
            BlockHeight: poh.GetBlockHeight(),
        }
    }

    return PoHTestResult{
        Success:     true,
        Details:     "PoH integration with PoS and PoW successful",
        Timestamp:   time.Now(),
        BlockHeight: poh.GetBlockHeight(),
    }
}

// TestPoHPerformance evaluates the performance of the PoH mechanism.
func TestPoHPerformance() PoHTestResult {
    poh := consensus.NewProofOfHistory()
    start := time.Now()

    sequence := poh.GenerateSequence(10000)
    duration := time.Since(start)

    if len(sequence) != 10000 {
        return PoHTestResult{
            Success:     false,
            Details:     "PoH performance test failed: sequence length mismatch",
            Timestamp:   time.Now(),
            BlockHeight: poh.GetBlockHeight(),
        }
    }

    return PoHTestResult{
        Success:     true,
        Details:     fmt.Sprintf("PoH performance test successful: %v", duration),
        Timestamp:   time.Now(),
        BlockHeight: poh.GetBlockHeight(),
    }
}

// TestPoHSecurity tests the security aspects of the PoH mechanism.
func TestPoHSecurity() PoHTestResult {
    poh := consensus.NewProofOfHistory()
    sequence := poh.GenerateSequence(100)

    // Attempt to tamper with the sequence
    sequence[50] = "tampered_hash"

    if err := poh.ValidateSequence(sequence); err == nil {
        return PoHTestResult{
            Success:     false,
            Details:     "PoH security test failed: tampering undetected",
            Timestamp:   time.Now(),
            BlockHeight: poh.GetBlockHeight(),
        }
    }

    return PoHTestResult{
        Success:     true,
        Details:     "PoH security test successful: tampering detected",
        Timestamp:   time.Now(),
        BlockHeight: poh.GetBlockHeight(),
    }
}

// Encrypt and Decrypt functions to secure the PoH data
func EncryptPoHData(data string, passphrase string) (string, error) {
    encryptedData, err := encryption.EncryptAES(data, passphrase)
    if err != nil {
        return "", err
    }
    return encryptedData, nil
}

func DecryptPoHData(encryptedData string, passphrase string) (string, error) {
    decryptedData, err := encryption.DecryptAES(encryptedData, passphrase)
    if err != nil {
        return "", err
    }
    return decryptedData, nil
}
