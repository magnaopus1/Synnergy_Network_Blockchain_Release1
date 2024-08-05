package child_chain

// other code


import (
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "sync"
)

type FraudProof struct {
    TransactionHash string
    ProofData       string
    Verified        bool
}

var fraudProofs []FraudProof
var fraudProofsMutex sync.Mutex

// submitFraudProof allows users to submit fraud proof for a specific transaction
func submitFraudProof(transactionHash, proofData string) error {
    fraudProofsMutex.Lock()
    defer fraudProofsMutex.Unlock()

    if transactionHash == "" || proofData == "" {
        return errors.New("transaction hash and proof data must not be empty")
    }

    // Verify if the transaction hash exists in the blockchain
    if !isValidTransactionHash(transactionHash) {
        return errors.New("invalid transaction hash")
    }

    // Create the fraud proof
    fraudProof := FraudProof{
        TransactionHash: transactionHash,
        ProofData:       proofData,
        Verified:        false,
    }

    fraudProofs = append(fraudProofs, fraudProof)
    fmt.Println("Fraud proof submitted:", fraudProof)
    return nil
}

// isValidTransactionHash checks if the given transaction hash exists in the blockchain
func isValidTransactionHash(hash string) bool {
    // Simulate checking the transaction hash in the blockchain
    // In a real application, this function should interface with the blockchain
    // to verify the existence of the transaction hash
    return true // Placeholder return value
}

// verifyFraudProofs verifies all submitted fraud proofs
func verifyFraudProofs() {
    fraudProofsMutex.Lock()
    defer fraudProofsMutex.Unlock()

    for i, proof := range fraudProofs {
        if !proof.Verified {
            // Add logic to verify the fraud proof
            // In a real application, this would involve more complex validation
            if validateProof(proof.ProofData) {
                fraudProofs[i].Verified = true
                fmt.Println("Fraud proof verified:", proof)
            } else {
                fmt.Println("Fraud proof invalid:", proof)
            }
        }
    }
}

// validateProof validates the provided proof data
func validateProof(proofData string) bool {
    // Placeholder validation logic
    // In a real application, this should involve thorough validation of the proof data
    return len(proofData) > 10 // Example validation: proof data length must be greater than 10
}

// generateFraudProofHash generates a unique hash for the fraud proof
func generateFraudProofHash(proof FraudProof) string {
    record := proof.TransactionHash + proof.ProofData
    hash := sha256.New()
    hash.Write([]byte(record))
    hashed := hash.Sum(nil)
    return hex.EncodeToString(hashed)
}

// getFraudProof retrieves a fraud proof based on the given hash
func getFraudProof(fraudProofHash string) (*FraudProof, error) {
    fraudProofsMutex.Lock()
    defer fraudProofsMutex.Unlock()

    for _, proof := range fraudProofs {
        if generateFraudProofHash(proof) == fraudProofHash {
            return &proof, nil
        }
    }
    return nil, errors.New("fraud proof not found")
}

// listUnverifiedFraudProofs lists all unverified fraud proofs
func listUnverifiedFraudProofs() []FraudProof {
    fraudProofsMutex.Lock()
    defer fraudProofsMutex.Unlock()

    var unverifiedProofs []FraudProof
    for _, proof := range fraudProofs {
        if !proof.Verified {
            unverifiedProofs = append(unverifiedProofs, proof)
        }
    }
    return unverifiedProofs
}

// listAllFraudProofs lists all fraud proofs
func listAllFraudProofs() []FraudProof {
    fraudProofsMutex.Lock()
    defer fraudProofsMutex.Unlock()

    return fraudProofs
}
