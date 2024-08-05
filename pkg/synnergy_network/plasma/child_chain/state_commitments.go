package child_chain

// other code


import (
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "sync"
    "time"
)

type StateCommitment struct {
    StateHash  string
    Timestamp  string
    Validator  string
    Verified   bool
}

var stateCommitments []StateCommitment
var stateCommitmentsMutex sync.Mutex

// createStateCommitment creates a new state commitment
func createStateCommitment(stateData string, validator string) (StateCommitment, error) {
    if stateData == "" || validator == "" {
        return StateCommitment{}, errors.New("state data and validator must not be empty")
    }

    stateHash := generateStateHash(stateData)
    timestamp := time.Now().String()
    commitment := StateCommitment{
        StateHash:  stateHash,
        Timestamp:  timestamp,
        Validator:  validator,
        Verified:   false,
    }

    stateCommitmentsMutex.Lock()
    stateCommitments = append(stateCommitments, commitment)
    stateCommitmentsMutex.Unlock()

    fmt.Println("State commitment created:", commitment)
    return commitment, nil
}

// generateStateHash generates a unique hash for the state data
func generateStateHash(stateData string) string {
    hash := sha256.New()
    hash.Write([]byte(stateData))
    return hex.EncodeToString(hash.Sum(nil))
}

// verifyStateCommitment verifies the state commitment
func verifyStateCommitment(commitment StateCommitment) bool {
    stateCommitmentsMutex.Lock()
    defer stateCommitmentsMutex.Unlock()

    for i, storedCommitment := range stateCommitments {
        if storedCommitment.StateHash == commitment.StateHash && storedCommitment.Validator == commitment.Validator {
            if !storedCommitment.Verified {
                stateCommitments[i].Verified = true
                fmt.Println("State commitment verified:", storedCommitment)
                return true
            }
            fmt.Println("State commitment already verified:", storedCommitment)
            return false
        }
    }
    fmt.Println("State commitment not found for verification")
    return false
}

// getStateCommitment retrieves a state commitment based on the state hash
func getStateCommitment(stateHash string) (*StateCommitment, error) {
    stateCommitmentsMutex.Lock()
    defer stateCommitmentsMutex.Unlock()

    for _, commitment := range stateCommitments {
        if commitment.StateHash == stateHash {
            return &commitment, nil
        }
    }
    return nil, errors.New("state commitment not found")
}

// listUnverifiedStateCommitments lists all unverified state commitments
func listUnverifiedStateCommitments() []StateCommitment {
    stateCommitmentsMutex.Lock()
    defer stateCommitmentsMutex.Unlock()

    var unverifiedCommitments []StateCommitment
    for _, commitment := range stateCommitments {
        if !commitment.Verified {
            unverifiedCommitments = append(unverifiedCommitments, commitment)
        }
    }
    return unverifiedCommitments
}

// listAllStateCommitments lists all state commitments
func listAllStateCommitments() []StateCommitment {
    stateCommitmentsMutex.Lock()
    defer stateCommitmentsMutex.Unlock()

    return stateCommitments
}

// invalidateStateCommitment invalidates a state commitment if it is found to be fraudulent
func invalidateStateCommitment(stateHash string) error {
    stateCommitmentsMutex.Lock()
    defer stateCommitmentsMutex.Unlock()

    for i, commitment := range stateCommitments {
        if commitment.StateHash == stateHash {
            stateCommitments = append(stateCommitments[:i], stateCommitments[i+1:]...)
            fmt.Println("State commitment invalidated:", commitment)
            return nil
        }
    }
    return errors.New("state commitment not found for invalidation")
}

