package proof_of_work_challenge

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"math/rand"
	"time"
)

// Puzzle represents a Proof of Work challenge.
type Puzzle struct {
	Challenge string
	Target    *big.Int
}

// NewPuzzle generates a new Proof of Work challenge.
func NewPuzzle(difficulty int) (*Puzzle, error) {
	if difficulty <= 0 {
		return nil, errors.New("difficulty must be a positive integer")
	}

	challenge, err := generateRandomChallenge()
	if err != nil {
		return nil, err
	}

	target := calculateTarget(difficulty)

	return &Puzzle{
		Challenge: challenge,
		Target:    target,
	}, nil
}

// generateRandomChallenge generates a random challenge string.
func generateRandomChallenge() (string, error) {
	rand.Seed(time.Now().UnixNano())
	challengeBytes := make([]byte, 32)
	_, err := rand.Read(challengeBytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(challengeBytes), nil
}

// calculateTarget calculates the target value based on the difficulty.
func calculateTarget(difficulty int) *big.Int {
	target := big.NewInt(1)
	target.Lsh(target, uint(256-difficulty))
	return target
}

// SolvePuzzle attempts to solve the Proof of Work challenge.
func (p *Puzzle) SolvePuzzle() (string, error) {
	var nonce int64
	var hash [32]byte

	for {
		nonceBytes := []byte(p.Challenge + string(nonce))
		hash = sha256.Sum256(nonceBytes)
		hashInt := new(big.Int).SetBytes(hash[:])

		if hashInt.Cmp(p.Target) == -1 {
			return hex.EncodeToString(nonceBytes), nil
		}
		nonce++
	}
}

// VerifySolution verifies if the provided solution is valid for the puzzle.
func (p *Puzzle) VerifySolution(solution string) bool {
	hash := sha256.Sum256([]byte(solution))
	hashInt := new(big.Int).SetBytes(hash[:])
	return hashInt.Cmp(p.Target) == -1
}

// Example usage
func main() {
	difficulty := 20

	// Create a new puzzle
	puzzle, err := NewPuzzle(difficulty)
	if err != nil {
		panic(err)
	}

	// Solve the puzzle
	solution, err := puzzle.SolvePuzzle()
	if err != nil {
		panic(err)
	}

	// Verify the solution
	valid := puzzle.VerifySolution(solution)
	if valid {
		println("Puzzle solved successfully!")
	} else {
		println("Failed to solve the puzzle.")
	}
}
