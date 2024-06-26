package proof_of_history

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// HashFunction represents the cryptographic hash function used in PoH
func HashFunction(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// GenerateTimestamp creates a timestamp based on the previous timestamp and the transaction data
func GenerateTimestamp(prevTimestamp string, data string) string {
	input := prevTimestamp + data
	return HashFunction([]byte(input))
}

// ValidateTimestamp ensures that the provided timestamp is valid in the sequence
func ValidateTimestamp(prevTimestamp, currentTimestamp, data string) bool {
	expectedTimestamp := GenerateTimestamp(prevTimestamp, data)
	return expectedTimestamp == currentTimestamp
}

// DynamicTimestampAdjustment adjusts the timestamping interval based on current network conditions
func DynamicTimestampAdjustment(currentLoad int) time.Duration {
	baseInterval := time.Millisecond * 500 // Default timestamping interval
	if currentLoad > 1000 {
		return baseInterval / 2 // Increase the frequency of timestamping
	}
	return baseInterval
}

// RewardCalculation computes the rewards for block validation and transaction processing
func RewardCalculation(numberOfTransactions int, isValidator bool) float64 {
	baseReward := 10.0 // Base reward for participating in the network
	if isValidator {
		return baseReward + float64(numberOfTransactions)*0.01 // Additional rewards based on transaction volume
	}
	return 0
}

func main() {
	// Example usage of the PoH module
	prevTimestamp := "0000000000000000000000000000000000000000000000000000000000000000"
	data := "Example transaction data"
	currentTimestamp := GenerateTimestamp(prevTimestamp, data)
	fmt.Println("Generated Timestamp:", currentTimestamp)

	valid := ValidateTimestamp(prevTimestamp, currentTimestamp, data)
	fmt.Println("Is Timestamp Valid?:", valid)

	load := 1500
	adjustment := DynamicTimestampAdjustment(load)
	fmt.Println("Adjusted Timestamp Interval:", adjustment)

	reward := RewardCalculation(250, true)
	fmt.Println("Calculated Reward:", reward)
}
