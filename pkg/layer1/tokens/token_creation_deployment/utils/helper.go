package utils

import (
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "regexp"
    "strings"

    "synthron-blockchain/pkg/common"
)

// GenerateHash takes any input string and returns its SHA-256 hash as a hex string.
func GenerateHash(input string) string {
    hasher := sha256.New()
    hasher.Write([]byte(input))
    return hex.EncodeToString(hasher.Sum(nil))
}

// ValidateContractSource checks if the source code of a contract meets certain criteria.
func ValidateContractSource(source string) error {
    if len(strings.TrimSpace(source)) == 0 {
        return fmt.Errorf("source code cannot be empty")
    }
    // Additional checks can be implemented here, such as size limits, forbidden commands, etc.
    return nil
}

// FormatContractForDisplay converts contract details into a readable string format.
func FormatContractForDisplay(contract common.ContractDetails) string {
    return fmt.Sprintf("Contract ID: %s\nSender: %s\nRecipient: %s\nAmount: %.2f\n",
        contract.ID, contract.Sender, contract.Recipient, contract.Amount)
}

// CheckAddressFormat verifies if a blockchain address is valid based on predefined rules.
func CheckAddressFormat(address string) bool {
    match, _ := regexp.MatchString(`^[a-zA-Z0-9]{34}$`, address)
    return match
}

// SimplifyABI strips unnecessary metadata from ABI for easier handling in deployments.
func SimplifyABI(abi string) string {
    // This is a dummy implementation, replace with actual logic to parse and simplify ABI.
    simplified := strings.Replace(abi, " ", "", -1)
    return simplified
}

// EncodeTransaction prepares a transaction for sending by encoding necessary fields.
func EncodeTransaction(tx common.Transaction) ([]byte, error) {
    // Assume a JSON-like encoding for simplicity
    encoded, err := json.Marshal(tx)
    if err != nil {
        return nil, fmt.Errorf("failed to encode transaction: %v", err)
    }
    return encoded, nil
}

// DecodeTransaction decodes transaction data back into a Transaction struct.
func DecodeTransaction(data []byte) (*common.Transaction, error) {
    var tx common.Transaction
    if err := json.Unmarshal(data, &tx); err != nil {
        return nil, fmt.Errorf("failed to decode transaction: %v", err)
    }
    return &tx, nil
}
