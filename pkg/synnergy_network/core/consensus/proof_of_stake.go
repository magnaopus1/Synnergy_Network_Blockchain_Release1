package consensus

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"sync"
	"time"
	"synnergy_network_blockchain/pkg/synnergy_network/core/common"
)


// NewProofOfStake initializes a new ProofOfStake instance.
func NewProofOfStake(electionInterval time.Duration, slashingPenalty *big.Int) *ProofOfStake {
	return &ProofOfStake{
		Validators:       make(map[string]*Validator),
		TotalStake:       big.NewInt(0),
		RewardPool:       big.NewInt(0),
		TransactionFees:  big.NewInt(0),
		ElectionInterval: electionInterval,
		SlashingPenalty:  slashingPenalty,
	}
}

// ProcessTransactions processes a list of transactions.
func (pos *ProofOfStake) ProcessTransactions(txs []*common.Transaction) error {
	pos.Lock.Lock()
	defer pos.Lock.Unlock()

	for _, tx := range txs {
		if err := pos.AddTransaction(tx); err != nil {
			return err
		}
	}
	return nil
}

// AddTransaction adds a transaction to the transaction pool.
func (pos *ProofOfStake) AddTransaction(tx *common.Transaction) error {
	// Implement logic to add transaction to the pool.
	return nil
}



var penalties = make(map[string][]Penalty)

// RegisterValidator registers a new validator to the PoS mechanism.
func (pos *ProofOfStake) RegisterValidator(id string, stake *big.Int) {
	pos.Lock.Lock()
	defer pos.Lock.Unlock()

	if _, exists := pos.Validators[id]; exists {
		return
	}

	validator := &Validator{
		ID:          id,
		Stake:       stake,
		LastBlock:   pos.CurrentBlock,
		IsValidator: false,
		IsSlashed:   false,
	}
	pos.Validators[id] = validator
	pos.TotalStake.Add(pos.TotalStake, stake)
}

// UnregisterValidator removes a validator from the PoS mechanism.
func (pos *ProofOfStake) UnregisterValidator(id string) {
	pos.Lock.Lock()
	defer pos.Lock.Unlock()

	if validator, exists := pos.Validators[id]; exists {
		pos.TotalStake.Sub(pos.TotalStake, validator.Stake)
		delete(pos.Validators, id)
	}
}

// ElectValidators elects validators based on their stake and a randomization mechanism to ensure fairness.
func (pos *ProofOfStake) ElectValidators() {
	pos.Lock.Lock()
	defer pos.Lock.Unlock()

	for id, validator := range pos.Validators {
		if validator.IsSlashed {
			continue
		}
		weight := big.NewInt(0).Div(validator.Stake, pos.TotalStake)
		if pos.randomSelection(weight) {
			validator.IsValidator = true
		} else {
			validator.IsValidator = false
		}
	}
}

// randomSelection determines if a validator is selected based on their weight.
func (pos *ProofOfStake) randomSelection(weight *big.Int) bool {
	n, err := rand.Int(rand.Reader, big.NewInt(100))
	if err != nil {
		fmt.Printf("Random selection failed: %v\n", err)
		return false
	}
	return n.Cmp(weight) < 0
}

// ValidateBlock validates a new block.
func (pos *ProofOfStake) ValidateBlock(block *Block, validatorID string) bool {
	pos.Lock.Lock()
	defer pos.Lock.Unlock()

	validator, exists := pos.Validators[validatorID]
	if !exists || !validator.IsValidator || validator.IsSlashed {
		return false
	}

	if err := ValidateBlock(block); err != nil {
		return false
	}

	if !pos.verifySignature(block, validatorID) {
		return false
	}

	pos.RewardValidator(validatorID)
	pos.CurrentBlock++
	validator.LastBlock = pos.CurrentBlock

	return true
}

// RewardValidator rewards the validator for validating a block.
func (pos *ProofOfStake) RewardValidator(validatorID string) {
	reward := big.NewInt(100) // Example reward value, can be dynamic
	pos.RewardPool.Sub(pos.RewardPool, reward)
	pos.Validators[validatorID].Stake.Add(pos.Validators[validatorID].Stake, reward)
}

// verifySignature verifies the block's signature.
func (pos *ProofOfStake) verifySignature(block *Block, validatorID string) bool {
	publicKey, err := GetPublicKey(validatorID)
	if err != nil {
		return false
	}

	return VerifySignature(block.Hash(), block.Signature, publicKey)
}

// RunElection runs the election process periodically.
func (pos *ProofOfStake) RunElection() {
	ticker := time.NewTicker(pos.ElectionInterval)
	for {
		select {
		case <-ticker.C:
			pos.ElectValidators()
		}
	}
}

// SlashValidator slashes a validator for malicious behavior.
func (pos *ProofOfStake) SlashValidator(validatorID string) {
	pos.Lock.Lock()
	defer pos.Lock.Unlock()

	validator, exists := pos.Validators[validatorID]
	if !exists {
		return
	}

	validator.Stake.Sub(validator.Stake, pos.SlashingPenalty)
	pos.TotalStake.Sub(pos.TotalStake, pos.SlashingPenalty)
	validator.IsSlashed = true
}


// Hash returns the hash of the block.
func (block *Block) Hash() []byte {
	h := sha256.New()
	binary.Write(h, binary.BigEndian, block.Timestamp)
	h.Write(block.PreviousHash)
	for _, tx := range block.Transactions {
		h.Write(tx.Hash())
	}
	return h.Sum(nil)
}

// ValidateBlock validates the block.
func ValidateBlock(block *Block) error {
	// Implement block validation logic here.
	return nil
}

// GetPublicKey returns the public key for a given validator ID.
func GetPublicKey(validatorID string) (string, error) {
	// Implement public key retrieval logic here.
	return "", nil
}

// VerifySignature verifies the signature of the block.
func VerifySignature(hash []byte, signature []byte, publicKey string) bool {
	// Implement signature verification logic here.
	return true
}

// LogViolation logs a violation.
func LogViolation(validatorID string, violationType ViolationType, severityLevel int, details string) {
	violation := Violation{
		ValidatorID:   validatorID,
		ViolationType: violationType,
		Timestamp:     time.Now(),
		SeverityLevel: severityLevel,
		Details:       details,
	}
	violationLog.AddViolation(violation)
	log.Printf("Logged violation: %v", violation)
	ApplyPenalty(validatorID, violation)
}

// ApplyPenalty applies a penalty to a validator.
func ApplyPenalty(validatorID string, violation Violation) {
	var penaltyAmount int64
	switch violation.ViolationType {
	case DoubleSigning:
		penaltyAmount = int64(float64(GetValidatorStake(validatorID)) * 0.1 * float64(violation.SeverityLevel))
	case Downtime:
		penaltyAmount = int64(float64(GetValidatorStake(validatorID)) * 0.05 * float64(violation.SeverityLevel))
	case InvalidBlock:
		penaltyAmount = int64(float64(GetValidatorStake(validatorID)) * 0.2 * float64(violation.SeverityLevel))
	default:
		penaltyAmount = 0
	}
	penalty := Penalty{
		ValidatorID: validatorID,
		Amount:      penaltyAmount,
		Timestamp:   time.Now(),
		Reason:      fmt.Sprintf("%v violation, Severity Level: %d", violation.ViolationType, violation.SeverityLevel),
	}
	penalties[validatorID] = append(penalties[validatorID], penalty)
	log.Printf("Applied penalty to validator %s: %v", validatorID, penalty)
	// Slash stake of the validator.
	err := SlashStake(validatorID, penaltyAmount)
	if err != nil {
		log.Printf("Error slashing stake for validator %s: %v", validatorID, err)
	}
}

// AddViolation adds a violation to the log.
func (vl *ViolationLog) AddViolation(violation Violation) {
	vl.mu.Lock()
	defer vl.mu.Unlock()
	vl.Violations = append(vl.Violations, violation)
}

// GetValidatorStake returns the stake of a validator.
func GetValidatorStake(validatorID string) int64 {
	// Implement stake retrieval logic here.
	return 0
}

// SlashStake slashes the stake of a validator.
func SlashStake(validatorID string, penaltyAmount int64) error {
	// Implement stake slashing logic here.
	return nil
}

// SaveViolationLog saves the violation log to a file.
func SaveViolationLog(filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	data, err := json.MarshalIndent(violationLog, "", "  ")
	if err != nil {
		return err
	}

	_, err = file.Write(data)
	if err != nil {
		return err
	}

	log.Printf("Violation log saved to %s", filePath)
	return nil
}

// LoadViolationLog loads the violation log from a file.
func LoadViolationLog(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	err = json.Unmarshal(data, &violationLog)
	if err != nil {
		return err
	}

	log.Printf("Violation log loaded from %s", filePath)
	return nil
}

// GenerateRandomnessForSelection uses VRF to generate randomness for validator selection.
func GenerateRandomnessForSelection(seed []byte) ([]byte, error) {
	hash := sha256.New()
	hash.Write(seed)
	hash.Write([]byte(time.Now().String()))
	return hash.Sum(nil), nil
}

// GenerateVRF generates a VRF output for randomization.
func GenerateVRF(seed string) (string, error) {
	vrfHash := sha256.Sum256([]byte(seed + time.Now().String()))
	return hex.EncodeToString(vrfHash[:]), nil
}

// GenerateSlashingProof generates a proof for slashing.
func GenerateSlashingProof(validatorID string, blockData string, signature string) string {
	hash := sha256.New()
	hash.Write([]byte(validatorID + blockData + signature))
	return hex.EncodeToString(hash.Sum(nil))
}

// VerifySlashingProof verifies the proof of slashing.
func VerifySlashingProof(proof string) bool {
	// Logic to verify slashing proof.
	return true
}
