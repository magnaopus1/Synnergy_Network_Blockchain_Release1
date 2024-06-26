package proof_of_stake

import (
	"crypto/sha256"
	"math/big"
	"time"

	"github.com/synthron/synthronchain/crypto"
	"github.com/synthron/synthronchain/crypto/vrf"
)

// Validator struct defines the structure for blockchain validators
type Validator struct {
	Address      string
	Stake        *big.Int
	StakedSince  time.Time
	IsActive     bool
	VRFKey       crypto.PublicKey
}

// Blockchain struct represents the blockchain data structure
type Blockchain struct {
	Validators []*Validator
	LatestBlockHash []byte
}

// RandomizationMechanism handles the selection of validators
type RandomizationMechanism struct {
	Blockchain *Blockchain
}

// NewRandomizationMechanism initializes a new instance of RandomizationMechanism
func NewRandomizationMechanism(blockchain *Blockchain) *RandomizationMechanism {
	return &RandomizationMechanism{
		Blockchain: blockchain,
	}
}

// GenerateRandomSeed uses the latest block hash and current timestamp to generate a random seed
func (rm *RandomizationMechanism) GenerateRandomSeed() []byte {
	currentTime := time.Now().Unix()
	timeBytes := big.NewInt(currentTime).Bytes()
	seed := append(rm.Blockchain.LatestBlockHash, timeBytes...)
	return sha256.Sum256(seed)
}

// SelectValidators selects the validators for the next consensus round using VRF
func (rm *RandomizationMechanism) SelectValidators() ([]*Validator, error) {
	seed := rm.GenerateRandomSeed()
	selectedValidators := []*Validator{}
	for _, validator := range rm.Blockchain.Validators {
		if validator.IsActive {
			vrfProof, err := vrf.Prove(validator.VRFKey, seed)
			if err != nil {
				return nil, err
			}
			if rm.isValidatorSelected(vrfProof) {
				selectedValidators = append(selectedValidators, validator)
			}
		}
	}
	return selectedValidators, nil
}

// isValidatorSelected determines if a validator is selected based on VRF proof
func (rm *RandomizationMechanism) isValidatorSelected(vrfProof []byte) bool {
	proofValue := new(big.Int).SetBytes(vrfProof)
	selectionThreshold := new(big.Int).Div(big.NewInt(1), big.NewInt(10)) // Example threshold
	return proofValue.Cmp(selectionThreshold) == -1
}

func main() {
	// Example blockchain initialization
	blockchain := &Blockchain{
		LatestBlockHash: []byte("example_latest_block_hash"),
		Validators: []*Validator{
			{Address: "validator_1", Stake: big.NewInt(1000), IsActive: true, VRFKey: crypto.GeneratePublicKey()},
			{Address: "validator_2", Stake: big.NewInt(500), IsActive: true, VRFKey: crypto.GeneratePublicKey()},
		},
	}

	// Initialize RandomizationMechanism
	randMech := NewRandomizationMechanism(blockchain)

	// Select validators for the next block
	validators, err := randMech.SelectValidators()
	if err != nil {
		panic(err)
	}
	for _, v := range validators {
		println("Selected Validator:", v.Address)
	}
}
