package common

import(
	"time"
	"sync"

)

// MessageValidator is responsible for validating messages using a public key map
type MessageValidator struct {
	Logger       Logger
	PublicKeyMap map[string]string
}

// NewMessageValidator creates and returns a new MessageValidator instance
func NewMessageValidator(logger Logger, publicKeyMap map[string]string) *MessageValidator {
	return &MessageValidator{
		Logger:       logger,
		PublicKeyMap: publicKeyMap,
	}
}

// validateChallengeResponse validates the given challenge-response pair
func validateChallengeResponse(challenge, response []byte) bool {
	// Implement your logic here
	return true
}


type TransactionValidator interface {
	ValidateTransaction(txn Transaction) error
}

type Validator struct {
	ID              string
	Stake           float64
	Performance     float64
	Contribution    float64
	IsParticipating bool
	LastActive    time.Time
	Reputation    int
	IdentityValid bool
}

func NewTransactionValidator() *TransactionValidator { return &TransactionValidator{} }


// MinimumStakeValidator manages the staking requirements for validators.
type MinimumStakeValidator struct {
	sync.Mutex
	Blockchain *Blockchain
	MinStake   uint64 // Minimum amount of tokens required to become a validator.
}

// NewMinimumStakeValidator creates a new MinimumStakeValidator.
func NewMinimumStakeValidator(blockchain *Blockchain, minStake uint64) *MinimumStakeValidator {
	return &MinimumStakeValidator{
		Blockchain: blockchain,
		MinStake:   minStake,
	}
}

// StakeValidator manages the staking requirements for validators.
type StakeValidator struct {
	minStakeAmount     int64
	validatorAddresses map[string]int64 // Address -> Stake amount
	mutex              sync.Mutex
}

// NewStakeValidator creates a new StakeValidator.
func NewStakeValidator(minStakeAmount int64) *StakeValidator {
	return &StakeValidator{
		minStakeAmount:     minStakeAmount,
		validatorAddresses: make(map[string]int64),
	}
}


// SlashingCondition defines the structure for various slashing conditions
type SlashingCondition struct {
	Type        string
	Description string
	Condition   func(validator Validator) bool
	Penalty     func(validator *Validator) error
}


// NewValidator creates a new validator instance
func NewValidator(id string, stake int) *Validator {
	return &Validator{
		ID:            id,
		Stake:         stake,
		LastActive:    time.Now(),
		Reputation:    100,
		IdentityValid: true,
	}
}


// GetValidator retrieves a validator from the blockchain.
func (bc *Blockchain) GetValidator(validatorID string) (*Validator, bool) {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	validator, exists := bc.validators[validatorID]
	return validator, exists
}

// GetAllValidators retrieves all validators from the blockchain.
func (bc *Blockchain) GetAllValidators() map[string]*Validator {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	validatorsCopy := make(map[string]*Validator)
	for id, validator := range bc.validators {
		validatorsCopy[id] = validator
	}
	return validatorsCopy
}

// TransactionValidation represents the validation of a transaction on the blockchain.
type TransactionValidation struct {
	TxID           string
	Sender         string
	Receiver       string
	Amount         float64
	Timestamp      time.Time
	Signature      string
	Validated      bool
	ValidationTime time.Duration
}

// NewTransactionValidation creates a new transaction validation instance.
func NewTransactionValidation(txID, sender, receiver string, amount float64, signature string) (*TransactionValidation, error) {
	if txID == "" || sender == "" || receiver == "" || amount <= 0 || signature == "" {
		return nil, errors.New("invalid transaction parameters")
	}

	return &TransactionValidation{
		TxID:      txID,
		Sender:    sender,
		Receiver:  receiver,
		Amount:    amount,
		Timestamp: time.Now(),
		Signature: signature,
		Validated: false,
	}, nil
}

// ValidationOptimization handles the optimization of transaction validation processes.
type ValidationOptimization struct {
	TransactionID    string
	Sender           string
	Receiver         string
	Amount           float64
	Timestamp        time.Time
	Signature        string
	Validated        bool
	ValidationTime   time.Duration
}

// NewValidationOptimization creates a new instance of ValidationOptimization.
func NewValidationOptimization(transactionID, sender, receiver string, amount float64, signature string) (*ValidationOptimization, error) {
	if transactionID == "" || sender == "" || receiver == "" || amount <= 0 || signature == "" {
		return nil, errors.New("invalid transaction parameters")
	}

	return &ValidationOptimization{
		TransactionID: transactionID,
		Sender:        sender,
		Receiver:      receiver,
		Amount:        amount,
		Timestamp:     time.Now(),
		Signature:     signature,
		Validated:     false,
	}, nil
}
