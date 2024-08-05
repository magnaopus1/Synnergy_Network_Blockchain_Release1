package payments

import (
	"errors"
	"time"

	"github.com/synnergy_network/blockchain/assets"
	"github.com/synnergy_network/blockchain/events"
	"github.com/synnergy_network/blockchain/ledger"
	"github.com/synnergy_network/blockchain/transactions"
	"golang.org/x/crypto/scrypt"
)

// DepositManagement handles security deposit transactions and management
type DepositManagement struct {
	Ledger            ledger.Ledger
	AssetManager      assets.AssetManager
	EventLogger       events.EventLogger
	TransactionSystem transactions.TransactionSystem
}

// NewDepositManagement creates a new instance of DepositManagement
func NewDepositManagement(ledger ledger.Ledger, assetManager assets.AssetManager, eventLogger events.EventLogger, transactionSystem transactions.TransactionSystem) *DepositManagement {
	return &DepositManagement{
		Ledger:            ledger,
		AssetManager:      assetManager,
		EventLogger:       eventLogger,
		TransactionSystem: transactionSystem,
	}
}

// Deposit represents a security deposit transaction
type Deposit struct {
	TokenID     string
	Amount      float64
	Timestamp   time.Time
	ReleaseDate time.Time
	Status      string // "held", "released"
}

// HoldDeposit places a deposit in escrow until the end of the tenancy period
func (dm *DepositManagement) HoldDeposit(tokenID string, amount float64, releaseDate time.Time) error {
	deposit := Deposit{
		TokenID:     tokenID,
		Amount:      amount,
		Timestamp:   time.Now(),
		ReleaseDate: releaseDate,
		Status:      "held",
	}

	if err := dm.Ledger.StoreDeposit(deposit); err != nil {
		return err
	}

	dm.EventLogger.LogEvent(events.Event{
		Type:      "DepositHeld",
		Timestamp: time.Now(),
		Details:   map[string]interface{}{"tokenID": tokenID, "amount": amount, "releaseDate": releaseDate},
	})

	return nil
}

// ReleaseDeposit releases the deposit to the tenant or landlord based on the legal outcome
func (dm *DepositManagement) ReleaseDeposit(tokenID string, releaseTo string) error {
	deposit, err := dm.Ledger.GetDeposit(tokenID)
	if err != nil {
		return err
	}

	if deposit.Status != "held" {
		return errors.New("deposit is not currently held")
	}

	deposit.Status = "released"
	if err := dm.Ledger.UpdateDeposit(deposit); err != nil {
		return err
	}

	// Process the payment to the tenant or landlord
	payment := transactions.PaymentRecord{
		TokenID:   tokenID,
		Amount:    deposit.Amount,
		Timestamp: time.Now(),
		Type:      "Deposit Release",
	}

	if err := dm.TransactionSystem.ProcessPayment(payment, releaseTo); err != nil {
		return err
	}

	dm.EventLogger.LogEvent(events.Event{
		Type:      "DepositReleased",
		Timestamp: time.Now(),
		Details:   map[string]interface{}{"tokenID": tokenID, "amount": deposit.Amount, "releasedTo": releaseTo},
	})

	return nil
}

// DisputeResolution handles disputes and determines the release of the deposit
func (dm *DepositManagement) DisputeResolution(tokenID string, legalOutcome string) error {
	// Legal outcome could be "tenant" or "landlord"
	return dm.ReleaseDeposit(tokenID, legalOutcome)
}

// encryptPassword encrypts a password using scrypt
func encryptPassword(password, salt []byte) ([]byte, error) {
	const N = 32768
	const r = 8
	const p = 1
	const keyLen = 32

	dk, err := scrypt.Key(password, salt, N, r, p, keyLen)
	if err != nil {
		return nil, err
	}

	return dk, nil
}
