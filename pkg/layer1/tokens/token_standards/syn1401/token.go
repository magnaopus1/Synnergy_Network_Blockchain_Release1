package syn1401

import (
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "log"
    "sync"
    "time"

    "synthron-blockchain/pkg/common"
)

// InvestmentToken represents an investment token with a fixed interest rate.
type InvestmentToken struct {
    ID            string
    Owner         string
    Principal     float64   // The principal amount invested
    InterestRate  float64   // Annual fixed interest rate
    StartDate     time.Time // The date the investment starts accruing interest
    MaturityDate  time.Time // The date the investment matures
    Yield         float64   // Guaranteed yield on maturity
    mutex         sync.Mutex
}

// NewInvestmentToken creates a new investment token with a guaranteed yield.
func NewInvestmentToken(id, owner string, principal, interestRate float64, durationDays int) *InvestmentToken {
    startDate := time.Now()
    maturityDate := startDate.AddDate(0, 0, durationDays)
    yield := principal + (principal * interestRate * float64(durationDays) / 365)

    token := &InvestmentToken{
        ID:            id,
        Owner:         owner,
        Principal:     principal,
        InterestRate:  interestRate,
        StartDate:     startDate,
        MaturityDate:  maturityDate,
        Yield:         yield,
    }
    log.Printf("New Investment Token created: %s, Owner: %s, Yield: %f", token.ID, token.Owner, token.Yield)
    return token
}

// CalculateYield computes the expected yield at maturity.
func (it *InvestmentToken) CalculateYield() float64 {
    it.mutex.Lock()
    defer it.mutex.Unlock()

    // Calculate the number of days until maturity
    daysUntilMaturity := it.MaturityDate.Sub(it.StartDate).Hours() / 24
    it.Yield = it.Principal + (it.Principal * it.InterestRate * daysUntilMaturity / 365)
    log.Printf("Calculated yield for token %s: %f", it.ID, it.Yield)
    return it.Yield
}

// TransferOwnership changes the ownership of the investment token.
func (it *InvestmentToken) TransferOwnership(newOwner string) {
    it.mutex.Lock()
    defer it.mutex.Unlock()

    log.Printf("Transferred token %s from %s to %s", it.ID, it.Owner, newOwner)
    it.Owner = newOwner
}

// GetDetails returns the details of the investment token.
func (it *InvestmentToken) GetDetails() map[string]interface{} {
    it.mutex.Lock()
    defer it.mutex.Unlock()

    details := map[string]interface{}{
        "ID":            it.ID,
        "Owner":         it.Owner,
        "Principal":     it.Principal,
        "InterestRate":  it.InterestRate,
        "StartDate":     it.StartDate,
        "MaturityDate":  it.MaturityDate,
        "Yield":         it.Yield,
    }
    log.Printf("Retrieved details for investment token %s", it.ID)
    return details
}

// GenerateTokenID creates a unique identifier for a new investment token based on owner and start date.
func GenerateTokenID(owner string) string {
    data := fmt.Sprintf("%s:%s", owner, time.Now().String())
    hash := sha256.Sum256([]byte(data))
    return hex.EncodeToString(hash[:])
}

// Example of how to create and use an investment token.
func ExampleUsage() {
    token := NewInvestmentToken(GenerateTokenID("user123"), "user123", 1000, 0.05, 365)
    token.CalculateYield()
    token.TransferOwnership("user456")
    fmt.Println(token.GetDetails())
}
