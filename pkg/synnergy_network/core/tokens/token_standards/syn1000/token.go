package syn1000

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"

	"synthron-blockchain/pkg/common"
)

// Stablecoin represents a stablecoin that is pegged to a specific value or asset.
type Stablecoin struct {
	ID            string
	Peg           string // Description of what the coin is pegged to, e.g., USD, a basket of currencies, etc.
	Owner         string
	Balance       float64
	CreationDate  time.Time
	LastAuditDate time.Time
	mutex         sync.Mutex
	AuditLog      []AuditEntry
}

// AuditEntry records details of each audit, necessary to ensure the peg is maintained.
type AuditEntry struct {
	Date         time.Time
	AuditOutcome string
}

// NewStablecoin initializes a new stablecoin with a specified peg.
func NewStablecoin(id, owner, peg string) *Stablecoin {
	return &Stablecoin{
		ID:           id,
		Peg:          peg,
		Owner:        owner,
		Balance:      0,
		CreationDate: time.Now(),
		AuditLog:     []AuditEntry{},
	}
}

// Mint mints new stablecoins to the specified wallet address.
func (s *Stablecoin) Mint(amount float64) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.Balance += amount
	log.Printf("Minted %f of %s stablecoins to %s", amount, s.Peg, s.Owner)
}

// Burn removes stablecoins from circulation, typically used to maintain peg stability.
func (s *Stablecoin) Burn(amount float64) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if amount > s.Balance {
		log.Printf("Attempt to burn %f stablecoins failed due to insufficient balance", amount)
		return
	}

	s.Balance -= amount
	log.Printf("Burned %f of %s stablecoins from %s", amount, s.Peg, s.Owner)
}

// ConductAudit performs a check to ensure that the stablecoin is still properly pegged to the underlying asset.
func (s *Stablecoin) ConductAudit(outcome string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	audit := AuditEntry{
		Date:         time.Now(),
		AuditOutcome: outcome,
	}
	s.AuditLog = append(s.AuditLog, audit)
	s.LastAuditDate = audit.Date

	log.Printf("Conducted audit on %s: %s", s.ID, outcome)
}

// GetDetails returns the details and current state of the stablecoin.
func (s *Stablecoin) GetDetails() map[string]interface{} {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return map[string]interface{}{
		"ID":            s.ID,
		"Owner":         s.Owner,
		"Peg":           s.Peg,
		"Balance":       s.Balance,
		"CreationDate":  s.CreationDate,
		"LastAuditDate": s.LastAuditDate,
		"AuditLog":      s.AuditLog,
	}
}

// GenerateTokenID creates a unique identifier based on the stablecoin’s details.
func GenerateTokenID(peg, owner string) string {
	data := fmt.Sprintf("%s:%s:%s", peg, owner, time.Now().String())
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// Example of using the SYN1000 token standard for a stablecoin.
func ExampleUsage() {
	sc := NewStablecoin(GenerateTokenID("USD", "user123"), "user123", "USD")
	sc.Mint(1000)
	sc.Burn(500)
	sc.ConductAudit("Peg maintained")
	fmt.Println(sc.GetDetails())
}
