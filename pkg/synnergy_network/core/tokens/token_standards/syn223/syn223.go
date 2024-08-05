package syn223

import (
	"fmt"
	"time"
	"sync"
	"github.com/pkg/synnergy_network/core/tokens/token_standards/syn223/ledger"
	"github.com/pkg/synnergy_network/core/tokens/token_standards/syn223/management"
	"github.com/pkg/synnergy_network/core/tokens/token_standards/syn223/security"
	"github.com/pkg/synnergy_network/core/tokens/token_standards/syn223/transactions"
	"github.com/pkg/synnergy_network/core/tokens/token_standards/syn223/utils"
)

// SYN223 represents the SYN223 token standard
type SYN223 struct {
	Name             string
	Symbol           string
	Decimals         int
	TotalSupply      float64
	Ledger           *ledger.Ledger
	EventLog         *EventLog
	WhitelistManager *management.WhitelistBlacklistManager
	BlacklistManager *management.WhitelistBlacklistManager
	SecurityManager  *security.SecurityManager
	TransactionManager *transactions.TransactionManager
	mutex            sync.Mutex
}

// NewSYN223 initializes a new SYN223 token
func NewSYN223(name, symbol string, decimals int, totalSupply float64) *SYN223 {
	ledger := ledger.NewLedger()
	eventLog := NewEventLog()
	whitelistManager := management.NewWhitelistBlacklistManager()
	blacklistManager := management.NewWhitelistBlacklistManager()
	securityManager := security.NewSecurityManager()
	transactionManager := transactions.NewTransactionManager(ledger, securityManager, eventLog)

	return &SYN223{
		Name:              name,
		Symbol:            symbol,
		Decimals:          decimals,
		TotalSupply:       totalSupply,
		Ledger:            ledger,
		EventLog:          eventLog,
		WhitelistManager:  whitelistManager,
		BlacklistManager:  blacklistManager,
		SecurityManager:   securityManager,
		TransactionManager: transactionManager,
		mutex:             sync.Mutex{},
	}
}

// Transfer transfers tokens from one account to another
func (syn *SYN223) Transfer(from, to string, amount float64) error {
	syn.mutex.Lock()
	defer syn.mutex.Unlock()

	if !syn.WhitelistManager.IsWhitelisted(to) || syn.BlacklistManager.IsBlacklisted(to) {
		details := fmt.Sprintf("Transfer failed from %s to %s: address not whitelisted or blacklisted", from, to)
		syn.EventLog.LogEvent(RevertEvent, details)
		return fmt.Errorf(details)
	}

	if !syn.TransactionManager.IsValidAddress(to) {
		details := fmt.Sprintf("Transfer failed from %s to %s: invalid address", from, to)
		syn.EventLog.LogEvent(RevertEvent, details)
		return fmt.Errorf(details)
	}

	if err := syn.Ledger.Transfer(from, to, amount); err != nil {
		details := fmt.Sprintf("Transfer failed from %s to %s of amount %f: %v", from, to, amount, err)
		syn.EventLog.LogEvent(RevertEvent, details)
		return err
	}

	details := TransferEventDetails(from, to, amount)
	syn.EventLog.LogEvent(TransferEvent, details)
	return nil
}

// Mint creates new tokens and adds them to the total supply
func (syn *SYN223) Mint(to string, amount float64) error {
	syn.mutex.Lock()
	defer syn.mutex.Unlock()

	if syn.SecurityManager.IsMultisigRequired(amount) && !syn.SecurityManager.VerifyMultisig() {
		details := fmt.Sprintf("Minting failed to %s of amount %f: multisig verification failed", to, amount)
		syn.EventLog.LogEvent(RevertEvent, details)
		return fmt.Errorf(details)
	}

	syn.TotalSupply += amount
	syn.Ledger.IncreaseBalance(to, amount)
	details := fmt.Sprintf("Minted %f tokens to %s", amount, to)
	syn.EventLog.LogEvent("Mint", details)
	return nil
}

// Burn removes tokens from the total supply
func (syn *SYN223) Burn(from string, amount float64) error {
	syn.mutex.Lock()
	defer syn.mutex.Unlock()

	if err := syn.Ledger.DecreaseBalance(from, amount); err != nil {
		details := fmt.Sprintf("Burn failed from %s of amount %f: %v", from, amount, err)
		syn.EventLog.LogEvent(RevertEvent, details)
		return err
	}

	syn.TotalSupply -= amount
	details := fmt.Sprintf("Burned %f tokens from %s", amount, from)
	syn.EventLog.LogEvent("Burn", details)
	return nil
}

// AddToWhitelist adds an address to the whitelist
func (syn *SYN223) AddToWhitelist(address string) {
	syn.WhitelistManager.AddToWhitelist(address)
	details := WhitelistUpdateEventDetails(address, "added")
	syn.EventLog.LogEvent(WhitelistEvent, details)
}

// RemoveFromWhitelist removes an address from the whitelist
func (syn *SYN223) RemoveFromWhitelist(address string) {
	syn.WhitelistManager.RemoveFromWhitelist(address)
	details := WhitelistUpdateEventDetails(address, "removed")
	syn.EventLog.LogEvent(WhitelistEvent, details)
}

// AddToBlacklist adds an address to the blacklist
func (syn *SYN223) AddToBlacklist(address string) {
	syn.BlacklistManager.AddToBlacklist(address)
	details := BlacklistUpdateEventDetails(address, "added")
	syn.EventLog.LogEvent(BlacklistEvent, details)
}

// RemoveFromBlacklist removes an address from the blacklist
func (syn *SYN223) RemoveFromBlacklist(address string) {
	syn.BlacklistManager.RemoveFromBlacklist(address)
	details := BlacklistUpdateEventDetails(address, "removed")
	syn.EventLog.LogEvent(BlacklistEvent, details)
}

// GetBalance returns the balance of the given address
func (syn *SYN223) GetBalance(address string) (float64, error) {
	return syn.Ledger.GetBalance(address)
}

// GetEventLog returns the event log
func (syn *SYN223) GetEventLog() *EventLog {
	return syn.EventLog
}

// GetTotalSupply returns the total supply of tokens
func (syn *SYN223) GetTotalSupply() float64 {
	return syn.TotalSupply
}

// Example usage:

func main() {
	token := NewSYN223("SYN Token", "SYN", 18, 1000000)

	// Whitelist some addresses
	token.AddToWhitelist("0xAddress1")
	token.AddToWhitelist("0xAddress2")

	// Transfer tokens
	err := token.Transfer("0xAddress1", "0xAddress2", 100)
	if err != nil {
		fmt.Println(err)
	}

	// Mint tokens
	err = token.Mint("0xAddress1", 500)
	if err != nil {
		fmt.Println(err)
	}

	// Burn tokens
	err = token.Burn("0xAddress2", 50)
	if err != nil {
		fmt.Println(err)
	}

	// Get balance
	balance, err := token.GetBalance("0xAddress1")
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Printf("Balance of 0xAddress1: %f\n", balance)
	}

	// Get total supply
	totalSupply := token.GetTotalSupply()
	fmt.Printf("Total Supply: %f\n", totalSupply)

	// Retrieve and print all events
	allEvents := token.GetEventLog().GetEvents()
	for _, event := range allEvents {
		fmt.Println(event)
	}
}
