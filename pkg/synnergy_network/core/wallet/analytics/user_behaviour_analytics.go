package analytics

import (
	"fmt"
	"time"

	"github.com/synthron_blockchain_final/pkg/layer0/core/transaction/transaction_types"
	"github.com/synthron_blockchain_final/pkg/layer0/core/wallet"
)

// UserBehaviorAnalytics handles analytics related to user behavior in transactions.
type UserBehaviorAnalytics struct {
	wallets map[string]*wallet.Wallet
}

// NewUserBehaviorAnalytics creates a new instance of UserBehaviorAnalytics.
func NewUserBehaviorAnalytics() *UserBehaviorAnalytics {
	return &UserBehaviorAnalytics{
		wallets: make(map[string]*wallet.Wallet),
	}
}

// AddWallet adds a wallet to the analytics tracking.
func (uba *UserBehaviorAnalytics) AddWallet(wallet *wallet.Wallet) {
	uba.wallets[wallet.Address] = wallet
}

// TrackTransaction tracks a transaction and updates the relevant analytics.
func (uba *UserBehaviorAnalytics) TrackTransaction(tx transaction_types.Transaction) {
	if wallet, exists := uba.wallets[tx.FromAddress]; exists {
		wallet.AddTransaction(tx)
	}
	if wallet, exists := uba.wallets[tx.ToAddress]; exists {
		wallet.AddTransaction(tx)
	}
}

// AnalyzeSpendingPatterns analyzes the spending patterns of a specific wallet over a specified period.
func (uba *UserBehaviorAnalytics) AnalyzeSpendingPatterns(walletAddress string, start, end time.Time) {
	wallet, exists := uba.wallets[walletAddress]
	if !exists {
		fmt.Printf("Wallet with address %s not found.\n", walletAddress)
		return
	}

	totalSpent := 0.0
	for _, tx := range wallet.Transactions {
		if tx.Timestamp.After(start) && tx.Timestamp.Before(end) && tx.FromAddress == walletAddress {
			totalSpent += tx.Amount
		}
	}
	fmt.Printf("Total spent by wallet %s from %s to %s: %f\n", walletAddress, start, end, totalSpent)
}

// AnalyzeReceivingPatterns analyzes the receiving patterns of a specific wallet over a specified period.
func (uba *UserBehaviorAnalytics) AnalyzeReceivingPatterns(walletAddress string, start, end time.Time) {
	wallet, exists := uba.wallets[walletAddress]
	if !exists {
		fmt.Printf("Wallet with address %s not found.\n", walletAddress)
		return
	}

	totalReceived := 0.0
	for _, tx := range wallet.Transactions {
		if tx.Timestamp.After(start) && tx.Timestamp.Before(end) && tx.ToAddress == walletAddress {
			totalReceived += tx.Amount
		}
	}
	fmt.Printf("Total received by wallet %s from %s to %s: %f\n", walletAddress, start, end, totalReceived)
}

// IdentifyFrequentContacts identifies the most frequent transaction partners of a specific wallet.
func (uba *UserBehaviorAnalytics) IdentifyFrequentContacts(walletAddress string) {
	wallet, exists := uba.wallets[walletAddress]
	if !exists {
		fmt.Printf("Wallet with address %s not found.\n", walletAddress)
		return
	}

	contactFrequency := make(map[string]int)
	for _, tx := range wallet.Transactions {
		if tx.FromAddress == walletAddress {
			contactFrequency[tx.ToAddress]++
		}
		if tx.ToAddress == walletAddress {
			contactFrequency[tx.FromAddress]++
		}
	}

	fmt.Printf("Frequent contacts of wallet %s:\n", walletAddress)
	for contact, frequency := range contactFrequency {
		fmt.Printf("Address: %s, Frequency: %d\n", contact, frequency)
	}
}

// DetectSuspiciousActivity detects suspicious activity based on transaction patterns.
func (uba *UserBehaviorAnalytics) DetectSuspiciousActivity(walletAddress string, threshold float64) {
	wallet, exists := uba.wallets[walletAddress]
	if !exists {
		fmt.Printf("Wallet with address %s not found.\n", walletAddress)
		return
	}

	for _, tx := range wallet.Transactions {
		if tx.Amount > threshold {
			fmt.Printf("Suspicious transaction detected: %v\n", tx)
		}
	}
}

// GenerateUserBehaviorReport generates a comprehensive report of user behavior over a specified period.
func (uba *UserBehaviorAnalytics) GenerateUserBehaviorReport(walletAddress string, start, end time.Time) {
	wallet, exists := uba.wallets[walletAddress]
	if !exists {
		fmt.Printf("Wallet with address %s not found.\n", walletAddress)
		return
	}

	fmt.Printf("User Behavior Report for wallet %s from %s to %s:\n", walletAddress, start, end)
	uba.AnalyzeSpendingPatterns(walletAddress, start, end)
	uba.AnalyzeReceivingPatterns(walletAddress, start, end)
	uba.IdentifyFrequentContacts(walletAddress)
	uba.DetectSuspiciousActivity(walletAddress, 1000.0) // Example threshold
}
