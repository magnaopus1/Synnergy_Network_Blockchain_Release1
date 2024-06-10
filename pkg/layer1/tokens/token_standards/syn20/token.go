package syn20

import (
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"synthron-blockchain/pkg/common"
)

// Token represents a SYN20 fungible token with enhanced capabilities.
type Token struct {
	symbol         string
	name           string
	totalSupply    uint64
	decimals       uint8
	balances       map[string]uint64
	allowed        map[string]map[string]uint64
	transactionLog []common.TransactionRecord
	fee            uint64 // Fee for transactions, could be used for burning or redistribution
	mutex          sync.RWMutex
}

// NewToken initializes a new SYN20 token.
func NewToken(name, symbol string, decimals uint8, initialSupply uint64, creatorAddress string, transactionFee uint64) *Token {
	t := &Token{
		symbol:      symbol,
		name:        name,
		decimals:    decimals,
		totalSupply: initialSupply,
		balances:    make(map[string]uint64),
		allowed:     make(map[string]map[string]uint64),
		fee:         transactionFee,
	}
	t.balances[creatorAddress] = initialSupply
	log.Printf("Created new token: %s (%s) with supply %d and transaction fee %d", name, symbol, initialSupply, transactionFee)
	return t
}

// TotalSupply returns the current total supply of the token.
func (t *Token) TotalSupply() uint64 {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	return t.totalSupply
}

// BalanceOf retrieves the balance of a given address.
func (t *Token) BalanceOf(address string) uint64 {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	return t.balances[address]
}

// Transfer moves a specified amount of tokens from sender to recipient, applying a transaction fee.
func (t *Token) Transfer(from, to string, amount uint64) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if amount <= t.fee || t.balances[from] < amount {
		return errors.New("insufficient balance or amount too low to cover fees")
	}

	netAmount := amount - t.fee
	t.balances[from] -= amount
	t.balances[to] += netAmount
	t.balances["fee_collector"] += t.fee // assuming 'fee_collector' is a predefined address for collecting fees

	t.logTransaction(from, to, amount, t.fee)
	return nil
}

// Approve sets aside an allowance for a spender on behalf of an owner.
func (t *Token) Approve(owner, spender string, amount uint64) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if t.balances[owner] < amount {
		return errors.New("balance is lower than the approved amount")
	}
	if t.allowed[owner] == nil {
		t.allowed[owner] = make(map[string]uint64)
	}
	t.allowed[owner][spender] = amount

	log.Printf("Approval: %s is allowed to spend %d tokens on behalf of %s", spender, amount, owner)
	return nil
}

// TransferFrom moves tokens from one account to another, based on a previously set allowance.
func (t *Token) TransferFrom(owner, spender, recipient string, amount uint64) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if t.allowed[owner][spender] < amount {
		return errors.New("allowance is less than the amount to be transferred")
	}
	if t.balances[owner] < amount {
		return errors.New("insufficient balance")
	}

	t.balances[owner] -= amount
	t.balances[recipient] += amount
	t.allowed[owner][spender] -= amount

	t.logTransaction(owner, recipient, amount, 0)
	return nil
}

// logTransaction records the details of a transaction.
func (t *Token) logTransaction(from, to string, amount, fee uint64) {
	record := common.TransactionRecord{
		From:   from,
		To:     to,
		Amount: amount,
		Fee:    fee,
		Time:   time.Now(),
	}
	t.transactionLog = append(t.transactionLog, record)
	log.Printf("Transaction: %s -> %s, Amount: %d, Fee: %d", from, to, amount, fee)
}
