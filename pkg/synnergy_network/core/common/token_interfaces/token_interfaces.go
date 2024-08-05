package common

import(
	"errors"
)

// Token represents a blockchain token
type Token struct {
	ID       string
	Standard string
	Balance  float64
}

// GetBalance retrieves the balance of the token for the given address
func (t *Token) GetBalance(address string) (float64, error) {
	// Placeholder implementation
	return t.Balance, nil
}

// Transfer transfers the given amount of the token from one address to another
func (t *Token) Transfer(from, to string, amount float64) error {
	// Placeholder implementation
	if t.Balance < amount {
		return errors.New("insufficient balance")
	}
	t.Balance -= amount
	return nil
}