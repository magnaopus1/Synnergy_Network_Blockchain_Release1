package syn3200

import (
    "errors"
    "fmt"
    "time"
)

type Metadata struct {
    Terms      string `json:"terms"`
    Conditions string `json:"conditions"`
}

type Bill struct {
    BillID          string    `json:"billId"`
    Issuer          string    `json:"issuer"`
    Payer           string    `json:"payer"`
    OriginalAmount  float64   `json:"originalAmount"`
    RemainingAmount float64   `json:"remainingAmount"`
    DueDate         time.Time `json:"dueDate"`
    Paid            bool      `json:"paid"`
    Metadata        Metadata  `json:"metadata"`
}

type BillToken struct {
    TokenID         string    `json:"tokenId"`
    Bill            *Bill     `json:"bill"`
    IssuedDate      time.Time `json:"issuedDate"`
    LastPaymentDate time.Time `json:"lastPaymentDate"`
}

type BillLedger struct {
    Tokens         map[string]BillToken
    TotalSupply    float64
    PaymentHistory map[string][]float64
}

func NewBillLedger() *BillLedger {
    return &BillLedger{
        Tokens:         make(map[string]BillToken),
        PaymentHistory: make(map[string][]float64),
    }
}

func (bl *BillLedger) RecordPayment(tokenID string, paymentAmount float64) error {
    token, exists := bl.Tokens[tokenID]
    if !exists {
        return errors.New("bill token not found")
    }

    if token.Bill.RemainingAmount < paymentAmount {
        return errors.New("payment exceeds the remaining amount")
    }

    token.Bill.RemainingAmount -= paymentAmount
    if token.Bill.RemainingAmount == 0 {
        token.Bill.Paid = true
    }
    token.LastPaymentDate = time.Now()
    bl.Tokens[tokenID] = token
    bl.PaymentHistory[tokenID] = append(bl.PaymentHistory[tokenID], paymentAmount)

    return nil
}

func (bl *BillLedger) ListRecentPayments(tokenID string) ([]float64, error) {
    payments, exists := bl.PaymentHistory[tokenID]
    if !exists {
        return nil, fmt.Errorf("no payment history found for token %s", tokenID)
    }
    return payments, nil
}
