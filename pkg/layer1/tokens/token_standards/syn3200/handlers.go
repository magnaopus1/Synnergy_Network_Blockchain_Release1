package syn3200

import (
    "context"
    "fmt"
    "log"
    "time"
)

type TokenService struct {
    Ledger *BillLedger
}

func NewTokenService(ledger *BillLedger) *TokenService {
    return &TokenService{
        Ledger: ledger,
    }
}

func (s *TokenService) CreateBillToken(issuer, payer string, originalAmount float64, terms, conditions string) (string, error) {
    tokenID := fmt.Sprintf("%s-%s-%d", issuer, payer, time.Now().UnixNano()) // Generate a unique token ID.
    metadata := Metadata{
        Terms: terms,
        Conditions: conditions,
    }
    bill := &Bill{ // Make sure to use a reference to Bill
        BillID:         tokenID,
        Issuer:         issuer,
        Payer:          payer,
        OriginalAmount: originalAmount,
        RemainingAmount: originalAmount,
        DueDate:        time.Now().Add(30 * 24 * time.Hour), // Default due date in 30 days.
        Metadata:       metadata,
    }
    billToken := BillToken{
        TokenID:     tokenID,
        Bill:        bill, // Pass the reference correctly
        IssuedDate:  time.Now(),
        LastPaymentDate: time.Time{}, // Initialized as zero time.
    }

    s.Ledger.Tokens[tokenID] = billToken
    s.Ledger.TotalSupply += originalAmount

    log.Printf("Created new bill token: %v", billToken)

    return tokenID, nil
}

func (s *TokenService) PayBill(tokenID string, amount float64) error {
    return s.Ledger.RecordPayment(tokenID, amount)
}

func (s *TokenService) GetBillToken(tokenID string) (*BillToken, error) {
    token, exists := s.Ledger.Tokens[tokenID]
    if !exists {
        return nil, fmt.Errorf("bill token not found: %s", tokenID)
    }
    return &token, nil
}

func (s *TokenService) ListAllPayments(tokenID string) ([]float64, error) {
    return s.Ledger.ListRecentPayments(tokenID)
}

func (s *TokenService) GetTotalSupply() float64 {
    return s.Ledger.TotalSupply
}

func EventHandler(ctx context.Context, event string, data interface{}) {
    switch event {
    case "paymentReceived":
        tokenID := data.(string)
        log.Printf("Payment received for token ID: %s", tokenID)
    case "tokenIssued":
        tokenID := data.(string)
        log.Printf("New token issued: %s", tokenID)
    default:
        log.Printf("Unhandled event: %s", event)
    }
}
