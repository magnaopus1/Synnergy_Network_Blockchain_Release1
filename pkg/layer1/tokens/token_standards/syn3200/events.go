package syn3200

import (
    "encoding/json"
    "log"
    "time"
)

// Event types in the bill token system.
const (
    EventTypeTokenIssued        = "TokenIssued"
    EventTypePaymentReceived    = "PaymentReceived"
    EventTypePaymentAdjusted    = "PaymentAdjusted"
    EventTypeTokenFinalized     = "TokenFinalized"
)

// Event represents a generic event in the bill token lifecycle.
type Event struct {
    Type      string      `json:"type"`
    Timestamp time.Time   `json:"timestamp"`
    Details   interface{} `json:"details"`
}

// TokenIssuedDetails holds data for token issuance events.
type TokenIssuedDetails struct {
    TokenID     string  `json:"tokenId"`
    Issuer      string  `json:"issuer"`
    Payer       string  `json:"payer"`
    Amount      float64 `json:"amount"`
}

// PaymentReceivedDetails holds data for payment receipt events.
type PaymentReceivedDetails struct {
    TokenID     string  `json:"tokenId"`
    Amount      float64 `json:"amount"`
    Remaining   float64 `json:"remaining"`
}

// PaymentAdjustedDetails holds data for payment adjustment events.
type PaymentAdjustedDetails struct {
    TokenID     string  `json:"tokenId"`
    AdjustedAmount float64 `json:"adjustedAmount"`
    Reason      string  `json:"reason"`
}

// TokenFinalizedDetails holds data when a token is fully paid and closed.
type TokenFinalizedDetails struct {
    TokenID     string  `json:"tokenId"`
}

// PublishEvent sends an event to a message broker or event queue.
func PublishEvent(event Event) {
    // In a real application, you would publish this event to a Kafka topic, an MQTT broker, or a similar system.
    eventData, err := json.Marshal(event)
    if err != nil {
        log.Fatalf("Error marshaling event: %v", err)
    }
    log.Printf("Event Published: %s", eventData)
    // Here you would typically have code to connect and send to a broker.
}

// LogEvent locally logs the event, this should be used for development or troubleshooting.
func LogEvent(event Event) {
    eventData, err := json.Marshal(event)
    if err != nil {
        log.Fatalf("Error marshaling event: %v", err)
    }
    log.Printf("Event Logged: %s", eventData)
}

// EmitTokenIssued creates and publishes a token issued event.
func EmitTokenIssued(tokenID, issuer, payer string, amount float64) {
    details := TokenIssuedDetails{
        TokenID: tokenID,
        Issuer: issuer,
        Payer: payer,
        Amount: amount,
    }
    event := Event{
        Type: EventTypeTokenIssued,
        Timestamp: time.Now(),
        Details: details,
    }
    PublishEvent(event)
}

// EmitPaymentReceived creates and publishes a payment received event.
func EmitPaymentReceived(tokenID string, amount, remaining float64) {
    details := PaymentReceivedDetails{
        TokenID: tokenID,
        Amount: amount,
        Remaining: remaining,
    }
    event := Event{
        Type: EventTypePaymentReceived,
        Timestamp: time.Now(),
        Details: details,
    }
    PublishEvent(event)
}

// EmitPaymentAdjusted creates and publishes a payment adjusted event.
func EmitPaymentAdjusted(tokenID string, adjustedAmount float64, reason string) {
    details := PaymentAdjustedDetails{
        TokenID: tokenID,
        AdjustedAmount: adjustedAmount,
        Reason: reason,
    }
    event := Event{
        Type: EventTypePaymentAdjusted,
        Timestamp: time.Now(),
        Details: details,
    }
    PublishEvent(event)
}

// EmitTokenFinalized creates and publishes an event when a token is fully paid.
func EmitTokenFinalized(tokenID string) {
    details := TokenFinalizedDetails{
        TokenID: tokenID,
    }
    event := Event{
        Type: EventTypeTokenFinalized,
        Timestamp: time.Now(),
        Details: details,
    }
    PublishEvent(event)
}
