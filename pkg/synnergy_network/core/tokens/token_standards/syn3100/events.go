package syn3100

import (
    "time"
    "log"
)

// Event types for employment token lifecycle changes.
const (
    EventTypeCreate   = "CREATE"
    EventTypeUpdate   = "UPDATE"
    EventTypeDeactivate = "DEACTIVATE"
)

// EmploymentTokenEvent defines the structure for employment token-related events.
type EmploymentTokenEvent struct {
    Type      string           // Type of the event: CREATE, UPDATE, DEACTIVATE
    TokenID   string           // Identifier of the token involved in the event
    Details   string           // Human-readable details about the event
    Timestamp time.Time        // Timestamp when the event occurred
}

// NewEmploymentTokenEvent creates a new event related to an employment token's lifecycle.
func NewEmploymentTokenEvent(eventType, tokenID, details string) EmploymentTokenEvent {
    return EmploymentTokenEvent{
        Type:      eventType,
        TokenID:   tokenID,
        Details:   details,
        Timestamp: time.Now(),
    }
}

// EmitEvent simulates the emission of an employment token event to a blockchain or logging system.
func EmitEvent(event EmploymentTokenEvent) {
    // In a real-world scenario, this function would interface with a blockchain event system
    // or a logging service to record the event. This example simply prints to standard output.
    log.Printf("Event Emitted: Type=%s, TokenID=%s, Details=%s, Timestamp=%s\n",
        event.Type, event.TokenID, event.Details, event.Timestamp.Format(time.RFC3339))
}

// Here are some example helper functions that might be called within the ledger operations to emit events

// LogTokenCreation logs the creation of a new employment token.
func LogTokenCreation(tokenID string) {
    event := NewEmploymentTokenEvent(EventTypeCreate, tokenID, "New employment token created.")
    EmitEvent(event)
}

// LogTokenUpdate logs updates to an existing employment token.
func LogTokenUpdate(tokenID string, updateDetails string) {
    details := "Employment token updated: " + updateDetails
    event := NewEmploymentTokenEvent(EventTypeUpdate, tokenID, details)
    EmitEvent(event)
}

// LogTokenDeactivation logs the deactivation of an employment token.
func LogTokenDeactivation(tokenID string) {
    event := NewEmploymentTokenEvent(EventTypeDeactivate, tokenID, "Employment token deactivated.")
    EmitEvent(event)
}

