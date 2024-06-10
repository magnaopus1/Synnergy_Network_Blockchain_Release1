package syn2900

import (
    "time"
)

// InsuranceTokenEvent defines the structure for insurance token-related events.
type InsuranceTokenEvent struct {
    Type        string          `json:"type"`        // Type of event (e.g., Issued, Activated, Deactivated, Transferred)
    TokenID     string          `json:"tokenId"`     // ID of the token related to the event
    Timestamp   time.Time       `json:"timestamp"`   // Timestamp when the event occurred
    Details     interface{}     `json:"details"`     // Detailed data about the event
}

// InsurancePolicyUpdateEvent captures details about updates to an insurance policy.
type InsurancePolicyUpdateEvent struct {
    PolicyID    string          `json:"policyId"`    // ID of the policy that was updated
    Changes     map[string]interface{} `json:"changes"` // Description of what has changed
}

// NewInsuranceTokenIssued creates an event when a new insurance token is issued.
func NewInsuranceTokenIssued(tokenID string) InsuranceTokenEvent {
    return InsuranceTokenEvent{
        Type:      "Issued",
        TokenID:   tokenID,
        Timestamp: time.Now(),
        Details:   "New insurance token issued",
    }
}

// NewInsuranceTokenActivated creates an event when an insurance token is activated.
func NewInsuranceTokenActivated(tokenID string) InsuranceTokenEvent {
    return InsuranceTokenEvent{
        Type:      "Activated",
        TokenID:   tokenID,
        Timestamp: time.Now(),
        Details:   "Insurance token activated",
    }
}

// NewInsuranceTokenDeactivated creates an event when an insurance token is deactivated.
func NewInsuranceTokenDeactivated(tokenID string) InsuranceTokenEvent {
    return InsuranceTokenEvent{
        Type:      "Deactivated",
        TokenID:   tokenID,
        Timestamp: time.Now(),
        Details:   "Insurance token deactivated",
    }
}

// NewInsuranceTokenTransferred creates an event when ownership of an insurance token is transferred.
func NewInsuranceTokenTransferred(tokenID, fromOwner, toOwner string) InsuranceTokenEvent {
    return InsuranceTokenEvent{
        Type:      "Transferred",
        TokenID:   tokenID,
        Timestamp: time.Now(),
        Details:   map[string]string{"from": fromOwner, "to": toOwner},
    }
}

// NewPolicyUpdated creates an event when changes are made to an insurance policy.
func NewPolicyUpdated(policyID string, changes map[string]interface{}) InsurancePolicyUpdateEvent {
    return InsurancePolicyUpdateEvent{
        PolicyID: policyID,
        Changes:  changes,
    }
}

// The events in this module can be used to log activities, notify stakeholders, or trigger external systems
// and processes that might be interested in insurance token lifecycle events.
