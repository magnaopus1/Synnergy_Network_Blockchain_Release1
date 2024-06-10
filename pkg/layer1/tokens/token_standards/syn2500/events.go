package syn2500

import (
	"time"
)

// TokenIssuedEvent is triggered when a new DAO token is issued.
type TokenIssuedEvent struct {
	TokenID     string    `json:"tokenId"`
	Owner       string    `json:"owner"`
	DAOID       string    `json:"daoId"`
	VotingPower int       `json:"votingPower"`
	IssuedDate  time.Time `json:"issuedDate"`
}

// TokenTransferredEvent is triggered when a DAO token is transferred from one owner to another.
type TokenTransferredEvent struct {
	TokenID  string    `json:"tokenId"`
	From     string    `json:"from"`
	To       string    `json:"to"`
	TransferDate time.Time `json:"transferDate"`
}

// TokenDeactivatedEvent is triggered when a DAO token is deactivated.
type TokenDeactivatedEvent struct {
	TokenID        string    `json:"tokenId"`
	DeactivatedBy  string    `json:"deactivatedBy"`
	DeactivationDate time.Time `json:"deactivationDate"`
}

// NewTokenIssuedEvent creates a new instance of TokenIssuedEvent.
func NewTokenIssuedEvent(tokenID, owner, daoID string, votingPower int, issuedDate time.Time) *TokenIssuedEvent {
	return &TokenIssuedEvent{
		TokenID:     tokenID,
		Owner:       owner,
		DAOID:       daoID,
		VotingPower: votingPower,
		IssuedDate:  issuedDate,
	}
}

// NewTokenTransferredEvent creates a new instance of TokenTransferredEvent.
func NewTokenTransferredEvent(tokenID, from, to string, transferDate time.Time) *TokenTransferredEvent {
	return &TokenTransferredEvent{
		TokenID:  tokenID,
		From:     from,
		To:       to,
		TransferDate: transferDate,
	}
}

// NewTokenDeactivatedEvent creates a new instance of TokenDeactivatedEvent.
func NewTokenDeactivatedEvent(tokenID, deactivatedBy string, deactivationDate time.Time) *TokenDeactivatedEvent {
	return &TokenDeactivatedEvent{
		TokenID:        tokenID,
		DeactivatedBy:  deactivatedBy,
		DeactivationDate: deactivationDate,
	}
}

