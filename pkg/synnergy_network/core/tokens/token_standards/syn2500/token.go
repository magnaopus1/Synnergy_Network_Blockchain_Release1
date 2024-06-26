package syn2500

import (
    "errors"
    "fmt"
    "time"
)

// DAOToken represents a token used within a DAO to represent membership and voting rights.
type DAOToken struct {
    TokenID     string    `json:"tokenId"`     // Unique identifier for the token
    Owner       string    `json:"owner"`       // Owner's identifier
    DAOID       string    `json:"daoId"`       // DAO's identifier this token is associated with
    VotingPower int       `json:"votingPower"` // Voting power conferred by this token
    IssuedDate  time.Time `json:"issuedDate"`  // Date when the token was issued
    Active      bool      `json:"active"`      // Status to indicate if the token is active
}

// DAOLedger manages the lifecycle and ownership of DAO tokens.
type DAOLedger struct {
    Tokens map[string]DAOToken // Maps Token IDs to DAOTokens
    DAOs   map[string]struct {
        TotalVotingPower int
        TotalSupply      int
    } // Maps DAO IDs to total voting power and total token supply
}

// NewDAOLedger initializes a new ledger for managing DAO tokens.
func NewDAOLedger() *DAOLedger {
    return &DAOLedger{
        Tokens: make(map[string]DAOToken),
        DAOs:   make(map[string]struct {
            TotalVotingPower int
            TotalSupply      int
        }),
    }
}

// IssueToken creates and registers a new DAO token.
func (dl *DAOLedger) IssueToken(token DAOToken) error {
    if _, exists := dl.Tokens[token.TokenID]; exists {
        return fmt.Errorf("token with ID %s already exists", token.TokenID)
    }

    daoInfo, exists := dl.DAOs[token.DAOID]
    if !exists {
        daoInfo = struct {
            TotalVotingPower int
            TotalSupply      int
        }{}
    }

    token.IssuedDate = time.Now()
    token.Active = true
    dl.Tokens[token.TokenID] = token
    daoInfo.TotalVotingPower += token.VotingPower
    daoInfo.TotalSupply++
    dl.DAOs[token.DAOID] = daoInfo
    return nil
}

// TransferToken changes the ownership of a DAO token to a new owner.
func (dl *DAOLedger) TransferToken(tokenID, newOwner string) error {
    token, exists := dl.Tokens[tokenID]
    if !exists {
        return errors.New("token does not exist")
    }

    token.Owner = newOwner
    dl.Tokens[tokenID] = token
    return nil
}

// DeactivateToken marks a token as inactive, effectively removing it from active governance.
func (dl *DAOLedger) DeactivateToken(tokenID string) error {
    token, exists := dl.Tokens[tokenID]
    if !exists {
        return errors.New("token not found")
    }

    if !token.Active {
        return fmt.Errorf("token %s is already inactive", tokenID)
    }

    token.Active = false
    dl.DAOs[token.DAOID].TotalVotingPower -= token.VotingPower
    dl.Tokens[tokenID] = token
    return nil
}

// GetToken retrieves a DAO token by its ID.
func (dl *DAOLedger) GetToken(tokenID string) (DAOToken, error) {
    token, exists := dl.Tokens[tokenID]
    if !exists {
        return DAOToken{}, fmt.Errorf("token with ID %s not found", tokenID)
    }
    return token, nil
}

// ListTokensByDAO lists all active tokens for a specific DAO.
func (dl *DAOLedger) ListTokensByDAO(daoID string) ([]DAOToken, error) {
    var tokens []DAOToken
    for _, token := range dl.Tokens {
        if token.DAOID == daoID && token.Active {
            tokens = append(tokens, token)
        }
    }
    if len(tokens) == 0 {
        return nil, fmt.Errorf("no active tokens found for DAO ID %s", daoID)
    }
    return tokens, nil
}
