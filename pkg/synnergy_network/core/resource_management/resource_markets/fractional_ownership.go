package resource_markets

import (
    "fmt"
    "log"
    "math/big"
    "time"

    "github.com/synnergy_network/core/contracts"
    "github.com/synnergy_network/core/resource_security"
    "github.com/synnergy_network/core/auditing"
    "github.com/synnergy_network/core/management"
)

// OwnershipShare represents a share of ownership in a resource
type OwnershipShare struct {
    OwnerID      string
    ResourceID   string
    Share        *big.Float // Fraction of the total resource owned
    PurchaseDate time.Time
    LastDividend time.Time
}

// FractionalOwnershipContract manages fractional ownership of resources
type FractionalOwnershipContract struct {
    Shares map[string][]OwnershipShare // ResourceID to list of shares
}

// NewFractionalOwnershipContract initializes a new fractional ownership contract
func NewFractionalOwnershipContract() *FractionalOwnershipContract {
    return &FractionalOwnershipContract{
        Shares: make(map[string][]OwnershipShare),
    }
}

// AllocateShares allocates fractional shares to a new owner
func (foc *FractionalOwnershipContract) AllocateShares(resourceID, ownerID string, share *big.Float) error {
    if share.Cmp(big.NewFloat(0)) <= 0 || share.Cmp(big.NewFloat(1)) > 0 {
        return fmt.Errorf("invalid share value")
    }

    // Ensure the total shares do not exceed 100%
    totalShares := foc.calculateTotalShares(resourceID)
    if totalShares.Add(totalShares, share).Cmp(big.NewFloat(1)) > 0 {
        return fmt.Errorf("total shares exceed 100%% for resource %s", resourceID)
    }

    ownershipShare := OwnershipShare{
        OwnerID:      ownerID,
        ResourceID:   resourceID,
        Share:        share,
        PurchaseDate: time.Now(),
        LastDividend: time.Now(),
    }

    foc.Shares[resourceID] = append(foc.Shares[resourceID], ownershipShare)

    // Log the allocation for auditing
    auditing.LogShareAllocation(resourceID, ownerID, share)
    return nil
}

// calculateTotalShares calculates the total fractional shares allocated for a resource
func (foc *FractionalOwnershipContract) calculateTotalShares(resourceID string) *big.Float {
    total := big.NewFloat(0)
    for _, share := range foc.Shares[resourceID] {
        total.Add(total, share.Share)
    }
    return total
}

// TransferShares transfers ownership of shares from one owner to another
func (foc *FractionalOwnershipContract) TransferShares(resourceID, fromOwnerID, toOwnerID string, share *big.Float) error {
    if share.Cmp(big.NewFloat(0)) <= 0 {
        return fmt.Errorf("invalid share value")
    }

    fromShares := foc.getSharesForOwner(resourceID, fromOwnerID)
    totalFromShare := big.NewFloat(0)
    for _, s := range fromShares {
        totalFromShare.Add(totalFromShare, s.Share)
    }

    if totalFromShare.Cmp(share) < 0 {
        return fmt.Errorf("not enough shares to transfer")
    }

    // Subtract shares from the seller
    remainingShares := share
    for i := range fromShares {
        if remainingShares.Cmp(big.NewFloat(0)) == 0 {
            break
        }
        if fromShares[i].Share.Cmp(remainingShares) <= 0 {
            remainingShares.Sub(remainingShares, fromShares[i].Share)
            foc.Shares[resourceID] = removeShare(foc.Shares[resourceID], fromShares[i])
        } else {
            fromShares[i].Share.Sub(fromShares[i].Share, remainingShares)
            remainingShares = big.NewFloat(0)
        }
    }

    // Add shares to the buyer
    foc.AllocateShares(resourceID, toOwnerID, share)
    return nil
}

// removeShare removes a specific share from the list
func removeShare(shares []OwnershipShare, share OwnershipShare) []OwnershipShare {
    for i, s := range shares {
        if s.OwnerID == share.OwnerID && s.ResourceID == share.ResourceID && s.Share.Cmp(share.Share) == 0 {
            return append(shares[:i], shares[i+1:]...)
        }
    }
    return shares
}

// DistributeDividends distributes dividends to all fractional owners of a resource
func (foc *FractionalOwnershipContract) DistributeDividends(resourceID string, totalDividend *big.Float) error {
    for i, share := range foc.Shares[resourceID] {
        dividend := new(big.Float).Mul(share.Share, totalDividend)
        // Update the owner's last dividend distribution time
        foc.Shares[resourceID][i].LastDividend = time.Now()
        // Log the distribution for auditing
        auditing.LogDividendDistribution(resourceID, share.OwnerID, dividend)
    }
    return nil
}

// getSharesForOwner returns the shares owned by a specific owner for a resource
func (foc *FractionalOwnershipContract) getSharesForOwner(resourceID, ownerID string) []OwnershipShare {
    var ownerShares []OwnershipShare
    for _, share := range foc.Shares[resourceID] {
        if share.OwnerID == ownerID {
            ownerShares = append(ownerShares, share)
        }
    }
    return ownerShares
}

// Additional functions for governance, voting, and marketplace integration can be added
