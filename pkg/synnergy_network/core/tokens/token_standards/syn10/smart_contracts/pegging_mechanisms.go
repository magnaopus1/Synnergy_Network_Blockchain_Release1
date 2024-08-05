package smart_contracts

import (
    "errors"
    "math/big"
    "sync"
    "time"
)

// PeggingMechanism manages the pegging of SYN10 tokens to fiat currencies and the potential transition to a free-floating value
type PeggingMechanism struct {
    mu                sync.RWMutex
    fiatCurrency      string
    pegValue          *big.Float
    currentValue      *big.Float
    collateralReserves map[string]*big.Float
    stabilizationActive bool
    removalDate       time.Time
}

// NewPeggingMechanism initializes the PeggingMechanism with a fiat currency peg and initial values
func NewPeggingMechanism(fiatCurrency string, pegValue, initialValue *big.Float) *PeggingMechanism {
    return &PeggingMechanism{
        fiatCurrency:      fiatCurrency,
        pegValue:          pegValue,
        currentValue:      initialValue,
        collateralReserves: make(map[string]*big.Float),
        stabilizationActive: true,
        removalDate:       time.Time{},
    }
}

// UpdatePegValue updates the pegged value and triggers necessary adjustments
func (pm *PeggingMechanism) UpdatePegValue(newPegValue *big.Float) error {
    pm.mu.Lock()
    defer pm.mu.Unlock()

    if !pm.stabilizationActive {
        return errors.New("peg stabilization is inactive")
    }

    pm.pegValue = newPegValue
    pm.adjustCollateral() // Method to adjust collateral reserves based on new peg value
    pm.currentValue = newPegValue // Immediate adjustment for simplicity; real implementation might have complex logic

    return nil
}

// adjustCollateral adjusts the collateral reserves based on the peg value
func (pm *PeggingMechanism) adjustCollateral() {
    // Logic to adjust collateral reserves
    // This could involve transferring assets, buying/selling reserves, etc.
}

// GetCurrentValue returns the current value of the SYN10 token
func (pm *PeggingMechanism) GetCurrentValue() *big.Float {
    pm.mu.RLock()
    defer pm.mu.RUnlock()
    return pm.currentValue
}

// AddCollateral adds collateral to the reserves
func (pm *PeggingMechanism) AddCollateral(asset string, amount *big.Float) {
    pm.mu.Lock()
    defer pm.mu.Unlock()
    if pm.collateralReserves[asset] == nil {
        pm.collateralReserves[asset] = new(big.Float)
    }
    pm.collateralReserves[asset].Add(pm.collateralReserves[asset], amount)
}

// RemoveCollateral removes collateral from the reserves
func (pm *PeggingMechanism) RemoveCollateral(asset string, amount *big.Float) error {
    pm.mu.Lock()
    defer pm.mu.Unlock()

    if pm.collateralReserves[asset] == nil || pm.collateralReserves[asset].Cmp(amount) < 0 {
        return errors.New("insufficient collateral")
    }
    pm.collateralReserves[asset].Sub(pm.collateralReserves[asset], amount)
    return nil
}

// InitiatePegRemoval schedules the removal of the peg
func (pm *PeggingMechanism) InitiatePegRemoval(removalDate time.Time) {
    pm.mu.Lock()
    defer pm.mu.Unlock()
    pm.removalDate = removalDate
    pm.stabilizationActive = false
}

// FinalizePegRemoval finalizes the removal of the peg, allowing the token to free-float
func (pm *PeggingMechanism) FinalizePegRemoval() error {
    pm.mu.Lock()
    defer pm.mu.Unlock()

    if time.Now().Before(pm.removalDate) {
        return errors.New("removal date not reached")
    }

    pm.pegValue = nil
    pm.stabilizationActive = false

    // Additional logic to manage the transition to a free-floating value

    return nil
}

// GetCollateralDetails provides details about the current collateral reserves
func (pm *PeggingMechanism) GetCollateralDetails() map[string]*big.Float {
    pm.mu.RLock()
    defer pm.mu.RUnlock()

    // Return a copy of the collateral details to avoid external modification
    collateralCopy := make(map[string]*big.Float)
    for k, v := range pm.collateralReserves {
        collateralCopy[k] = new(big.Float).Set(v)
    }
    return collateralCopy
}

// IsPegActive checks if the stabilization mechanism is currently active
func (pm *PeggingMechanism) IsPegActive() bool {
    pm.mu.RLock()
    defer pm.mu.RUnlock()
    return pm.stabilizationActive
}

