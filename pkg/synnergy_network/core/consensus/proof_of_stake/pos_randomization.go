package consensus

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "math/big"

    "github.com/synnergy-network/cryptocurrency/vrf"
)

// VRFProvider offers functionality to generate and verify VRF proofs using ECDSA
type VRFProvider struct {
    PrivateKey *ecdsa.PrivateKey
}

// NewVRFProvider initializes a new VRF provider with a randomly generated ECDSA private key
func NewVRFProvider() (*VRFProvider, error) {
    privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        return nil, err
    }
    return &VRFProvider{PrivateKey: privateKey}, nil
}

// GenerateVRF generates a VRF proof using the provider's private key and a given seed
func (vp *VRFProvider) GenerateVRF(seed []byte) (vrfOutput []byte, vrfProof []byte, err error) {
    return vrf.GenerateVRF(vp.PrivateKey, seed)
}

// VerifyVRF verifies a VRF proof using the corresponding public key, seed, output, and proof
func (vp *VRFProvider) VerifyVRF(publicKey ecdsa.PublicKey, seed, output, proof []byte) bool {
    return vrf.VerifyVRF(&publicKey, seed, output, proof)
}

// ValidatorSelection uses VRF to perform a cryptographically secure, random selection of validators
type ValidatorSelection struct {
    VRFProvider *VRFProvider
}

// NewValidatorSelection creates a new ValidatorSelection instance using an existing VRFProvider
func NewValidatorSelection(vrfProvider *VRFProvider) *ValidatorSelection {
    return &ValidatorSelection{VRFProvider: vrfProvider}
}

// SelectValidators selects validators based on VRF outputs and their stakes
func (vs *ValidatorSelection) SelectValidators(candidates []Validator, seed []byte) ([]Validator, error) {
    if len(candidates) == 0 {
        return nil, errors.New("no candidates available for selection")
    }

    var selected []Validator
    for _, candidate := range candidates {
        vrfOutput, vrfProof, err := vs.VRFProvider.GenerateVRF(append(seed, candidate.ID...))
        if err != nil {
            continue // Skip on error
        }

        if vs.validateSelection(vrfOutput, candidate.Stake) {
            selected = append(selected, candidate)
        }
    }
    return selected, nil
}

// validateSelection checks if a candidate is selected based on their VRF output and stake
func (vs *ValidatorSelection) validateSelection(vrfOutput []byte, stake *big.Int) bool {
    selectionThreshold := new(big.Int).Div(big.NewInt(1<<32), stake) // Higher stake, higher chance
    outputNumber := new(big.Int).SetBytes(vrfOutput)
    return outputNumber.Cmp(selectionThreshold) < 0
}

// Validator represents a stakeholder eligible to become a validator
type Validator struct {
    ID    []byte
    Stake *big.Int
}
