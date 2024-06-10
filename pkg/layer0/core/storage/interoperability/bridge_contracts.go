package interoperability

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"

	"synthron_blockchain/pkg/layer0/core/blockchain"
	"synthron_blockchain/pkg/layer0/core/crypto"
)

// BridgeContract represents the logic and data needed to bridge assets between blockchains.
type BridgeContract struct {
	registry     map[string]Token
	blockchains  map[string]blockchain.Blockchain
	mutex        sync.Mutex
	cryptoHelper crypto.Crypto
}

// Token represents the details of a token managed by a bridge contract.
type Token struct {
	ID        string
	Origin    string
	Owner     string
	Locked    bool
	BlockHash string
}

// NewBridgeContract initializes a new bridge contract instance.
func NewBridgeContract(cryptoHelper crypto.Crypto) *BridgeContract {
	return &BridgeContract{
		registry:     make(map[string]Token),
		blockchains:  make(map[string]blockchain.Blockchain),
		cryptoHelper: cryptoHelper,
	}
}

// RegisterBlockchain adds a new blockchain to the bridge system.
func (bc *BridgeContract) RegisterBlockchain(name string, chain blockchain.Blockchain) {
	bc.blockchains[name] = chain
}

// LockToken locks a token on its origin blockchain to prepare for cross-chain transfer.
func (bc *BridgeContract) LockToken(tokenID, blockchainName string) error {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	token, exists := bc.registry[tokenID]
	if !exists {
		return errors.New("token does not exist")
	}

	if token.Locked {
		return errors.New("token already locked")
	}

	bChain, ok := bc.blockchains[blockchainName]
	if !ok {
		return errors.New("blockchain not registered")
	}

	if err := bChain.LockAsset(tokenID); err != nil {
		return err
	}

	token.Locked = true
	token.BlockHash = bChain.CurrentBlockHash()
	bc.registry[tokenID] = token

	return nil
}

// UnlockToken releases a token on its origin blockchain after a failed or reversed transfer.
func (bc *BridgeContract) UnlockToken(tokenID, blockchainName string) error {
	bc.mutex.Lock()
	defer bc.Mutex.Unlock()

	token, exists := bc.registry[tokenID]
	if !exists || !token.Locked {
		return errors.New("token does not exist or is not locked")
	}

	bChain, ok := bc.blockchains[blockchainName]
	if !ok {
		return errors.New("blockchain not registered")
	}

	if err := bChain.UnlockAsset(tokenID); err != nil {
		return err
	}

	token.Locked = false
	bc.registry[tokenID] = token

	return nil
}

// MintToken mints a new token on a target blockchain corresponding to the locked token on the origin blockchain.
func (bc *BridgeContract) MintToken(originalTokenID, targetBlockchainName, newOwner string) (string, error) {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	originToken, exists := bc.registry[originalTokenID]
	if !exists || !originToken.Locked {
		return "", errors.New("original token does not exist or is not locked")
	}

	targetChain, ok := bc.blockchains[targetBlockchainName]
	if !ok {
		return "", errors.New("target blockchain not registered")
	}

	newTokenID := generateTokenID()
	newToken := Token{
		ID:        newTokenID,
		Origin:    originToken.Origin,
		Owner:     newOwner,
		Locked:    false,
		BlockHash: targetChain.CurrentBlockHash(),
	}

	if err := targetChain.MintAsset(newTokenID, newOwner); err != nil {
		return "", err
	}

	bc.registry[newTokenID] = newToken
	return newTokenID, nil
}

// generateTokenID creates a unique identifier for a new token.
func generateTokenID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

