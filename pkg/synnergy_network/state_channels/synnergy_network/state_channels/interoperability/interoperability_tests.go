package interoperability

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewAtomicSwap(t *testing.T) {
	secret := []byte("supersecret")
	swap := NewAtomicSwap("swap1", "participantA", "participantB", 100, 200, secret)

	assert.Equal(t, "swap1", swap.SwapID)
	assert.Equal(t, "participantA", swap.ParticipantAID)
	assert.Equal(t, "participantB", swap.ParticipantBID)
	assert.Equal(t, int64(100), swap.AmountA)
	assert.Equal(t, int64(200), swap.AmountB)
	assert.Equal(t, SwapActive, swap.Status)
}

func TestCompleteSwap(t *testing.T) {
	secret := []byte("supersecret")
	swap := NewAtomicSwap("swap1", "participantA", "participantB", 100, 200, secret)

	err := swap.CompleteSwap(secret)
	assert.Nil(t, err)
	assert.Equal(t, SwapComplete, swap.Status)
}

func TestExpireSwap(t *testing.T) {
	secret := []byte("supersecret")
	swap := NewAtomicSwap("swap1", "participantA", "participantB", 100, 200, secret)

	swap.ExpireSwap()
	assert.Equal(t, SwapExpired, swap.Status)
}

func TestEncryptDecryptAtomicSwap(t *testing.T) {
	secret := []byte("supersecret")
	swap := NewAtomicSwap("swap1", "participantA", "participantB", 100, 200, secret)
	key := []byte("encryptionkey123")

	encrypted, err := swap.EncryptSwap(key)
	assert.Nil(t, err)

	newSwap := &AtomicSwap{}
	err = newSwap.DecryptSwap(encrypted, key)
	assert.Nil(t, err)
	assert.Equal(t, swap.SwapID, newSwap.SwapID)
	assert.Equal(t, swap.ParticipantAID, newSwap.ParticipantAID)
	assert.Equal(t, swap.ParticipantBID, newSwap.ParticipantBID)
	assert.Equal(t, swap.AmountA, newSwap.AmountA)
	assert.Equal(t, swap.AmountB, newSwap.AmountB)
	assert.Equal(t, swap.Status, newSwap.Status)
}

func TestNewCrossChainBridge(t *testing.T) {
	bridge := NewCrossChainBridge("bridge1", "chainA", "chainB", []string{"participantA", "participantB"}, 100, 200)

	assert.Equal(t, "bridge1", bridge.BridgeID)
	assert.Equal(t, "chainA", bridge.ChainAID)
	assert.Equal(t, "chainB", bridge.ChainBID)
	assert.Equal(t, []string{"participantA", "participantB"}, bridge.ParticipantIDs)
	assert.Equal(t, int64(100), bridge.AmountA)
	assert.Equal(t, int64(200), bridge.AmountB)
	assert.Equal(t, BridgeActive, bridge.Status)
}

func TestCloseBridge(t *testing.T) {
	bridge := NewCrossChainBridge("bridge1", "chainA", "chainB", []string{"participantA", "participantB"}, 100, 200)

	err := bridge.CloseBridge()
	assert.Nil(t, err)
	assert.Equal(t, BridgeClosed, bridge.Status)
}

func TestEncryptDecryptCrossChainBridge(t *testing.T) {
	bridge := NewCrossChainBridge("bridge1", "chainA", "chainB", []string{"participantA", "participantB"}, 100, 200)
	key := []byte("encryptionkey123")

	encrypted, err := bridge.EncryptBridge(key)
	assert.Nil(t, err)

	newBridge := &CrossChainBridge{}
	err = newBridge.DecryptBridge(encrypted, key)
	assert.Nil(t, err)
	assert.Equal(t, bridge.BridgeID, newBridge.BridgeID)
	assert.Equal(t, bridge.ChainAID, newBridge.ChainAID)
	assert.Equal(t, bridge.ChainBID, newBridge.ChainBID)
	assert.Equal(t, bridge.ParticipantIDs, newBridge.ParticipantIDs)
	assert.Equal(t, bridge.AmountA, newBridge.AmountA)
	assert.Equal(t, bridge.AmountB, newBridge.AmountB)
	assert.Equal(t, bridge.Status, newBridge.Status)
}

func TestNewCrossChainDAppEco(t *testing.T) {
	dapp := NewCrossChainDAppEco("app1", "chainA", []string{"participantA", "participantB"}, []byte("contractData"))

	assert.Equal(t, "app1", dapp.AppID)
	assert.Equal(t, "chainA", dapp.ChainID)
	assert.Equal(t, []string{"participantA", "participantB"}, dapp.ParticipantIDs)
	assert.Equal(t, []byte("contractData"), dapp.ContractData)
	assert.Equal(t, DAppActive, dapp.Status)
}

func TestCloseDAppEco(t *testing.T) {
	dapp := NewCrossChainDAppEco("app1", "chainA", []string{"participantA", "participantB"}, []byte("contractData"))

	err := dapp.CloseDAppEco()
	assert.Nil(t, err)
	assert.Equal(t, DAppClosed, dapp.Status)
}

func TestEncryptDecryptCrossChainDAppEco(t *testing.T) {
	dapp := NewCrossChainDAppEco("app1", "chainA", []string{"participantA", "participantB"}, []byte("contractData"))
	key := []byte("encryptionkey123")

	encrypted, err := dapp.EncryptDAppEco(key)
	assert.Nil(t, err)

	newDApp := &CrossChainDAppEco{}
	err = newDApp.DecryptDAppEco(encrypted, key)
	assert.Nil(t, err)
	assert.Equal(t, dapp.AppID, newDApp.AppID)
	assert.Equal(t, dapp.ChainID, newDApp.ChainID)
	assert.Equal(t, dapp.ParticipantIDs, newDApp.ParticipantIDs)
	assert.Equal(t, dapp.ContractData, newDApp.ContractData)
	assert.Equal(t, dapp.Status, newDApp.Status)
}

func TestNewCrossChainStateChannel(t *testing.T) {
	stateChannel := NewCrossChainStateChannel("channel1", "chainA", "chainB", []string{"participantA", "participantB"}, []byte("stateData"))

	assert.Equal(t, "channel1", stateChannel.ChannelID)
	assert.Equal(t, "chainA", stateChannel.ChainAID)
	assert.Equal(t, "chainB", stateChannel.ChainBID)
	assert.Equal(t, []string{"participantA", "participantB"}, stateChannel.ParticipantIDs)
	assert.Equal(t, []byte("stateData"), stateChannel.StateData)
	assert.Equal(t, StateChannelActive, stateChannel.Status)
}

func TestCloseStateChannel(t *testing.T) {
	stateChannel := NewCrossChainStateChannel("channel1", "chainA", "chainB", []string{"participantA", "participantB"}, []byte("stateData"))

	err := stateChannel.CloseStateChannel()
	assert.Nil(t, err)
	assert.Equal(t, StateChannelClosed, stateChannel.Status)
}

func TestEncryptDecryptCrossChainStateChannel(t *testing.T) {
	stateChannel := NewCrossChainStateChannel("channel1", "chainA", "chainB", []string{"participantA", "participantB"}, []byte("stateData"))
	key := []byte("encryptionkey123")

	encrypted, err := stateChannel.EncryptStateChannel(key)
	assert.Nil(t, err)

	newStateChannel := &CrossChainStateChannel{}
	err = newStateChannel.DecryptStateChannel(encrypted, key)
	assert.Nil(t, err)
	assert.Equal(t, stateChannel.ChannelID, newStateChannel.ChannelID)
	assert.Equal(t, stateChannel.ChainAID, newStateChannel.ChainAID)
	assert.Equal(t, stateChannel.ChainBID, newStateChannel.ChainBID)
	assert.Equal(t, stateChannel.ParticipantIDs, newStateChannel.ParticipantIDs)
	assert.Equal(t, stateChannel.StateData, newStateChannel.StateData)
	assert.Equal(t, stateChannel.Status, newStateChannel.Status)
}
