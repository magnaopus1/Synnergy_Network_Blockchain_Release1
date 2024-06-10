package smart_contract_core

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// StateChannel represents a state channel for off-chain transactions
type StateChannel struct {
	ID               string
	Participants     []string
	State            string
	Nonce            int
	Timeout          time.Time
	Signature        string
}

// OpenStateChannel initializes a new state channel
func OpenStateChannel(participants []string, timeout time.Duration) (*StateChannel, error) {
	if len(participants) < 2 {
		return nil, errors.New("a state channel requires at least two participants")
	}

	channelID := generateChannelID(participants)
	channel := &StateChannel{
		ID:           channelID,
		Participants: participants,
		State:        "",
		Nonce:        0,
		Timeout:      time.Now().Add(timeout),
	}

	return channel, nil
}

// UpdateState updates the state of the state channel
func (sc *StateChannel) UpdateState(newState string, signature string) error {
	if time.Now().After(sc.Timeout) {
		return errors.New("state channel has timed out")
	}

	if !verifySignature(newState, signature, sc.Participants) {
		return errors.New("invalid signature")
	}

	sc.State = newState
	sc.Nonce++
	sc.Signature = signature

	return nil
}

// CloseStateChannel closes the state channel and finalizes the state on-chain
func (sc *StateChannel) CloseStateChannel() error {
	if time.Now().After(sc.Timeout) {
		return errors.New("state channel has timed out")
	}

	if err := finalizeStateOnChain(sc); err != nil {
		return fmt.Errorf("failed to finalize state on-chain: %v", err)
	}

	return nil
}

// generateChannelID generates a unique ID for the state channel
func generateChannelID(participants []string) string {
	hash := sha256.New()
	for _, participant := range participants {
		hash.Write([]byte(participant))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// verifySignature verifies the signature of the state update
func verifySignature(state string, signature string, participants []string) bool {
	// Simplified signature verification, should be replaced with proper cryptographic verification
	return signature == generateSignature(state, participants)
}

// generateSignature generates a signature for the state update
func generateSignature(state string, participants []string) string {
	// Simplified signature generation, should be replaced with proper cryptographic signing
	hash := sha256.New()
	hash.Write([]byte(state))
	for _, participant := range participants {
		hash.Write([]byte(participant))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// finalizeStateOnChain finalizes the state on the blockchain
func finalizeStateOnChain(sc *StateChannel) error {
	// Simulate on-chain finalization with a command, replace with actual blockchain interaction
	cmd := exec.Command("finalize_state", sc.ID, sc.State, fmt.Sprintf("%d", sc.Nonce), sc.Signature)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to finalize state on-chain: %v", err)
	}

	return nil
}

// SolidityCompatibility provides functions to ensure compatibility with Solidity smart contracts
type SolidityCompatibility struct{}

// CompileSolidity compiles Solidity code
func (s *SolidityCompatibility) CompileSolidity(code string) (*CompilerOutput, error) {
	cmd := exec.Command("solc", "--bin", "--abi", "--optimize", "--combined-json", "bin,abi,srcmap", "-")
	cmd.Stdin = strings.NewReader(code)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("failed to compile Solidity code: %v", err)
	}

	output, err := parseSolcOutput(out.String())
	if err != nil {
		return nil, err
	}
	output.Compiler = Solidity
	output.CompilerVer = getSolcVersion()
	return output, nil
}

// parseSolcOutput parses the output from the Solidity compiler
func parseSolcOutput(output string) (*CompilerOutput, error) {
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		return nil, fmt.Errorf("failed to parse solc output: %v", err)
	}

	contracts := result["contracts"].(map[string]interface{})
	compiledContract := contracts["<stdin>:MyContract"].(map[string]interface{})

	return &CompilerOutput{
		Bytecode:   compiledContract["bin"].(string),
		ABI:        compiledContract["abi"].(string),
		SourceMap:  compiledContract["srcmap"].(string),
	}, nil
}

// getSolcVersion returns the version of solc compiler
func getSolcVersion() string {
	cmd := exec.Command("solc", "--version")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(out.String())
}
