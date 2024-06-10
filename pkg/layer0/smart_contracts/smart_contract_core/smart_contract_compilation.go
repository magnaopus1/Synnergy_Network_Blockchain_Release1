package smart_contract_core

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// SupportedLanguages is an enum-like type for supported smart contract languages
type SupportedLanguages string

const (
	Solidity SupportedLanguages = "solidity"
	Vyper    SupportedLanguages = "vyper"
	YUL      SupportedLanguages = "yul"
	Rust     SupportedLanguages = "rust"
)

// CompilerOutput represents the output of the compilation process
type CompilerOutput struct {
	Bytecode    string
	ABI         string
	SourceMap   string
	Compiler    SupportedLanguages
	CompilerVer string
}

// CompileSmartContract compiles the smart contract code into bytecode and other related outputs
func CompileSmartContract(code string, lang SupportedLanguages) (*CompilerOutput, error) {
	switch lang {
	case Solidity:
		return compileSolidity(code)
	case Vyper:
		return compileVyper(code)
	case YUL:
		return compileYUL(code)
	case Rust:
		return compileRust(code)
	default:
		return nil, errors.New("unsupported smart contract language")
	}
}

// compileSolidity compiles Solidity code
func compileSolidity(code string) (*CompilerOutput, error) {
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

// compileVyper compiles Vyper code
func compileVyper(code string) (*CompilerOutput, error) {
	cmd := exec.Command("vyper", "-f", "combined_json", "-")
	cmd.Stdin = strings.NewReader(code)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("failed to compile Vyper code: %v", err)
	}

	output, err := parseVyperOutput(out.String())
	if err != nil {
		return nil, err
	}
	output.Compiler = Vyper
	output.CompilerVer = getVyperVersion()
	return output, nil
}

// compileYUL compiles YUL code
func compileYUL(code string) (*CompilerOutput, error) {
	cmd := exec.Command("solc", "--strict-assembly", "--bin", "--optimize", "-")
	cmd.Stdin = strings.NewReader(code)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("failed to compile YUL code: %v", err)
	}

	output, err := parseSolcOutput(out.String())
	if err != nil {
		return nil, err
	}
	output.Compiler = YUL
	output.CompilerVer = getSolcVersion()
	return output, nil
}

// compileRust compiles Rust code for smart contracts
func compileRust(code string) (*CompilerOutput, error) {
	// Placeholder for Rust compilation logic
	return nil, errors.New("Rust smart contract compilation not implemented")
}

// parseSolcOutput parses the output of the Solidity compiler
func parseSolcOutput(output string) (*CompilerOutput, error) {
	var result map[string]interface{}
	err := json.Unmarshal([]byte(output), &result)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Solidity compiler output: %v", err)
	}

	bytecode := result["bin"].(string)
	abi := result["abi"].(string)
	sourceMap := result["srcmap"].(string)

	return &CompilerOutput{
		Bytecode:   bytecode,
		ABI:        abi,
		SourceMap:  sourceMap,
	}, nil
}

// parseVyperOutput parses the output of the Vyper compiler
func parseVyperOutput(output string) (*CompilerOutput, error) {
	var result map[string]interface{}
	err := json.Unmarshal([]byte(output), &result)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Vyper compiler output: %v", err)
	}

	bytecode := result["bytecode"].(string)
	abi := result["abi"].(string)

	return &CompilerOutput{
		Bytecode:  bytecode,
		ABI:       abi,
		SourceMap: "",
	}, nil
}

// getSolcVersion gets the version of the installed Solidity compiler
func getSolcVersion() string {
	cmd := exec.Command("solc", "--version")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "unknown"
	}
	return parseCompilerVersion(out.String())
}

// getVyperVersion gets the version of the installed Vyper compiler
func getVyperVersion() string {
	cmd := exec.Command("vyper", "--version")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "unknown"
	}
	return parseCompilerVersion(out.String())
}

// parseCompilerVersion parses the compiler version from its output
func parseCompilerVersion(output string) string {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Version:") {
			parts := strings.Split(line, " ")
			if len(parts) > 1 {
				return parts[1]
			}
		}
	}
	return "unknown"
}
