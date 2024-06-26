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
	cmd := exec.Command("solc", "--bin", "--abi", "--optimize", "--strict-assembly", "-")
	cmd.Stdin = strings.NewReader(code)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("failed to compile YUL code: %v", err)
	}

	output, err := parseYulOutput(out.String())
	if err != nil {
		return nil, err
	}
	output.Compiler = YUL
	output.CompilerVer = getSolcVersion() // YUL uses solc as well
	return output, nil
}

// compileRust compiles Rust code
func compileRust(code string) (*CompilerOutput, error) {
	// Assume we have a custom Rust compiler for smart contracts
	cmd := exec.Command("rustc", "--emit=llvm-bc", "-o", "contract.bc", "-")
	cmd.Stdin = strings.NewReader(code)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("failed to compile Rust code: %v", err)
	}

	output := &CompilerOutput{
		Bytecode:   out.String(),
		Compiler:   Rust,
		CompilerVer: getRustVersion(),
	}
	return output, nil
}

// parseSolcOutput parses the output from the Solidity compiler
func parseSolcOutput(output string) (*CompilerOutput, error) {
	// Simplified example of parsing JSON output
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

// parseVyperOutput parses the output from the Vyper compiler
func parseVyperOutput(output string) (*CompilerOutput, error) {
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		return nil, fmt.Errorf("failed to parse vyper output: %v", err)
	}

	return &CompilerOutput{
		Bytecode:  result["bytecode"].(string),
		ABI:       result["abi"].(string),
		SourceMap: result["source_map"].(string),
	}, nil
}

// parseYulOutput parses the output from the YUL compiler
func parseYulOutput(output string) (*CompilerOutput, error) {
	// Similar to parseSolcOutput, parsing output of YUL compilation
	// Assume similar structure for the purpose of this example
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		return nil, fmt.Errorf("failed to parse yul output: %v", err)
	}

	contracts := result["contracts"].(map[string]interface{})
	compiledContract := contracts["<stdin>:MyContract"].(map[string]interface{})

	return &CompilerOutput{
		Bytecode:  compiledContract["bin"].(string),
		ABI:       compiledContract["abi"].(string),
		SourceMap: compiledContract["srcmap"].(string),
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

// getVyperVersion returns the version of vyper compiler
func getVyperVersion() string {
	cmd := exec.Command("vyper", "--version")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(out.String())
}

// getRustVersion returns the version of rust compiler
func getRustVersion() string {
	cmd := exec.Command("rustc", "--version")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(out.String())
}
