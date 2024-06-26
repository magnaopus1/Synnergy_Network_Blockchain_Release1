package smart_contract_deployment

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

// CompilerType defines the type of compiler used for smart contracts
type CompilerType string

const (
	SolidityCompiler CompilerType = "solc"
	VyperCompiler    CompilerType = "vyper"
)

// ContractCompiler handles the compilation of smart contracts
type ContractCompiler struct {
	SourceDir     string
	OutputDir     string
	Compiler      CompilerType
	Optimization  bool
	IncludePaths  []string
}

// NewContractCompiler initializes a new ContractCompiler
func NewContractCompiler(sourceDir, outputDir string, compiler CompilerType, optimization bool, includePaths []string) *ContractCompiler {
	return &ContractCompiler{
		SourceDir:    sourceDir,
		OutputDir:    outputDir,
		Compiler:     compiler,
		Optimization: optimization,
		IncludePaths: includePaths,
	}
}

// Compile compiles the smart contracts in the source directory
func (cc *ContractCompiler) Compile() error {
	log.Printf("Starting compilation of smart contracts in %s...", cc.SourceDir)

	sourceFiles, err := filepath.Glob(filepath.Join(cc.SourceDir, "*.sol"))
	if err != nil {
		return fmt.Errorf("failed to list source files: %v", err)
	}

	if len(sourceFiles) == 0 {
		return fmt.Errorf("no source files found in directory: %s", cc.SourceDir)
	}

	for _, sourceFile := range sourceFiles {
		err := cc.compileSourceFile(sourceFile)
		if err != nil {
			return fmt.Errorf("failed to compile source file %s: %v", sourceFile, err)
		}
	}

	log.Printf("Compilation of smart contracts completed successfully.")
	return nil
}

// compileSourceFile compiles a single smart contract source file
func (cc *ContractCompiler) compileSourceFile(sourceFile string) error {
	log.Printf("Compiling source file %s...", sourceFile)

	outputFile := filepath.Join(cc.OutputDir, filepath.Base(strings.TrimSuffix(sourceFile, filepath.Ext(sourceFile)))+".bin")

	args := []string{
		"--bin",
		"--optimize",
		"--overwrite",
		"-o", cc.OutputDir,
	}

	if cc.Optimization {
		args = append(args, "--optimize")
	}

	for _, includePath := range cc.IncludePaths {
		args = append(args, "--allow-paths", includePath)
	}

	args = append(args, sourceFile)

	cmd := exec.Command(string(cc.Compiler), args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("compilation failed: %v - output: %s", err, out.String())
	}

	log.Printf("Compiled %s successfully to %s", sourceFile, outputFile)
	return nil
}

// main function for demonstration
func main() {
	sourceDir := "./contracts"
	outputDir := "./build"
	compiler := SolidityCompiler
	optimization := true
	includePaths := []string{"./libraries"}

	contractCompiler := NewContractCompiler(sourceDir, outputDir, compiler, optimization, includePaths)
	err := contractCompiler.Compile()
	if err != nil {
		log.Fatalf("Failed to compile contracts: %v", err)
	}
}
