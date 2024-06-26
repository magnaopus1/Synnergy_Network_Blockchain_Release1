package contract_interactions

import (
	"github.com/ethereum/go-ethereum/common"
	"math/big"
)

// ContractRead is a struct for reading data from smart contracts.
type ContractRead struct {
	contractAddress common.Address
	abiJSON         string
	interactions    *ContractInteractions
}

// NewContractRead initializes a new instance of ContractRead for reading contract data.
func NewContractRead(contractAddress common.Address, abiJSON string, interactions *ContractInteractions) *ContractRead {
	return &ContractRead{
		contractAddress: contractAddress,
		abiJSON:         abiJSON,
		interactions:    interactions,
	}
}

// GetTotalSupply returns the total supply of the token.
func (cr *ContractRead) GetTotalSupply() (*big.Int, error) {
	methodName := "totalSupply" // Replace with the actual method name from your contract's ABI.
	result, err := cr.interactions.CallContractConstantMethod(cr.contractAddress, cr.abiJSON, methodName)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// GetBalanceOf returns the balance of a specific address.
func (cr *ContractRead) GetBalanceOf(address common.Address) (*big.Int, error) {
	methodName := "balanceOf" // Replace with the actual method name from your contract's ABI.
	result, err := cr.interactions.CallContractConstantMethod(cr.contractAddress, cr.abiJSON, methodName, address)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Implement other contract read functions as needed.
