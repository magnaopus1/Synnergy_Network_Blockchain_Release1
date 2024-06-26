package smart_contracts

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/synthron_blockchain_final/pkg/layer0/green_technology/energy_usage_monitoring"
	"github.com/synthron_blockchain_final/pkg/utils"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// EnergyData represents the structure of energy consumption data.
type EnergyData struct {
	NodeID      string    `json:"node_id"`
	Timestamp   time.Time `json:"timestamp"`
	Usage       float64   `json:"usage"`
	Temperature float64   `json:"temperature"`
	Humidity    float64   `json:"humidity"`
}

// SmartContract provides functions for managing energy data.
type SmartContract struct {
	contractapi.Contract
}

// InitLedger adds a base set of energy data to the ledger.
func (s *SmartContract) InitLedger(ctx contractapi.TransactionContextInterface) error {
	energyData := []EnergyData{
		{NodeID: "node1", Timestamp: time.Now(), Usage: 100.5, Temperature: 25.0, Humidity: 50.0},
		{NodeID: "node2", Timestamp: time.Now(), Usage: 200.0, Temperature: 24.0, Humidity: 55.0},
	}

	for _, data := range energyData {
		dataJSON, err := json.Marshal(data)
		if err != nil {
			return err
		}

		err = ctx.GetStub().PutState(data.NodeID, dataJSON)
		if err != nil {
			return fmt.Errorf("failed to put data to world state: %v", err)
		}
	}

	return nil
}

// AddEnergyData adds new energy data to the ledger.
func (s *SmartContract) AddEnergyData(ctx contractapi.TransactionContextInterface, nodeID string, timestamp time.Time, usage, temperature, humidity float64) error {
	data := EnergyData{
		NodeID:      nodeID,
		Timestamp:   timestamp,
		Usage:       usage,
		Temperature: temperature,
		Humidity:    humidity,
	}

	dataJSON, err := json.Marshal(data)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(nodeID, dataJSON)
}

// GetEnergyData retrieves energy data from the ledger.
func (s *SmartContract) GetEnergyData(ctx contractapi.TransactionContextInterface, nodeID string) (*EnergyData, error) {
	dataJSON, err := ctx.GetStub().GetState(nodeID)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if dataJSON == nil {
		return nil, fmt.Errorf("the data %s does not exist", nodeID)
	}

	var data EnergyData
	err = json.Unmarshal(dataJSON, &data)
	if err != nil {
		return nil, err
	}

	return &data, nil
}

// GetAllEnergyData returns all energy data stored in the ledger.
func (s *SmartContract) GetAllEnergyData(ctx contractapi.TransactionContextInterface) ([]*EnergyData, error) {
	queryString := `{"selector":{}}`
	resultsIterator, err := ctx.GetStub().GetQueryResult(queryString)
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var results []*EnergyData
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		var data EnergyData
		err = json.Unmarshal(queryResponse.Value, &data)
		if err != nil {
			return nil, err
		}
		results = append(results, &data)
	}

	return results, nil
}

// UpdateEnergyData updates an existing energy data record in the ledger.
func (s *SmartContract) UpdateEnergyData(ctx contractapi.TransactionContextInterface, nodeID string, timestamp time.Time, usage, temperature, humidity float64) error {
	exists, err := s.EnergyDataExists(ctx, nodeID)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("the energy data %s does not exist", nodeID)
	}

	data := EnergyData{
		NodeID:      nodeID,
		Timestamp:   timestamp,
		Usage:       usage,
		Temperature: temperature,
		Humidity:    humidity,
	}

	dataJSON, err := json.Marshal(data)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(nodeID, dataJSON)
}

// DeleteEnergyData deletes an energy data record from the ledger.
func (s *SmartContract) DeleteEnergyData(ctx contractapi.TransactionContextInterface, nodeID string) error {
	exists, err := s.EnergyDataExists(ctx, nodeID)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("the energy data %s does not exist", nodeID)
	}

	return ctx.GetStub().DelState(nodeID)
}

// EnergyDataExists checks if an energy data record exists in the ledger.
func (s *SmartContract) EnergyDataExists(ctx contractapi.TransactionContextInterface, nodeID string) (bool, error) {
	dataJSON, err := ctx.GetStub().GetState(nodeID)
	if err != nil {
		return false, fmt.Errorf("failed to read from world state: %v", err)
	}

	return dataJSON != nil, nil
}

// GetHistoryForEnergyData returns the history of changes for a specific energy data record.
func (s *SmartContract) GetHistoryForEnergyData(ctx contractapi.TransactionContextInterface, nodeID string) ([]*EnergyData, error) {
	resultsIterator, err := ctx.GetStub().GetHistoryForKey(nodeID)
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var results []*EnergyData
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		var data EnergyData
		err = json.Unmarshal(queryResponse.Value, &data)
		if err != nil {
			return nil, err
		}
		results = append(results, &data)
	}

	return results, nil
}

func main() {
	chaincode, err := contractapi.NewChaincode(new(SmartContract))
	if err != nil {
		fmt.Printf("Error creating energy data management chaincode: %v", err)
		return
	}

	if err := chaincode.Start(); err != nil {
		fmt.Printf("Error starting energy data management chaincode: %v", err)
	}
}
