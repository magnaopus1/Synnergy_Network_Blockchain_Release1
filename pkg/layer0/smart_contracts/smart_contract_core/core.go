package smart_contract_core

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil/base58"
	"github.com/dgraph-io/badger"
)

// SmartContract represents a basic structure for smart contracts
type SmartContract struct {
	Address        string
	Code           string
	Parameters     map[string]interface{}
	DeploymentTime time.Time
}

// ContractDB is a wrapper around a BadgerDB instance for storing smart contracts
type ContractDB struct {
	db *badger.DB
}

// NewContractDB creates a new instance of ContractDB
func NewContractDB(dir string) (*ContractDB, error) {
	opts := badger.DefaultOptions(dir)
	opts.Logger = nil
	db, err := badger.Open(opts)
	if err != nil {
		return nil, err
	}
	return &ContractDB{db: db}, nil
}

// Close closes the BadgerDB instance
func (cdb *ContractDB) Close() error {
	return cdb.db.Close()
}

// SaveContract saves a smart contract to the database
func (cdb *ContractDB) SaveContract(contract *SmartContract) error {
	return cdb.db.Update(func(txn *badger.Txn) error {
		data, err := json.Marshal(contract)
		if err != nil {
			return err
		}
		return txn.Set([]byte(contract.Address), data)
	})
}

// GetContract retrieves a smart contract from the database
func (cdb *ContractDB) GetContract(address string) (*SmartContract, error) {
	var contract SmartContract
	err := cdb.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(address))
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &contract)
		})
	})
	return &contract, err
}

// CreateSmartContract creates a new smart contract instance
func CreateSmartContract(code string, parameters map[string]interface{}) (*SmartContract, error) {
	contract := &SmartContract{
		Code:           code,
		Parameters:     parameters,
		DeploymentTime: time.Now(),
	}
	address, err := generateContractAddress(code)
	if err != nil {
		return nil, err
	}
	contract.Address = address
	return contract, nil
}

// DeploySmartContract deploys the smart contract to the blockchain
func DeploySmartContract(contract *SmartContract, cdb *ContractDB) (string, error) {
	err := cdb.SaveContract(contract)
	if err != nil {
		return "", err
	}
	txHash := sha256.New()
	txHash.Write([]byte(contract.Address + contract.Code + fmt.Sprint(contract.Parameters)))
	return hex.EncodeToString(txHash.Sum(nil)), nil
}

// CallSmartContractFunction simulates calling a function on the smart contract
func CallSmartContractFunction(contract *SmartContract, functionName string, args ...interface{}) (interface{}, error) {
	// Placeholder for actual smart contract function call logic
	return fmt.Sprintf("Called %s on contract %s with args %v", functionName, contract.Address, args), nil
}

// SignSmartContractData signs the smart contract data using a private key
func SignSmartContractData(privateKey *ecdsa.PrivateKey, data []byte) (string, error) {
	hash := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return "", err
	}
	signature := append(r.Bytes(), s.Bytes()...)
	return base58.Encode(signature), nil
}

// VerifySmartContractSignature verifies the signature of the smart contract data
func VerifySmartContractSignature(publicKey *ecdsa.PublicKey, data []byte, signature string) (bool, error) {
	hash := sha256.Sum256(data)
	decodedSignature := base58.Decode(signature)
	r := big.NewInt(0).SetBytes(decodedSignature[:32])
	s := big.NewInt(0).SetBytes(decodedSignature[32:])
	return ecdsa.Verify(publicKey, hash[:], r, s), nil
}

// EncryptAndSaveSmartContract encrypts and saves the smart contract to a file
func EncryptAndSaveSmartContract(contract *SmartContract, filename, passphrase string) error {
	data, err := json.Marshal(contract)
	if err != nil {
		return fmt.Errorf("error marshalling contract: %v", err)
	}

	encryptedData, err := EncryptData(data, passphrase)
	if err != nil {
		return fmt.Errorf("error encrypting contract: %v", err)
	}

	if err := os.WriteFile(filename, encryptedData, 0644); err != nil {
		return fmt.Errorf("error writing file: %v", err)
	}

	return nil
}

// LoadAndDecryptSmartContract loads and decrypts the smart contract from a file
func LoadAndDecryptSmartContract(filename, passphrase string) (*SmartContract, error) {
	encryptedData, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %v", err)
	}

	data, err := DecryptData(encryptedData, passphrase)
	if err != nil {
		return nil, fmt.Errorf("error decrypting contract: %v", err)
	}

	var contract SmartContract
	if err := json.Unmarshal(data, &contract); err != nil {
		return nil, fmt.Errorf("error unmarshalling contract: %v", err)
	}

	return &contract, nil
}

// Helper function to generate a contract address based on its code
func generateContractAddress(code string) (string, error) {
	hash := sha256.New()
	_, err := hash.Write([]byte(code))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// EncryptData encrypts data using AES with a passphrase
func EncryptData(data []byte, passphrase string) ([]byte, error) {
	// Placeholder for actual AES encryption logic
	return data, nil
}

// DecryptData decrypts data using AES with a passphrase
func DecryptData(data []byte, passphrase string) ([]byte, error) {
	// Placeholder for actual AES decryption logic
	return data, nil
}

func main() {
	// Example usage
	code := `
	pragma solidity ^0.8.0;
	contract Example {
		string public name;
		constructor(string memory _name) {
			name = _name;
		}
	}`

	parameters := map[string]interface{}{
		"name": "ExampleContract",
	}

	contract, err := CreateSmartContract(code, parameters)
	if err != nil {
		log.Fatalf("Error creating smart contract: %v", err)
	}

	dbDir := "./contractdb"
	cdb, err := NewContractDB(dbDir)
	if err != nil {
		log.Fatalf("Error creating contract DB: %v", err)
	}
	defer cdb.Close()

	txHash, err := DeploySmartContract(contract, cdb)
	if err != nil {
		log.Fatalf("Error deploying smart contract: %v", err)
	}

	fmt.Printf("Smart contract deployed with transaction hash: %s\n", txHash)

	result, err := CallSmartContractFunction(contract, "setName", "NewName")
	if err != nil {
		log.Fatalf("Error calling smart contract function: %v", err)
	}

	fmt.Printf("Smart contract function call result: %v\n", result)

	privateKey, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		log.Fatalf("Error generating private key: %v", err)
	}

	dataToSign := []byte("Sample data to sign")
	signature, err := SignSmartContractData(privateKey.ToECDSA(), dataToSign)
	if err != nil {
		log.Fatalf("Error signing data: %v", err)
	}

	fmt.Printf("Data signed successfully: %s\n", signature)

	publicKey := privateKey.PubKey().ToECDSA()
	isValid, err := VerifySmartContractSignature(publicKey, dataToSign, signature)
	if err != nil {
		log.Fatalf("Error verifying signature: %v", err)
	}

	fmt.Printf("Signature verification result: %v\n", isValid)

	filename := "smart_contract.json.enc"
	passphrase := "securepassword"
	if err := EncryptAndSaveSmartContract(contract, filename, passphrase); err != nil {
		log.Fatalf("Error encrypting and saving contract: %v", err)
	}

	loadedContract, err := LoadAndDecryptSmartContract(filename, passphrase)
	if err != nil {
		log.Fatalf("Error loading and decrypting contract: %v", err)
	}

	fmt.Printf("Loaded contract: %+v\n", loadedContract)
}
