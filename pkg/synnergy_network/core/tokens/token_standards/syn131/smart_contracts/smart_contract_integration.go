package smart_contracts

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn131/assets"
	"golang.org/x/crypto/scrypt"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

// Syn131SmartContract represents a comprehensive smart contract for SYN131 token standard
type Syn131SmartContract struct {
	ID                             string                  `json:"id"`
	Owner                          string                  `json:"owner"`
	IntangibleAssetID              string                  `json:"asset_id"`
	ContractType                   string                  `json:"contract_type"`
	Terms                          string                  `json:"terms"`
	EncryptedTerms                 string                  `json:"encrypted_terms"`
	EncryptionKey                  string                  `json:"encryption_key"`
	Status                         string                  `json:"status"`
	IntangibleAssetCategory        string                  `json:"asset_category"`
	IntangibleAssetClassification  string                  `json:"asset_classification"`
	IntangibleAssetMetadata        assets.AssetMetadata    `json:"asset_metadata"`
	PeggedTangibleAsset            assets.PeggedAsset      `json:"pegged_asset"`
	TrackedTangibleAsset           assets.TrackedAsset     `json:"tracked_asset"`
	IntangibleAssetStatus          assets.AssetStatus      `json:"asset_status"`
	IntangibleAssetValuation       assets.AssetValuation   `json:"asset_valuation"`
	IoTDevice                      assets.IoTDevice        `json:"iot_device"`
	LeaseAgreement                 LeaseAgreement          `json:"lease_agreement"`
	CoOwnershipAgreements          []CoOwnershipAgreement  `json:"co_ownership_agreements"`
	LicenseAgreement               LicenseAgreement        `json:"license_agreement"`
	RentalAgreement                RentalAgreement         `json:"rental_agreement"`
}

// LeaseAgreement represents a lease agreement within a smart contract
type LeaseAgreement struct {
	LeaseTerm  string `json:"lease_term"`
	RentAmount int    `json:"rent_amount"`
}

// CoOwnershipAgreement represents a co-ownership agreement within a smart contract
type CoOwnershipAgreement struct {
	CoOwners       []string `json:"co_owners"`
	OwnershipRatio []int    `json:"ownership_ratio"`
}

// LicenseAgreement represents a license agreement within a smart contract
type LicenseAgreement struct {
	Licensee   string `json:"licensee"`
	LicenseFee int    `json:"license_fee"`
	Duration   string `json:"duration"`
}

// RentalAgreement represents a rental agreement within a smart contract
type RentalAgreement struct {
	Renter       string `json:"renter"`
	RentAmount   int    `json:"rent_amount"`
	RentalPeriod string `json:"rental_period"`
}

// EncryptData encrypts the given data using AES
func EncryptData(data, passphrase string) (string, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return fmt.Sprintf("%x", append(salt, ciphertext...)), nil
}

// DecryptData decrypts the given encrypted data using AES
func DecryptData(encryptedData, passphrase string) (string, error) {
	data, err := hex.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}

	salt := data[:16]
	ciphertext := data[16:]

	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// Validate validates the smart contract fields
func (contract *Syn131SmartContract) Validate() error {
	if contract.ID == "" || contract.Owner == "" || contract.IntangibleAssetID == "" || contract.ContractType == "" {
		return errors.New("missing required fields")
	}

	if len(contract.CoOwnershipAgreements) > 0 {
		totalRatio := 0
		for _, coOwner := range contract.CoOwnershipAgreements {
			for _, ratio := range coOwner.OwnershipRatio {
				totalRatio += ratio
			}
		}
		if totalRatio != 100 {
			return errors.New("ownership ratios must add up to 100%")
		}
	}

	return nil
}

// SignContract signs the smart contract using the owner's key
func (contract *Syn131SmartContract) SignContract(ownerKey string) error {
	if contract.Status != "draft" {
		return errors.New("contract is not in draft status")
	}

	encryptedTerms, err := EncryptData(contract.Terms, ownerKey)
	if err != nil {
		return err
	}
	contract.EncryptedTerms = encryptedTerms
	contract.Status = "signed"
	return nil
}

// ExecuteContract executes the smart contract
func (contract *Syn131SmartContract) ExecuteContract() error {
	if contract.Status != "signed" {
		return errors.New("contract is not signed")
	}

	contract.Status = "executed"
	return nil
}

// TerminateContract terminates the smart contract
func (contract *Syn131SmartContract) TerminateContract() error {
	if contract.Status != "executed" {
		return errors.New("contract is not executed")
	}

	contract.Status = "terminated"
	return nil
}

// ContractTemplate defines the structure for a smart contract template
type ContractTemplate struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Description  string                 `json:"description"`
	Version      string                 `json:"version"`
	Code         string                 `json:"code"`
	Parameters   map[string]interface{} `json:"parameters"`
	CreatedAt    time.Time              `json:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at"`
	Owner        string                 `json:"owner"`
	Dependencies []string               `json:"dependencies"`
}

// ContractTemplateRepository defines the interface for managing contract templates
type ContractTemplateRepository interface {
	Create(template *ContractTemplate) error
	Update(template *ContractTemplate) error
	GetByID(id string) (*ContractTemplate, error)
	GetAll() ([]*ContractTemplate, error)
	Delete(id string) error
}

// InMemoryContractTemplateRepository is an in-memory implementation of ContractTemplateRepository
type InMemoryContractTemplateRepository struct {
	templates map[string]*ContractTemplate
}

// NewInMemoryContractTemplateRepository creates a new instance of InMemoryContractTemplateRepository
func NewInMemoryContractTemplateRepository() *InMemoryContractTemplateRepository {
	return &InMemoryContractTemplateRepository{
		templates: make(map[string]*ContractTemplate),
	}
}

// Create adds a new contract template to the repository
func (repo *InMemoryContractTemplateRepository) Create(template *ContractTemplate) error {
	if _, exists := repo.templates[template.ID]; exists {
		return errors.New("template with this ID already exists")
	}
	template.CreatedAt = time.Now()
	template.UpdatedAt = time.Now()
	repo.templates[template.ID] = template
	return nil
}

// Update updates an existing contract template in the repository
func (repo *InMemoryContractTemplateRepository) Update(template *ContractTemplate) error {
	if _, exists := repo.templates[template.ID]; !exists {
		return errors.New("template not found")
	}
	template.UpdatedAt = time.Now()
	repo.templates[template.ID] = template
	return nil
}

// GetByID retrieves a contract template by its ID
func (repo *InMemoryContractTemplateRepository) GetByID(id string) (*ContractTemplate, error) {
	template, exists := repo.templates[id]
	if !exists {
		return nil, errors.New("template not found")
	}
	return template, nil
}

// GetAll retrieves all contract templates
func (repo *InMemoryContractTemplateRepository) GetAll() ([]*ContractTemplate, error) {
	var templates []*ContractTemplate
	for _, template := range repo.templates {
		templates = append(templates, template)
	}
	return templates, nil
}

// Delete removes a contract template from the repository
func (repo *InMemoryContractTemplateRepository) Delete(id string) error {
	if _, exists := repo.templates[id]; !exists {
		return errors.New("template not found")
	}
	delete(repo.templates, id)
	return nil
}

// ContractTemplateService defines the methods for interacting with contract templates
type ContractTemplateService struct {
	repo ContractTemplateRepository
}

// NewContractTemplateService creates a new instance of ContractTemplateService
func NewContractTemplateService(repo ContractTemplateRepository) *ContractTemplateService {
	return &ContractTemplateService{repo: repo}
}

// CreateTemplate creates a new contract template
func (service *ContractTemplateService) CreateTemplate(template *ContractTemplate) error {
	return service.repo.Create(template)
}

// UpdateTemplate updates an existing contract template
func (service *ContractTemplateService) UpdateTemplate(template *ContractTemplate) error {
	return service.repo.Update(template)
}

// GetTemplateByID retrieves a contract template by its ID
func (service *ContractTemplateService) GetTemplateByID(id string) (*ContractTemplate, error) {
	return service.repo.GetByID(id)
}

// GetAllTemplates retrieves all contract templates
func (service *ContractTemplateService) GetAllTemplates() ([]*ContractTemplate, error) {
	return service.repo.GetAll()
}

// DeleteTemplate deletes a contract template by its ID
func (service *ContractTemplateService) DeleteTemplate(id string) error {
	return service.repo.Delete(id)
}
// Syn131SmartContractManager manages SYN131 smart contracts
type Syn131SmartContractManager struct {
	contracts map[string]*Syn131SmartContract
}

// NewSyn131SmartContractManager creates a new instance of Syn131SmartContractManager
func NewSyn131SmartContractManager() *Syn131SmartContractManager {
	return &Syn131SmartContractManager{
		contracts: make(map[string]*Syn131SmartContract),
	}
}

// CreateContract creates a new SYN131 smart contract
func (manager *Syn131SmartContractManager) CreateContract(contract *Syn131SmartContract) error {
	if _, exists := manager.contracts[contract.ID]; exists {
		return errors.New("contract with this ID already exists")
	}
	if err := contract.Validate(); err != nil {
		return err
	}
	manager.contracts[contract.ID] = contract
	return nil
}

// UpdateContract updates an existing SYN131 smart contract
func (manager *Syn131SmartContractManager) UpdateContract(contract *Syn131SmartContract) error {
	if _, exists := manager.contracts[contract.ID]; !exists {
		return errors.New("contract not found")
	}
	if err := contract.Validate(); err != nil {
		return err
	}
	manager.contracts[contract.ID] = contract
	return nil
}

// GetContractByID retrieves a SYN131 smart contract by its ID
func (manager *Syn131SmartContractManager) GetContractByID(id string) (*Syn131SmartContract, error) {
	contract, exists := manager.contracts[id]
	if !exists {
		return nil, errors.New("contract not found")
	}
	return contract, nil
}

// GetAllContracts retrieves all SYN131 smart contracts
func (manager *Syn131SmartContractManager) GetAllContracts() ([]*Syn131SmartContract, error) {
	var contracts []*Syn131SmartContract
	for _, contract := range manager.contracts {
		contracts = append(contracts, contract)
	}
	return contracts, nil
}

// DeleteContract deletes a SYN131 smart contract by its ID
func (manager *Syn131SmartContractManager) DeleteContract(id string) error {
	if _, exists := manager.contracts[id]; !exists {
		return errors.New("contract not found")
	}
	delete(manager.contracts, id)
	return nil
}

// SignContract signs the smart contract using the owner's key
func (manager *Syn131SmartContractManager) SignContract(id, ownerKey string) error {
	contract, exists := manager.contracts[id]
	if !exists {
		return errors.New("contract not found")
	}
	return contract.SignContract(ownerKey)
}

// ExecuteContract executes the smart contract
func (manager *Syn131SmartContractManager) ExecuteContract(id string) error {
	contract, exists := manager.contracts[id]
	if !exists {
		return errors.New("contract not found")
	}
	return contract.ExecuteContract()
}

// TerminateContract terminates the smart contract
func (manager *Syn131SmartContractManager) TerminateContract(id string) error {
	contract, exists := manager.contracts[id]
	if !exists {
		return errors.New("contract not found")
	}
	return contract.TerminateContract()
}

// GenerateContractID generates a unique contract ID
func GenerateContractID() string {
	return fmt.Sprintf("contract_%d", time.Now().UnixNano())
}

// CreateExampleContract demonstrates the creation of an example contract
func CreateExampleContract(manager *Syn131SmartContractManager, owner string) (*Syn131SmartContract, error) {
	contract := &Syn131SmartContract{
		ID:                             GenerateContractID(),
		Owner:                          owner,
		IntangibleAssetID:              "asset_123",
		ContractType:                   "rental",
		Terms:                          "Example rental terms",
		Status:                         "draft",
		IntangibleAssetCategory:        "digital",
		IntangibleAssetClassification:  "IP",
		IntangibleAssetMetadata:        assets.AssetMetadata{Name: "Example Asset"},
		IntangibleAssetValuation:       assets.AssetValuation{Value: 1000},
		LeaseAgreement:                 LeaseAgreement{LeaseTerm: "12 months", RentAmount: 500},
	}
	if err := manager.CreateContract(contract); err != nil {
		return nil, err
	}
	return contract, nil
}

func main() {
	manager := NewSyn131SmartContractManager()
	templateRepo := NewInMemoryContractTemplateRepository()
	templateService := NewContractTemplateService(templateRepo)

	// Create a contract template
	template := &ContractTemplate{
		ID:           "template_123",
		Name:         "Standard Rental Contract",
		Description:  "A standard template for rental contracts",
		Version:      "1.0",
		Code:         "contract code here",
		Parameters:   map[string]interface{}{"term": "12 months", "rent": 1000},
		Owner:        "admin",
		Dependencies: []string{},
	}
	if err := templateService.CreateTemplate(template); err != nil {
		fmt.Println("Error creating template:", err)
		return
	}

	// Create an example contract
	contract, err := CreateExampleContract(manager, "owner_123")
	if err != nil {
		fmt.Println("Error creating example contract:", err)
		return
	}

	// Sign the contract
	if err := manager.SignContract(contract.ID, "owner_key"); err != nil {
		fmt.Println("Error signing contract:", err)
		return
	}

	// Execute the contract
	if err := manager.ExecuteContract(contract.ID); err != nil {
		fmt.Println("Error executing contract:", err)
		return
	}

	// Terminate the contract
	if err := manager.TerminateContract(contract.ID); err != nil {
		fmt.Println("Error terminating contract:", err)
		return
	}

	fmt.Println("Contract lifecycle completed successfully")
}
