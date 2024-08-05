package storage

import (
	"errors"
	"sync"

	"github.com/ipfs/go-ipfs-api"
	"github.com/synnergy_network/core/tokens/token_standards/syn130/utils"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// StorageManager manages the storage of asset metadata and transaction data.
type StorageManager struct {
	db     *gorm.DB
	ipfs   *shell.Shell
	mutex  sync.Mutex
}

// AssetMetadata represents the metadata structure for an asset.
type AssetMetadata struct {
	ID          string `gorm:"primaryKey"`
	Description string
	Image       string
	Documents   string
}

// TransactionRecord represents the structure for storing transaction data.
type TransactionRecord struct {
	ID             string `gorm:"primaryKey"`
	AssetID        string
	TransactionID  string
	Timestamp      int64
	TransactionData string
}

// NewStorageManager initializes and returns a new StorageManager.
func NewStorageManager(dbURL string, ipfsURL string) (*StorageManager, error) {
	// Initialize database connection
	db, err := gorm.Open(postgres.Open(dbURL), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	// Initialize IPFS client
	ipfs := shell.NewShell(ipfsURL)

	manager := &StorageManager{
		db:   db,
		ipfs: ipfs,
	}

	// Auto-migrate the schema
	err = db.AutoMigrate(&AssetMetadata{}, &TransactionRecord{})
	if err != nil {
		return nil, err
	}

	return manager, nil
}

// StoreMetadata stores asset metadata in IPFS and the database.
func (sm *StorageManager) StoreMetadata(assetID, description, image, documents string) (string, error) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	// Create metadata structure
	metadata := AssetMetadata{
		ID:          assetID,
		Description: description,
		Image:       image,
		Documents:   documents,
	}

	// Convert metadata to JSON
	jsonData, err := utils.ToJSON(metadata)
	if err != nil {
		return "", err
	}

	// Store metadata in IPFS
	ipfsHash, err := sm.ipfs.Add(bytes.NewReader(jsonData))
	if err != nil {
		return "", err
	}

	// Update metadata with IPFS hash
	metadata.Documents = ipfsHash

	// Store metadata in the database
	err = sm.db.Create(&metadata).Error
	if err != nil {
		return "", err
	}

	return ipfsHash, nil
}

// RetrieveMetadata retrieves asset metadata from the database and IPFS.
func (sm *StorageManager) RetrieveMetadata(assetID string) (*AssetMetadata, error) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	// Retrieve metadata from the database
	var metadata AssetMetadata
	err := sm.db.First(&metadata, "id = ?", assetID).Error
	if err != nil {
		return nil, err
	}

	// Retrieve metadata from IPFS
	ipfsData, err := sm.ipfs.Cat(metadata.Documents)
	if err != nil {
		return nil, err
	}

	// Convert JSON data back to AssetMetadata structure
	err = utils.FromJSON(ipfsData, &metadata)
	if err != nil {
		return nil, err
	}

	return &metadata, nil
}

// StoreTransaction stores transaction data in the database.
func (sm *StorageManager) StoreTransaction(assetID, transactionID string, timestamp int64, transactionData string) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	// Create transaction record structure
	record := TransactionRecord{
		ID:             utils.GenerateUUID(),
		AssetID:        assetID,
		TransactionID:  transactionID,
		Timestamp:      timestamp,
		TransactionData: transactionData,
	}

	// Store transaction record in the database
	err := sm.db.Create(&record).Error
	if err != nil {
		return err
	}

	return nil
}

// RetrieveTransaction retrieves transaction data from the database.
func (sm *StorageManager) RetrieveTransaction(transactionID string) (*TransactionRecord, error) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	// Retrieve transaction record from the database
	var record TransactionRecord
	err := sm.db.First(&record, "transaction_id = ?", transactionID).Error
	if err != nil {
		return nil, err
	}

	return &record, nil
}

// StoreFileToIPFS stores a file to IPFS and returns the hash.
func (sm *StorageManager) StoreFileToIPFS(filePath string) (string, error) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	// Open file
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// Store file in IPFS
	ipfsHash, err := sm.ipfs.Add(file)
	if err != nil {
		return "", err
	}

	return ipfsHash, nil
}

// RetrieveFileFromIPFS retrieves a file from IPFS using the hash.
func (sm *StorageManager) RetrieveFileFromIPFS(ipfsHash string) ([]byte, error) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	// Retrieve file from IPFS
	data, err := sm.ipfs.Cat(ipfsHash)
	if err != nil {
		return nil, err
	}

	return ioutil.ReadAll(data)
}
