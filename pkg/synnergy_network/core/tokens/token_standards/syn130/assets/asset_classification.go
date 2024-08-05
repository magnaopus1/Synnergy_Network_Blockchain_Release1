package assets

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/synnergy_network/core/storage"
)

// AssetCategory represents the structure of an asset category
type AssetCategory struct {
	CategoryID   string
	CategoryName string
	Description  string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// AssetClassification represents the classification of assets
type AssetClassification struct {
	Categories     map[string]AssetCategory
	CustomTypes    map[string]AssetCategory
	Mutex          sync.Mutex
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// NewAssetClassification creates a new AssetClassification instance
func NewAssetClassification() *AssetClassification {
	return &AssetClassification{
		Categories:  make(map[string]AssetCategory),
		CustomTypes: make(map[string]AssetCategory),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
}

// AddCategory adds a new category to the asset classification
func (ac *AssetClassification) AddCategory(categoryID, categoryName, description string) error {
	ac.Mutex.Lock()
	defer ac.Mutex.Unlock()

	if _, exists := ac.Categories[categoryID]; exists {
		return errors.New("category already exists")
	}

	ac.Categories[categoryID] = AssetCategory{
		CategoryID:   categoryID,
		CategoryName: categoryName,
		Description:  description,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	ac.UpdatedAt = time.Now()
	return nil
}

// UpdateCategory updates an existing category in the asset classification
func (ac *AssetClassification) UpdateCategory(categoryID, categoryName, description string) error {
	ac.Mutex.Lock()
	defer ac.Mutex.Unlock()

	category, exists := ac.Categories[categoryID]
	if !exists {
		return errors.New("category not found")
	}

	category.CategoryName = categoryName
	category.Description = description
	category.UpdatedAt = time.Now()
	ac.Categories[categoryID] = category
	ac.UpdatedAt = time.Now()
	return nil
}

// RemoveCategory removes a category from the asset classification
func (ac *AssetClassification) RemoveCategory(categoryID string) error {
	ac.Mutex.Lock()
	defer ac.Mutex.Unlock()

	if _, exists := ac.Categories[categoryID]; !exists {
		return errors.New("category not found")
	}

	delete(ac.Categories, categoryID)
	ac.UpdatedAt = time.Now()
	return nil
}

// AddCustomType adds a new custom type to the asset classification
func (ac *AssetClassification) AddCustomType(typeID, typeName, description string) error {
	ac.Mutex.Lock()
	defer ac.Mutex.Unlock()

	if _, exists := ac.CustomTypes[typeID]; exists {
		return errors.New("custom type already exists")
	}

	ac.CustomTypes[typeID] = AssetCategory{
		CategoryID:   typeID,
		CategoryName: typeName,
		Description:  description,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	ac.UpdatedAt = time.Now()
	return nil
}

// UpdateCustomType updates an existing custom type in the asset classification
func (ac *AssetClassification) UpdateCustomType(typeID, typeName, description string) error {
	ac.Mutex.Lock()
	defer ac.Mutex.Unlock()

	customType, exists := ac.CustomTypes[typeID]
	if !exists {
		return errors.New("custom type not found")
	}

	customType.CategoryName = typeName
	customType.Description = description
	customType.UpdatedAt = time.Now()
	ac.CustomTypes[typeID] = customType
	ac.UpdatedAt = time.Now()
	return nil
}

// RemoveCustomType removes a custom type from the asset classification
func (ac *AssetClassification) RemoveCustomType(typeID string) error {
	ac.Mutex.Lock()
	defer ac.Mutex.Unlock()

	if _, exists := ac.CustomTypes[typeID]; !exists {
		return errors.New("custom type not found")
	}

	delete(ac.CustomTypes, typeID)
	ac.UpdatedAt = time.Now()
	return nil
}

// SaveClassification saves the asset classification to storage
func (ac *AssetClassification) SaveClassification(storagePath string) error {
	ac.Mutex.Lock()
	defer ac.Mutex.Unlock()

	data, err := json.Marshal(ac)
	if err != nil {
		return err
	}
	return storage.Save(storagePath, data)
}

// LoadClassification loads the asset classification from storage
func LoadClassification(storagePath string) (*AssetClassification, error) {
	data, err := storage.Load(storagePath)
	if err != nil {
		return nil, err
	}
	var ac AssetClassification
	err = json.Unmarshal(data, &ac)
	if err != nil {
		return nil, err
	}
	return &ac, nil
}

// GetCategory retrieves a category by its ID
func (ac *AssetClassification) GetCategory(categoryID string) (AssetCategory, error) {
	ac.Mutex.Lock()
	defer ac.Mutex.Unlock()

	category, exists := ac.Categories[categoryID]
	if !exists {
		return AssetCategory{}, errors.New("category not found")
	}
	return category, nil
}

// GetCustomType retrieves a custom type by its ID
func (ac *AssetClassification) GetCustomType(typeID string) (AssetCategory, error) {
	ac.Mutex.Lock()
	defer ac.Mutex.Unlock()

	customType, exists := ac.CustomTypes[typeID]
	if !exists {
		return AssetCategory{}, errors.New("custom type not found")
	}
	return customType, nil
}
