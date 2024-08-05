package trading

import (
	"errors"
	"sync"
	"time"
)

// Resource represents a single computing resource in the marketplace
type Resource struct {
	ID          string
	Name        string
	Description string
	Price       float64
	OwnerID     string
	Available   bool
}

// Bundle represents a bundle of resources
type Bundle struct {
	ID        string
	Name      string
	Resources []Resource
	Price     float64
	OwnerID   string
	CreatedAt time.Time
	Active    bool
}

// ResourceBundlingPackagingManager manages the bundling and packaging of resources for trading
type ResourceBundlingPackagingManager struct {
	mu       sync.Mutex
	resources map[string]Resource
	bundles   map[string]Bundle
}

// NewResourceBundlingPackagingManager initializes a new ResourceBundlingPackagingManager
func NewResourceBundlingPackagingManager() *ResourceBundlingPackagingManager {
	return &ResourceBundlingPackagingManager{
		resources: make(map[string]Resource),
		bundles:   make(map[string]Bundle),
	}
}

// AddResource adds a new resource to the marketplace
func (rbpm *ResourceBundlingPackagingManager) AddResource(id, name, description, ownerID string, price float64) error {
	rbpm.mu.Lock()
	defer rbpm.mu.Unlock()

	if _, exists := rbpm.resources[id]; exists {
		return errors.New("resource with this ID already exists")
	}

	resource := Resource{
		ID:          id,
		Name:        name,
		Description: description,
		Price:       price,
		OwnerID:     ownerID,
		Available:   true,
	}

	rbpm.resources[id] = resource
	return nil
}

// RemoveResource removes a resource from the marketplace
func (rbpm *ResourceBundlingPackagingManager) RemoveResource(id string) error {
	rbpm.mu.Lock()
	defer rbpm.mu.Unlock()

	if _, exists := rbpm.resources[id]; !exists {
		return errors.New("resource not found")
	}

	delete(rbpm.resources, id)
	return nil
}

// CreateBundle creates a new resource bundle
func (rbpm *ResourceBundlingPackagingManager) CreateBundle(id, name, ownerID string, resourceIDs []string, price float64) error {
	rbpm.mu.Lock()
	defer rbpm.mu.Unlock()

	if _, exists := rbpm.bundles[id]; exists {
		return errors.New("bundle with this ID already exists")
	}

	var resources []Resource
	for _, resID := range resourceIDs {
		resource, exists := rbpm.resources[resID]
		if !exists {
			return errors.New("one or more resources not found")
		}
		resources = append(resources, resource)
	}

	bundle := Bundle{
		ID:        id,
		Name:      name,
		Resources: resources,
		Price:     price,
		OwnerID:   ownerID,
		CreatedAt: time.Now(),
		Active:    true,
	}

	rbpm.bundles[id] = bundle
	return nil
}

// RemoveBundle removes a bundle from the marketplace
func (rbpm *ResourceBundlingPackagingManager) RemoveBundle(id string) error {
	rbpm.mu.Lock()
	defer rbpm.mu.Unlock()

	if _, exists := rbpm.bundles[id]; !exists {
		return errors.New("bundle not found")
	}

	delete(rbpm.bundles, id)
	return nil
}

// GetBundle retrieves the details of a bundle
func (rbpm *ResourceBundlingPackagingManager) GetBundle(id string) (Bundle, error) {
	rbpm.mu.Lock()
	defer rbpm.mu.Unlock()

	bundle, exists := rbpm.bundles[id]
	if !exists {
		return Bundle{}, errors.New("bundle not found")
	}

	return bundle, nil
}

// ListActiveBundles lists all active bundles
func (rbpm *ResourceBundlingPackagingManager) ListActiveBundles() []Bundle {
	rbpm.mu.Lock()
	defer rbpm.mu.Unlock()

	var activeBundles []Bundle
	for _, bundle := range rbpm.bundles {
		if bundle.Active {
			activeBundles = append(activeBundles, bundle)
		}
	}
	return activeBundles
}

// PurchaseBundle handles the purchase of a bundle
func (rbpm *ResourceBundlingPackagingManager) PurchaseBundle(bundleID, buyerID string) error {
	rbpm.mu.Lock()
	defer rbpm.mu.Unlock()

	bundle, exists := rbpm.bundles[bundleID]
	if !exists {
		return errors.New("bundle not found")
	}

	if !bundle.Active {
		return errors.New("bundle is not active")
	}

	// Perform the purchase logic, e.g., transferring ownership and processing payment
	bundle.Active = false
	rbpm.bundles[bundleID] = bundle

	return nil
}

// generateID generates a unique ID for resources and bundles
func generateID(parts ...interface{}) string {
	var input string
	for _, part := range parts {
		input += part.(string)
	}
	return hex.EncodeToString(argon2.IDKey([]byte(input), []byte("somesalt"), 1, 64*1024, 4, 32))
}
