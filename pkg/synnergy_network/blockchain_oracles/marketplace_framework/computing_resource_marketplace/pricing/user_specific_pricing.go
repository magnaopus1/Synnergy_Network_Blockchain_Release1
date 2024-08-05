package pricing

import (
	"errors"
	"sync"
	"time"
)

// User represents a user in the system
type User struct {
	ID       string
	Profile  UserProfile
	Purchase []PurchaseHistory
}

// UserProfile represents the profile of a user
type UserProfile struct {
	Location  string
	Industry  string
	Tier      string
	JoinDate  time.Time
}

// PurchaseHistory represents the purchase history of a user
type PurchaseHistory struct {
	ResourceID string
	Timestamp  time.Time
	Amount     float64
}

// UserSpecificPricingManager manages user-specific pricing
type UserSpecificPricingManager struct {
	mu       sync.Mutex
	userData map[string]User
	pricing  map[string]float64
}

// NewUserSpecificPricingManager initializes a new UserSpecificPricingManager
func NewUserSpecificPricingManager() *UserSpecificPricingManager {
	return &UserSpecificPricingManager{
		userData: make(map[string]User),
		pricing:  make(map[string]float64),
	}
}

// AddUser adds a new user to the system
func (uspm *UserSpecificPricingManager) AddUser(userID string, profile UserProfile) error {
	uspm.mu.Lock()
	defer uspm.mu.Unlock()

	if _, exists := uspm.userData[userID]; exists {
		return errors.New("user already exists")
	}

	uspm.userData[userID] = User{
		ID:      userID,
		Profile: profile,
	}
	return nil
}

// UpdateUserProfile updates the profile of an existing user
func (uspm *UserSpecificPricingManager) UpdateUserProfile(userID string, profile UserProfile) error {
	uspm.mu.Lock()
	defer uspm.mu.Unlock()

	user, exists := uspm.userData[userID]
	if !exists {
		return errors.New("user not found")
	}

	user.Profile = profile
	uspm.userData[userID] = user
	return nil
}

// AddPurchaseHistory adds a purchase history record for a user
func (uspm *UserSpecificPricingManager) AddPurchaseHistory(userID string, purchase PurchaseHistory) error {
	uspm.mu.Lock()
	defer uspm.mu.Unlock()

	user, exists := uspm.userData[userID]
	if !exists {
		return errors.New("user not found")
	}

	user.Purchase = append(user.Purchase, purchase)
	uspm.userData[userID] = user
	return nil
}

// GetUserProfile retrieves the profile of a user
func (uspm *UserSpecificPricingManager) GetUserProfile(userID string) (UserProfile, error) {
	uspm.mu.Lock()
	defer uspm.mu.Unlock()

	user, exists := uspm.userData[userID]
	if !exists {
		return UserProfile{}, errors.New("user not found")
	}

	return user.Profile, nil
}

// GetPurchaseHistory retrieves the purchase history of a user
func (uspm *UserSpecificPricingManager) GetPurchaseHistory(userID string) ([]PurchaseHistory, error) {
	uspm.mu.Lock()
	defer uspm.mu.Unlock()

	user, exists := uspm.userData[userID]
	if !exists {
		return nil, errors.New("user not found")
	}

	return user.Purchase, nil
}

// CalculateUserSpecificPrice calculates the specific price for a user based on their profile and purchase history
func (uspm *UserSpecificPricingManager) CalculateUserSpecificPrice(userID string, resourceID string) (float64, error) {
	uspm.mu.Lock()
	defer uspm.mu.Unlock()

	user, exists := uspm.userData[userID]
	if !exists {
		return 0, errors.New("user not found")
	}

	basePrice, exists := uspm.pricing[resourceID]
	if !exists {
		return 0, errors.New("resource not found")
	}

	// Adjust price based on user profile and purchase history
	price := basePrice
	if user.Profile.Tier == "premium" {
		price *= 0.9
	} else if user.Profile.Tier == "gold" {
		price *= 0.95
	}

	// Apply location-based discounts or surcharges
	if user.Profile.Location == "remote" {
		price *= 1.05
	}

	// Apply industry-specific adjustments
	if user.Profile.Industry == "education" {
		price *= 0.85
	} else if user.Profile.Industry == "finance" {
		price *= 1.1
	}

	// Apply discounts based on purchase history
	if len(user.Purchase) > 10 {
		price *= 0.9
	}

	return price, nil
}

// SetBasePrice sets the base price for a resource
func (uspm *UserSpecificPricingManager) SetBasePrice(resourceID string, price float64) {
	uspm.mu.Lock()
	defer uspm.mu.Unlock()
	uspm.pricing[resourceID] = price
}

// GetBasePrice retrieves the base price for a resource
func (uspm *UserSpecificPricingManager) GetBasePrice(resourceID string) (float64, error) {
	uspm.mu.Lock()
	defer uspm.mu.Unlock()

	price, exists := uspm.pricing[resourceID]
	if !exists {
		return 0, errors.New("resource not found")
	}

	return price, nil
}
