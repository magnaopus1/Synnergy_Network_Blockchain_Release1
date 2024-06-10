package behavioural_incentives

import (
	"fmt"
	"time"
	"sync"
)

// UserBehavior tracks user activities for incentive calculations
type UserBehavior struct {
	UserID    string
	Actions   map[string]int
	LastActive time.Time
}

// BehavioralIncentives handles incentive strategies based on user behavior
type BehavioralIncentives struct {
	Users  map[string]*UserBehavior
	mu     sync.Mutex
}

// NewBehavioralIncentives initializes a new BehavioralIncentives instance
func NewBehavioralIncentives() *BehavioralIncentives {
	return &BehavioralIncentives{
		Users: make(map[string]*UserBehavior),
	}
}

// RecordAction records a user action for behavioral incentives
func (bi *BehavioralIncentives) RecordAction(userID, action string) {
	bi.mu.Lock()
	defer bi.mu.Unlock()

	user, exists := bi.Users[userID]
	if !exists {
		user = &UserBehavior{
			UserID:    userID,
			Actions:   make(map[string]int),
			LastActive: time.Now(),
		}
		bi.Users[userID] = user
	}

	user.Actions[action]++
	user.LastActive = time.Now()
}

// CalculateIncentives calculates and distributes incentives based on user behavior
func (bi *BehavioralIncentives) CalculateIncentives() {
	bi.mu.Lock()
	defer bi.mu.Unlock()

	for _, user := range bi.Users {
		incentive := bi.calculateUserIncentive(user)
		bi.distributeIncentive(user.UserID, incentive)
	}
}

// calculateUserIncentive calculates the incentive for a single user based on their actions
func (bi *BehavioralIncentives) calculateUserIncentive(user *UserBehavior) float64 {
	// Example calculation: Each action type contributes a different incentive value
	// More sophisticated models could be implemented as needed
	incentive := 0.0
	for action, count := range user.Actions {
		switch action {
		case "transaction":
			incentive += float64(count) * 0.01 // 0.01 tokens per transaction
		case "stake":
			incentive += float64(count) * 0.05 // 0.05 tokens per staking action
		case "vote":
			incentive += float64(count) * 0.02 // 0.02 tokens per governance vote
		}
	}
	return incentive
}

// distributeIncentive distributes the calculated incentive to the user
func (bi *BehavioralIncentives) distributeIncentive(userID string, incentive float64) {
	// In a real-world scenario, this would involve updating the user's balance on the blockchain
	fmt.Printf("Distributing %.2f tokens to user %s\n", incentive, userID)
}

// DisplayUserActions prints the recorded actions of all users
func (bi *BehavioralIncentives) DisplayUserActions() {
	bi.mu.Lock()
	defer bi.mu.Unlock()

	for userID, user := range bi.Users {
		fmt.Printf("UserID: %s, Actions: %v, LastActive: %s\n", userID, user.Actions, user.LastActive)
	}
}

// StartIncentiveCalculationRoutine starts a routine to periodically calculate and distribute incentives
func (bi *BehavioralIncentives) StartIncentiveCalculationRoutine(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			bi.CalculateIncentives()
		}
	}()
}

func main() {
	bi := NewBehavioralIncentives()
	bi.RecordAction("user1", "transaction")
	bi.RecordAction("user1", "stake")
	bi.RecordAction("user2", "vote")
	bi.RecordAction("user2", "transaction")

	bi.DisplayUserActions()
	bi.CalculateIncentives()
	bi.StartIncentiveCalculationRoutine(24 * time.Hour)
}
