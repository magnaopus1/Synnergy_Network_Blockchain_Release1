package analytics

import (
	"encoding/json"
	"sync"
	"time"
)

// UserActivity represents a log of user actions within the wallet application.
type UserActivity struct {
	UserID     string    `json:"userId"`
	Action     string    `json:"action"`
	Timestamp  time.Time `json:"timestamp"`
	Parameters map[string]interface{} `json:"parameters"`
}

// UserBehaviourAnalyticsService provides functionality to track and analyze user behavior.
type UserBehaviourAnalyticsService struct {
	Activities []UserActivity
	mu         sync.Mutex
}

// NewUserBehaviourAnalyticsService initializes a new service for user behavior analytics.
func NewUserBehaviourAnalyticsService() *UserBehaviourAnalyticsService {
	return &UserBehaviourAnalyticsService{
		Activities: make([]UserActivity, 0),
	}
}

// LogActivity records user activities performed within the wallet application.
func (ubas *UserBehaviourAnalyticsService) LogActivity(activity UserActivity) {
	ubas.mu.Lock()
	defer ubas.mu.Unlock()
	activity.Timestamp = time.Now()
	ubas.Activities = append(ubas.Activities, activity)
}

// GetUserActivities returns a list of activities for a specific user.
func (ubas *UserBehaviourAnalyticsService) GetUserActivities(userID string) []UserActivity {
	ubas.mu.Lock()
	defer ubas.mu.Unlock()
	var userActivities []UserActivity
	for _, activity := range ubas.Activities {
		if activity.UserID == userID {
			userActivities = append(userActivities, activity)
		}
	}
	return userActivities
}

// AnalyzePatterns identifies patterns and trends in user behavior.
func (ubas *UserBehaviourAnalyticsService) AnalyzePatterns() map[string]interface{} {
	ubas.mu.Lock()
	defer ubas.mu.Unlock()
	// Example: Analyze common actions or detect sudden changes in behavior
	patterns := make(map[string]int)
	for _, activity := range ubas.Activities {
		patterns[activity.Action]++
	}
	// Convert counts to more sophisticated analysis, if needed
	analysisResults := make(map[string]interface{})
	for action, count := range patterns {
		analysisResults[action] = map[string]interface{}{
			"count": count,
			"trends": "Increasing", // Placeholder for trend analysis
		}
	}
	return analysisResults
}

// SerializeActivities converts the activities data to JSON for reporting.
func (ubas *UserBehaviourAnalyticsService) SerializeActivities() ([]byte, error) {
	ubas.mu.Lock()
	defer ubas.mu.Unlock()
	return json.Marshal(ubas.Activities)
}
