package fraud_detection_and_risk_management

import (
	"errors"
	"log"
	"sync"
	"time"
)

// ComplianceTraining represents the structure for compliance training.
type ComplianceTraining struct {
	trainingMaterials map[string]TrainingMaterial
	userTrainings     map[string]UserTraining
	mu                sync.RWMutex
}

// TrainingMaterial represents the training material for compliance.
type TrainingMaterial struct {
	ID          string
	Title       string
	Content     string
	LastUpdated time.Time
}

// UserTraining represents a user's training record.
type UserTraining struct {
	UserID           string
	TrainingID       string
	CompletionStatus bool
	CompletionDate   time.Time
}

// NewComplianceTraining initializes and returns a new ComplianceTraining.
func NewComplianceTraining() *ComplianceTraining {
	return &ComplianceTraining{
		trainingMaterials: make(map[string]TrainingMaterial),
		userTrainings:     make(map[string]UserTraining),
	}
}

// AddTrainingMaterial adds new training material to the system.
func (ct *ComplianceTraining) AddTrainingMaterial(tm TrainingMaterial) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	ct.trainingMaterials[tm.ID] = tm
}

// UpdateTrainingMaterial updates existing training material in the system.
func (ct *ComplianceTraining) UpdateTrainingMaterial(tm TrainingMaterial) error {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if _, exists := ct.trainingMaterials[tm.ID]; !exists {
		return errors.New("training material not found")
	}
	ct.trainingMaterials[tm.ID] = tm
	return nil
}

// GetTrainingMaterial retrieves training material by ID.
func (ct *ComplianceTraining) GetTrainingMaterial(id string) (TrainingMaterial, error) {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	tm, exists := ct.trainingMaterials[id]
	if !exists {
		return TrainingMaterial{}, errors.New("training material not found")
	}
	return tm, nil
}

// AssignTrainingToUser assigns training material to a user.
func (ct *ComplianceTraining) AssignTrainingToUser(userID, trainingID string) error {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if _, exists := ct.trainingMaterials[trainingID]; !exists {
		return errors.New("training material not found")
	}
	ct.userTrainings[userID+trainingID] = UserTraining{
		UserID:           userID,
		TrainingID:       trainingID,
		CompletionStatus: false,
	}
	return nil
}

// CompleteTraining marks a training material as completed for a user.
func (ct *ComplianceTraining) CompleteTraining(userID, trainingID string) error {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	utKey := userID + trainingID
	ut, exists := ct.userTrainings[utKey]
	if !exists {
		return errors.New("user training not found")
	}
	ut.CompletionStatus = true
	ut.CompletionDate = time.Now()
	ct.userTrainings[utKey] = ut
	return nil
}

// GetUserTrainingStatus retrieves the training status of a user.
func (ct *ComplianceTraining) GetUserTrainingStatus(userID, trainingID string) (UserTraining, error) {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	ut, exists := ct.userTrainings[userID+trainingID]
	if !exists {
		return UserTraining{}, errors.New("user training not found")
	}
	return ut, nil
}

func main() {
	// Initialize the compliance training system
	ct := NewComplianceTraining()

	// Add training materials
	tm := TrainingMaterial{
		ID:          "tm1",
		Title:       "Blockchain Compliance 101",
		Content:     "Introduction to blockchain compliance...",
		LastUpdated: time.Now(),
	}
	ct.AddTrainingMaterial(tm)

	// Assign training to a user
	userID := "user123"
	trainingID := "tm1"
	err := ct.AssignTrainingToUser(userID, trainingID)
	if err != nil {
		log.Println("Error assigning training:", err)
	}

	// Complete training for a user
	err = ct.CompleteTraining(userID, trainingID)
	if err != nil {
		log.Println("Error completing training:", err)
	}

	// Retrieve user training status
	status, err := ct.GetUserTrainingStatus(userID, trainingID)
	if err != nil {
		log.Println("Error getting user training status:", err)
	} else {
		log.Println("User training status:", status)
	}
}
