package bug_tracking

import (
	"encoding/json"
	"errors"
	"log"
	"sync"
	"time"
)

// BugLifecycleStage represents the different stages in the lifecycle of a bug
type BugLifecycleStage string

const (
	Reported   BugLifecycleStage = "Reported"
	Confirmed  BugLifecycleStage = "Confirmed"
	InProgress BugLifecycleStage = "InProgress"
	Resolved   BugLifecycleStage = "Resolved"
	Closed     BugLifecycleStage = "Closed"
)

// Bug represents the structure of a bug report
type Bug struct {
	ID          string            `json:"id"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Reporter    string            `json:"reporter"`
	Status      BugLifecycleStage `json:"status"`
	Severity    string            `json:"severity"`
	Timestamp   time.Time         `json:"timestamp"`
	Assignee    string            `json:"assignee"`
	Comments    []Comment         `json:"comments"`
}

// Comment represents a comment made on a bug report
type Comment struct {
	User      string    `json:"user"`
	Timestamp time.Time `json:"timestamp"`
	Content   string    `json:"content"`
}

// BugLifecycleManagement manages the lifecycle of bugs
type BugLifecycleManagement struct {
	bugs map[string]Bug
	mu   sync.Mutex
}

// NewBugLifecycleManagement creates a new instance of BugLifecycleManagement
func NewBugLifecycleManagement() *BugLifecycleManagement {
	return &BugLifecycleManagement{
		bugs: make(map[string]Bug),
	}
}

// ReportBug reports a new bug and adds it to the lifecycle management system
func (blm *BugLifecycleManagement) ReportBug(title, description, reporter, severity string) (string, error) {
	blm.mu.Lock()
	defer blm.mu.Unlock()

	id := generateBugID(title, description)
	if _, exists := blm.bugs[id]; exists {
		return "", errors.New("bug with this ID already exists")
	}

	bug := Bug{
		ID:          id,
		Title:       title,
		Description: description,
		Reporter:    reporter,
		Status:      Reported,
		Severity:    severity,
		Timestamp:   time.Now(),
	}

	blm.bugs[id] = bug
	logBugAction("reported", bug)
	return id, nil
}

// ConfirmBug confirms a reported bug
func (blm *BugLifecycleManagement) ConfirmBug(id, assignee string) error {
	blm.mu.Lock()
	defer blm.mu.Unlock()

	bug, exists := blm.bugs[id]
	if !exists {
		return errors.New("bug not found")
	}

	bug.Status = Confirmed
	bug.Assignee = assignee
	blm.bugs[id] = bug
	logBugAction("confirmed", bug)
	return nil
}

// StartProgress sets a bug's status to in progress
func (blm *BugLifecycleManagement) StartProgress(id string) error {
	blm.mu.Lock()
	defer blm.mu.Unlock()

	bug, exists := blm.bugs[id]
	if !exists {
		return errors.New("bug not found")
	}

	bug.Status = InProgress
	blm.bugs[id] = bug
	logBugAction("in progress", bug)
	return nil
}

// ResolveBug resolves a bug and updates its status
func (blm *BugLifecycleManagement) ResolveBug(id string) error {
	blm.mu.Lock()
	defer blm.mu.Unlock()

	bug, exists := blm.bugs[id]
	if !exists {
		return errors.New("bug not found")
	}

	bug.Status = Resolved
	blm.bugs[id] = bug
	logBugAction("resolved", bug)
	return nil
}

// CloseBug closes a resolved bug
func (blm *BugLifecycleManagement) CloseBug(id string) error {
	blm.mu.Lock()
	defer blm.mu.Unlock()

	bug, exists := blm.bugs[id]
	if !exists {
		return errors.New("bug not found")
	}

	bug.Status = Closed
	blm.bugs[id] = bug
	logBugAction("closed", bug)
	return nil
}

// AddComment adds a comment to a bug report
func (blm *BugLifecycleManagement) AddComment(id, user, content string) error {
	blm.mu.Lock()
	defer blm.mu.Unlock()

	bug, exists := blm.bugs[id]
	if !exists {
		return errors.New("bug not found")
	}

	comment := Comment{
		User:      user,
		Timestamp: time.Now(),
		Content:   content,
	}
	bug.Comments = append(bug.Comments, comment)
	blm.bugs[id] = bug
	logBugAction("comment added", bug)
	return nil
}

// GetBug retrieves the details of a bug by its ID
func (blm *BugLifecycleManagement) GetBug(id string) (Bug, error) {
	blm.mu.Lock()
	defer blm.mu.Unlock()

	bug, exists := blm.bugs[id]
	if !exists {
		return Bug{}, errors.New("bug not found")
	}
	return bug, nil
}

// ListBugs lists all bugs in the lifecycle management system
func (blm *BugLifecycleManagement) ListBugs() []Bug {
	blm.mu.Lock()
	defer blm.mu.Unlock()

	var bugs []Bug
	for _, bug := range blm.bugs {
		bugs = append(bugs, bug)
	}
	return bugs
}

// logBugAction logs actions performed on bugs
func logBugAction(action string, bug Bug) {
	log.Printf("Bug %s: %s - %s (Severity: %s, Status: %s)", action, bug.ID, bug.Title, bug.Severity, bug.Status)
}

// generateBugID generates a unique ID for a bug based on its title and description
func generateBugID(title, description string) string {
	data := title + description + time.Now().String()
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

