package prioritization_and_assignment

import (
	"errors"
	"time"
)

// Severity levels for bugs
const (
	SeverityLow    = "Low"
	SeverityMedium = "Medium"
	SeverityHigh   = "High"
	Critical       = "Critical"
)

// BugReport represents a single bug report
type BugReport struct {
	ID          string
	Title       string
	Description string
	Severity    string
	Reporter    string
	AssignedTo  string
	Status      string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Developer represents a developer to whom bugs can be assigned
type Developer struct {
	ID       string
	Name     string
	Email    string
	Capacity int // Number of bugs a developer can handle at a time
}

// AssignmentManager manages the assignment of bugs to developers
type AssignmentManager struct {
	Bugs       []BugReport
	Developers []Developer
}

// NewAssignmentManager creates a new instance of AssignmentManager
func NewAssignmentManager() *AssignmentManager {
	return &AssignmentManager{
		Bugs:       []BugReport{},
		Developers: []Developer{},
	}
}

// AddBug adds a new bug to the system
func (am *AssignmentManager) AddBug(bug BugReport) {
	bug.ID = generateID()
	bug.CreatedAt = time.Now()
	bug.UpdatedAt = time.Now()
	am.Bugs = append(am.Bugs, bug)
}

// AddDeveloper adds a new developer to the system
func (am *AssignmentManager) AddDeveloper(dev Developer) {
	dev.ID = generateID()
	am.Developers = append(am.Developers, dev)
}

// AssignBug assigns a bug to a developer based on severity and developer capacity
func (am *AssignmentManager) AssignBug(bugID, developerID string) error {
	bug, err := am.findBugByID(bugID)
	if err != nil {
		return err
	}
	dev, err := am.findDeveloperByID(developerID)
	if err != nil {
		return err
	}
	if dev.Capacity <= 0 {
		return errors.New("developer has no capacity")
	}
	bug.AssignedTo = dev.ID
	bug.Status = "Assigned"
	bug.UpdatedAt = time.Now()
	dev.Capacity--
	return nil
}

// PrioritizeBugs prioritizes bugs based on severity
func (am *AssignmentManager) PrioritizeBugs() {
	low := []BugReport{}
	medium := []BugReport{}
	high := []BugReport{}
	critical := []BugReport{}

	for _, bug := range am.Bugs {
		switch bug.Severity {
		case SeverityLow:
			low = append(low, bug)
		case SeverityMedium:
			medium = append(medium, bug)
		case SeverityHigh:
			high = append(high, bug)
		case Critical:
			critical = append(critical, bug)
		}
	}
	am.Bugs = append(append(append(critical, high...), medium...), low...)
}

// findBugByID finds a bug by its ID
func (am *AssignmentManager) findBugByID(id string) (*BugReport, error) {
	for i, bug := range am.Bugs {
		if bug.ID == id {
			return &am.Bugs[i], nil
		}
	}
	return nil, errors.New("bug not found")
}

// findDeveloperByID finds a developer by their ID
func (am *AssignmentManager) findDeveloperByID(id string) (*Developer, error) {
	for i, dev := range am.Developers {
		if dev.ID == id {
			return &am.Developers[i], nil
		}
	}
	return nil, errors.New("developer not found")
}

// ListUnassignedBugs lists all unassigned bugs
func (am *AssignmentManager) ListUnassignedBugs() []BugReport {
	unassigned := []BugReport{}
	for _, bug := range am.Bugs {
		if bug.AssignedTo == "" {
			unassigned = append(unassigned, bug)
		}
	}
	return unassigned
}

// generateID generates a unique ID for bugs and developers
func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// DetailedBugReport generates a detailed report for a given bug
func (am *AssignmentManager) DetailedBugReport(bugID string) (string, error) {
	bug, err := am.findBugByID(bugID)
	if err != nil {
		return "", err
	}
	report := fmt.Sprintf("ID: %s\nTitle: %s\nDescription: %s\nSeverity: %s\nReporter: %s\nAssignedTo: %s\nStatus: %s\nCreatedAt: %s\nUpdatedAt: %s\n",
		bug.ID, bug.Title, bug.Description, bug.Severity, bug.Reporter, bug.AssignedTo, bug.Status, bug.CreatedAt, bug.UpdatedAt)
	return report, nil
}

// ReassignBug reassigns a bug to another developer
func (am *AssignmentManager) ReassignBug(bugID, newDeveloperID string) error {
	bug, err := am.findBugByID(bugID)
	if err != nil {
		return err
	}
	oldDev, err := am.findDeveloperByID(bug.AssignedTo)
	if err != nil {
		return err
	}
	newDev, err := am.findDeveloperByID(newDeveloperID)
	if err != nil {
		return err
	}
	if newDev.Capacity <= 0 {
		return errors.New("new developer has no capacity")
	}
	oldDev.Capacity++
	newDev.Capacity--
	bug.AssignedTo = newDev.ID
	bug.UpdatedAt = time.Now()
	return nil
}

// ResolveBug marks a bug as resolved
func (am *AssignmentManager) ResolveBug(bugID string) error {
	bug, err := am.findBugByID(bugID)
	if err != nil {
		return err
	}
	if bug.AssignedTo == "" {
		return errors.New("bug is not assigned to any developer")
	}
	bug.Status = "Resolved"
	bug.UpdatedAt = time.Now()
	dev, err := am.findDeveloperByID(bug.AssignedTo)
	if err != nil {
		return err
	}
	dev.Capacity++
	return nil
}
