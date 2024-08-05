package prioritization_and_assignment

import (
	"errors"
	"sort"
	"sync"
)

// Bug represents a bug report in the system.
type Bug struct {
	ID          string
	Title       string
	Description string
	Severity    string
	Status      string
	Reporter    string
	AssignedTo  string
	Priority    int
}

// PriorityManager handles the prioritization and assignment of bugs.
type PriorityManager struct {
	bugs        map[string]*Bug
	priorityMap map[int][]*Bug
	mu          sync.Mutex
}

// NewPriorityManager creates a new instance of PriorityManager.
func NewPriorityManager() *PriorityManager {
	return &PriorityManager{
		bugs:        make(map[string]*Bug),
		priorityMap: make(map[int][]*Bug),
	}
}

// AddBug adds a new bug to the system.
func (pm *PriorityManager) AddBug(bug *Bug) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if _, exists := pm.bugs[bug.ID]; exists {
		return errors.New("bug with this ID already exists")
	}

	pm.bugs[bug.ID] = bug
	pm.priorityMap[bug.Priority] = append(pm.priorityMap[bug.Priority], bug)

	return nil
}

// UpdateBug updates an existing bug in the system.
func (pm *PriorityManager) UpdateBug(updatedBug *Bug) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	bug, exists := pm.bugs[updatedBug.ID]
	if !exists {
		return errors.New("bug not found")
	}

	// Remove bug from old priority list
	pm.removeBugFromPriorityMap(bug)

	// Update the bug details
	bug.Title = updatedBug.Title
	bug.Description = updatedBug.Description
	bug.Severity = updatedBug.Severity
	bug.Status = updatedBug.Status
	bug.Reporter = updatedBug.Reporter
	bug.AssignedTo = updatedBug.AssignedTo
	bug.Priority = updatedBug.Priority

	// Add bug to new priority list
	pm.priorityMap[bug.Priority] = append(pm.priorityMap[bug.Priority], bug)

	return nil
}

// removeBugFromPriorityMap removes a bug from the priority map.
func (pm *PriorityManager) removeBugFromPriorityMap(bug *Bug) {
	bugs := pm.priorityMap[bug.Priority]
	for i, b := range bugs {
		if b.ID == bug.ID {
			pm.priorityMap[bug.Priority] = append(bugs[:i], bugs[i+1:]...)
			break
		}
	}
}

// GetBugsByPriority retrieves all bugs of a given priority.
func (pm *PriorityManager) GetBugsByPriority(priority int) []*Bug {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	return pm.priorityMap[priority]
}

// GetBugByID retrieves a bug by its ID.
func (pm *PriorityManager) GetBugByID(id string) (*Bug, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	bug, exists := pm.bugs[id]
	if !exists {
		return nil, errors.New("bug not found")
	}

	return bug, nil
}

// ListAllBugs lists all bugs sorted by priority.
func (pm *PriorityManager) ListAllBugs() []*Bug {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	var allBugs []*Bug
	for _, bugs := range pm.priorityMap {
		allBugs = append(allBugs, bugs...)
	}

	sort.Slice(allBugs, func(i, j int) bool {
		return allBugs[i].Priority < allBugs[j].Priority
	})

	return allBugs
}

// AssignBug assigns a bug to a team member.
func (pm *PriorityManager) AssignBug(bugID, assignee string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	bug, exists := pm.bugs[bugID]
	if !exists {
		return errors.New("bug not found")
	}

	bug.AssignedTo = assignee
	return nil
}

// SetBugPriority sets the priority of a bug.
func (pm *PriorityManager) SetBugPriority(bugID string, priority int) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	bug, exists := pm.bugs[bugID]
	if !exists {
		return errors.New("bug not found")
	}

	// Remove bug from old priority list
	pm.removeBugFromPriorityMap(bug)

	// Update priority
	bug.Priority = priority

	// Add bug to new priority list
	pm.priorityMap[priority] = append(pm.priorityMap[priority], bug)

	return nil
}

// GeneratePriorityReport generates a report of bugs by priority.
func (pm *PriorityManager) GeneratePriorityReport() map[int][]*Bug {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	priorityReport := make(map[int][]*Bug)
	for priority, bugs := range pm.priorityMap {
		priorityReport[priority] = append([]*Bug(nil), bugs...)
	}

	return priorityReport
}

// AutomatedPriorityAdjustment uses predefined rules to adjust the priority of bugs based on their severity and status.
func (pm *PriorityManager) AutomatedPriorityAdjustment() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for _, bug := range pm.bugs {
		if bug.Status == "Critical" && bug.Priority != 1 {
			pm.SetBugPriority(bug.ID, 1)
		} else if bug.Status == "High" && bug.Priority > 2 {
			pm.SetBugPriority(bug.ID, 2)
		} else if bug.Status == "Medium" && bug.Priority > 3 {
			pm.SetBugPriority(bug.ID, 3)
		}
	}
}

// ResolveBug marks a bug as resolved.
func (pm *PriorityManager) ResolveBug(bugID string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	bug, exists := pm.bugs[bugID]
	if !exists {
		return errors.New("bug not found")
	}

	bug.Status = "Resolved"
	return nil
}

// BugAnalytics provides analytical insights into the bug data.
func (pm *PriorityManager) BugAnalytics() map[string]int {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	analytics := map[string]int{
		"TotalBugs":        len(pm.bugs),
		"CriticalBugs":     0,
		"HighBugs":         0,
		"MediumBugs":       0,
		"LowBugs":          0,
		"ResolvedBugs":     0,
		"UnresolvedBugs":   0,
		"AssignedBugs":     0,
		"UnassignedBugs":   0,
	}

	for _, bug := range pm.bugs {
		switch bug.Status {
		case "Critical":
			analytics["CriticalBugs"]++
		case "High":
			analytics["HighBugs"]++
		case "Medium":
			analytics["MediumBugs"]++
		case "Low":
			analytics["LowBugs"]++
		case "Resolved":
			analytics["ResolvedBugs"]++
		default:
			analytics["UnresolvedBugs"]++
		}

		if bug.AssignedTo != "" {
			analytics["AssignedBugs"]++
		} else {
			analytics["UnassignedBugs"]++
		}
	}

	return analytics
}
