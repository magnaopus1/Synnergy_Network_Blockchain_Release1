package allocation

import (
	"errors"
	"log"
	"sort"
	"sync"
	"time"
)

// Resource represents a computational resource.
type Resource struct {
	CPU    float64
	Memory float64
	Bandwidth float64
	Storage float64
}

// Task represents a job or process that requires resources.
type Task struct {
	ID          string
	Priority    int
	RequiredRes Resource
	Deadline    time.Time
}

// Node represents a network node capable of handling tasks.
type Node struct {
	ID        string
	AvailableRes Resource
	AllocatedTasks map[string]Task
	mu        sync.Mutex
}

// Scheduler handles the allocation of tasks to nodes.
type Scheduler struct {
	Nodes map[string]*Node
	mu    sync.Mutex
}

// NewScheduler creates a new Scheduler.
func NewScheduler() *Scheduler {
	return &Scheduler{
		Nodes: make(map[string]*Node),
	}
}

// AddNode adds a new node to the scheduler.
func (s *Scheduler) AddNode(node *Node) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Nodes[node.ID] = node
}

// ScheduleTask assigns a task to the most suitable node based on availability and priority.
func (s *Scheduler) ScheduleTask(task Task) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Find nodes that can accommodate the task's resource requirements
	var candidateNodes []*Node
	for _, node := range s.Nodes {
		if s.canAccommodate(node, task.RequiredRes) {
			candidateNodes = append(candidateNodes, node)
		}
	}

	if len(candidateNodes) == 0 {
		return errors.New("no suitable nodes available")
	}

	// Sort nodes by available resources and task priority
	sort.Slice(candidateNodes, func(i, j int) bool {
		return s.availableResources(candidateNodes[i]) > s.availableResources(candidateNodes[j])
	})

	// Assign the task to the most suitable node
	node := candidateNodes[0]
	node.mu.Lock()
	defer node.mu.Unlock()

	node.AllocatedTasks[task.ID] = task
	node.AvailableRes.CPU -= task.RequiredRes.CPU
	node.AvailableRes.Memory -= task.RequiredRes.Memory
	node.AvailableRes.Bandwidth -= task.RequiredRes.Bandwidth
	node.AvailableRes.Storage -= task.RequiredRes.Storage

	log.Printf("Task %s scheduled on node %s", task.ID, node.ID)
	return nil
}

// canAccommodate checks if a node has enough available resources for a task.
func (s *Scheduler) canAccommodate(node *Node, res Resource) bool {
	node.mu.Lock()
	defer node.mu.Unlock()

	return node.AvailableRes.CPU >= res.CPU &&
		node.AvailableRes.Memory >= res.Memory &&
		node.AvailableRes.Bandwidth >= res.Bandwidth &&
		node.AvailableRes.Storage >= res.Storage
}

// availableResources calculates the total available resources of a node.
func (s *Scheduler) availableResources(node *Node) float64 {
	node.mu.Lock()
	defer node.mu.Unlock()

	return node.AvailableRes.CPU + node.AvailableRes.Memory + node.AvailableRes.Bandwidth + node.AvailableRes.Storage
}

// MonitorAndReallocate continuously monitors node statuses and reallocates tasks if necessary.
func (s *Scheduler) MonitorAndReallocate() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.reallocateTasks()
		}
	}
}

// reallocateTasks redistributes tasks from overloaded nodes.
func (s *Scheduler) reallocateTasks() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, node := range s.Nodes {
		if s.isOverloaded(node) {
			for _, task := range node.AllocatedTasks {
				// Try to find a better node for this task
				if err := s.ScheduleTask(task); err == nil {
					node.mu.Lock()
					delete(node.AllocatedTasks, task.ID)
					node.mu.Unlock()
				}
			}
		}
	}
}

// isOverloaded checks if a node is overloaded.
func (s *Scheduler) isOverloaded(node *Node) bool {
	node.mu.Lock()
	defer node.mu.Unlock()

	const threshold = 0.8
	return node.AvailableRes.CPU < threshold ||
		node.AvailableRes.Memory < threshold ||
		node.AvailableRes.Bandwidth < threshold ||
		node.AvailableRes.Storage < threshold
}
