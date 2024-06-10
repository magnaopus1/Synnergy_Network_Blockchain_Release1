package contracts

import (
	"errors"
	"sync"
)

// Rule defines the structure for resource allocation rules.
type Rule struct {
	ID           string
	Description  string
	ResourceType string
	MinValue     int
	MaxValue     int
	Priority     int
}

// RuleManager manages the set of rules for resource allocation.
type RuleManager struct {
	mutex sync.Mutex
	rules map[string]*Rule
}

// NewRuleManager creates a new instance of RuleManager.
func NewRuleManager() *RuleManager {
	return &RuleManager{
		rules: make(map[string]*Rule),
	}
}

// AddRule adds a new rule to the manager.
func (rm *RuleManager) AddRule(id, description, resourceType string, minValue, maxValue, priority int) error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	if _, exists := rm.rules[id]; exists {
		return errors.New("rule already exists")
	}

	newRule := &Rule{
		ID:           id,
		Description:  description,
		ResourceType: resourceType,
		MinValue:     minValue,
		MaxValue:     maxValue,
		Priority:     priority,
	}
	rm.rules[id] = newRule
	return nil
}

// GetRule retrieves a rule by its ID.
func (rm *RuleManager) GetRule(id string) (*Rule, error) {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	rule, exists := rm.rules[id]
	if !exists {
		return nil, errors.New("rule not found")
	}
	return rule, nil
}

// UpdateRule updates the attributes of an existing rule.
func (rm *RuleManager) UpdateRule(id string, updates map[string]interface{}) error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	rule, exists := rm.rules[id]
	if !exists {
		return errors.New("rule not found")
	}

	if description, ok := updates["description"].(string); ok {
		rule.Description = description
	}
	if resourceType, ok := updates["resourceType"].(string); ok {
		rule.ResourceType = resourceType
	}
	if minValue, ok := updates["minValue"].(int); ok {
		rule.MinValue = minValue
	}
	if maxValue, ok := updates["maxValue"].(int); ok {
		rule.MaxValue = maxValue
	}
	if priority, ok := updates["priority"].(int); ok {
		rule.Priority = priority
	}

	return nil
}

// DeleteRule removes a rule from the manager.
func (rm *RuleManager) DeleteRule(id string) error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	if _, exists := rm.rules[id]; !exists {
		return errors.New("rule not found")
	}

	delete(rm.rules, id)
	return nil
}

// ListRules returns all rules managed by the RuleManager.
func (rm *RuleManager) ListRules() []*Rule {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	var list []*Rule
	for _, rule := range rm.rules {
		list = append(list, rule)
	}
	return list
}

