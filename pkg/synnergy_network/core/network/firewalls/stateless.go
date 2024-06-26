package firewalls

import (
	"net"
	"sync"
)

// Rule defines a firewall rule.
type Rule struct {
	Source      string
	Destination string
	Action      string // "Allow" or "Deny"
}

// StatelessFirewall represents a stateless packet filtering firewall.
type StatelessFirewall struct {
	Rules []Rule
	mu    sync.RWMutex
}

// NewStatelessFirewall creates a new StatelessFirewall instance.
func NewStatelessFirewall() *StatelessFirewall {
	return &StatelessFirewall{
		Rules: make([]Rule, 0),
	}
}

// AddRule adds a new rule to the firewall.
func (sf *StatelessFirewall) AddRule(rule Rule) {
	sf.mu.Lock()
	defer sf.mu.Unlock()
	sf.Rules = append(sf.Rules, rule)
}

// RemoveRule removes a rule from the firewall based on index.
func (sf *StatelessFirewall) RemoveRule(index int) {
	sf.mu.Lock()
	defer sf.mu.Unlock()
	if index >= 0 && index < len(sf.Rules) {
		sf.Rules = append(sf.Rules[:index], sf.Rules[index+1:]...)
	}
}

// EvaluatePacket checks if a packet meets any of the firewall's rules.
func (sf *StatelessFirewall) EvaluatePacket(packet *net.IPConn) bool {
	sf.mu.RLock()
	defer sf.mu.RUnlock()
	srcAddr := packet.RemoteAddr().String()
	destAddr := packet.LocalAddr().String()

	for _, rule := range sf.Rules {
		if rule.Source == srcAddr && rule.Destination == destAddr {
			return rule.Action == "Allow"
		}
	}
	return false // Default action is to deny
}

// MonitorRules displays current rules for debugging.
func (sf *StatelessFirewall) MonitorRules() {
	sf.mu.RLock()
	defer sf.mu.RUnlock()
	for i, rule := range sf.Rules {
		fmt.Printf("Rule %d: %+v\n", i, rule)
	}
}

// Initialize and configure the stateless firewall.
func init() {
	firewall := NewStatelessFirewall()
	firewall.AddRule(Rule{Source: "192.168.1.1", Destination: "192.168.1.2", Action: "Allow"})
	firewall.MonitorRules()
}
