package security

import (
	"net"
	"strings"
	"log"
	"fmt"
)

// FirewallRule defines the structure for firewall rules
type FirewallRule struct {
	SourceIP   string
	DestinationIP string
	Port       int
	Action     string // "allow" or "deny"
}

// Firewall manages a list of rules and checks traffic against them
type Firewall struct {
	Rules []FirewallRule
}

// NewFirewall initializes a new Firewall instance with default rules
func NewFirewall() *Firewall {
	return &Firewall{
		Rules: []FirewallRule{
			{SourceIP: "0.0.0.0/0", DestinationIP: "0.0.0.0/0", Port: 22, Action: "deny"}, // Default deny SSH globally
		},
	}
}

// AddRule adds a new rule to the firewall
func (f *Firewall) AddRule(rule FirewallRule) {
	f.Rules = append(f.Rules, rule)
}

// CheckTraffic checks if the given IP and port are allowed or denied
func (f *Firewall) CheckTraffic(sourceIP, destinationIP string, port int) bool {
	for _, rule := range f.Rules {
		if strings.Contains(sourceIP, rule.SourceIP) && strings.Contains(destinationIP, rule.DestinationIP) && port == rule.Port {
			return rule.Action == "allow"
		}
	}
	return false
}

// Example of a firewall rule to allow HTTP traffic from a specific IP
func setupExampleRules(fw *Firewall) {
	fw.AddRule(FirewallRule{SourceIP: "192.168.1.1", DestinationIP: "0.0.0.0/0", Port: 80, Action: "allow"})
}

// Example main function to demonstrate usage
func main() {
	fw := NewFirewall()
	setupExampleRules(fw)

	testIP := "192.168.1.1"
	testPort := 80
	allowed := fw.CheckTraffic(testIP, "anywhere", testPort)

	log.Printf("Traffic from %s to port %d allowed: %v", testIP, testPort, allowed)
}
