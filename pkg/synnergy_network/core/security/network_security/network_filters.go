package networksecurity

import (
	"errors"
	"log"
	"net"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

const (
	Salt      = "unique-salt-for-security"
	KeyLength = 32
)

// FilterRule defines a rule for filtering network traffic
type FilterRule struct {
	IPRange    string // IP range in CIDR notation
	Allowed    bool   // true if allowed, false if blocked
	Protocol   string // TCP, UDP, etc.
	Port       int    // Port number, 0 for all ports
}

// NetworkFilter manages a list of rules for network traffic
type NetworkFilter struct {
	rules []FilterRule
}

// NewNetworkFilter creates a new network filter with an initial set of rules
func NewNetworkFilter(rules []FilterRule) *NetworkFilter {
	return &NetworkFilter{
		rules: rules,
	}
}

// AddRule adds a new rule to the network filter
func (nf *NetworkFilter) AddRule(rule FilterRule) {
	nf.rules = append(nf.rules, rule)
}

// FilterPacket decides whether a packet should be allowed or blocked based on the rules
func (nf *NetworkFilter) FilterPacket(ip net.IP, protocol string, port int) bool {
	for _, rule := range nf.rules {
		_, ipNet, _ := net.ParseCIDR(rule.IPRange)
		if ipNet.Contains(ip) && rule.Protocol == protocol && (rule.Port == 0 || rule.Port == port) {
			return rule.Allowed
		}
	}
	return false // Default to blocking if no rule matches
}

// EncryptData provides an example of data encryption using Argon2
func EncryptData(data []byte) []byte {
	salt := []byte(Salt)
	return argon2.IDKey(data, salt, 1, 64*1024, 4, KeyLength)
}

// DecryptData provides an example of data decryption using Scrypt
func DecryptData(data []byte) ([]byte, error) {
	key, err := scrypt.Key(data, []byte(Salt), 16384, 8, 1, KeyLength)
	if err != nil {
		log.Println("Error decrypting data:", err)
		return nil, err
	}
	return key, nil
}

func main() {
	// Example setup for network filtering
	rules := []FilterRule{
		{IPRange: "192.168.1.0/24", Allowed: true, Protocol: "TCP", Port: 80},
		{IPRange: "10.0.0.0/8", Allowed: false, Protocol: "TCP", Port: 0},
	}
	filter := NewNetworkFilter(rules)
	// Simulate filtering a packet
	log.Println("Packet allowed:", filter.FilterPacket(net.ParseIP("192.168.1.100"), "TCP", 80))
}
