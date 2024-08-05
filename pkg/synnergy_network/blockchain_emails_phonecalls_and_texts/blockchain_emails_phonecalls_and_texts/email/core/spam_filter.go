package core


import (
	"regexp"
	"strings"
)

// SpamFilter represents the spam filtering mechanism
type SpamFilter struct {
	blacklist   []string
	whitelist   []string
	spamWords   []string
	blacklistRE []*regexp.Regexp
}

// NewSpamFilter creates a new spam filter
func NewSpamFilter() *SpamFilter {
	return &SpamFilter{
		blacklist:   []string{},
		whitelist:   []string{},
		spamWords:   []string{},
		blacklistRE: []*regexp.Regexp{},
	}
}

// AddToBlacklist adds an address or domain to the blacklist
func (sf *SpamFilter) AddToBlacklist(addressOrDomain string) {
	sf.blacklist = append(sf.blacklist, addressOrDomain)
	re := regexp.MustCompile(strings.ReplaceAll(addressOrDomain, "*", ".*"))
	sf.blacklistRE = append(sf.blacklistRE, re)
}

// RemoveFromBlacklist removes an address or domain from the blacklist
func (sf *SpamFilter) RemoveFromBlacklist(addressOrDomain string) {
	for i, v := range sf.blacklist {
		if v == addressOrDomain {
			sf.blacklist = append(sf.blacklist[:i], sf.blacklist[i+1:]...)
			sf.blacklistRE = append(sf.blacklistRE[:i], sf.blacklistRE[i+1:]...)
			break
		}
	}
}

// AddToWhitelist adds an address or domain to the whitelist
func (sf *SpamFilter) AddToWhitelist(addressOrDomain string) {
	sf.whitelist = append(sf.whitelist, addressOrDomain)
}

// RemoveFromWhitelist removes an address or domain from the whitelist
func (sf *SpamFilter) RemoveFromWhitelist(addressOrDomain string) {
	for i, v := range sf.whitelist {
		if v == addressOrDomain {
			sf.whitelist = append(sf.whitelist[:i], sf.whitelist[i+1:]...)
			break
		}
	}
}

// AddSpamWord adds a word to the spam word list
func (sf *SpamFilter) AddSpamWord(word string) {
	sf.spamWords = append(sf.spamWords, word)
}

// RemoveSpamWord removes a word from the spam word list
func (sf *SpamFilter) RemoveSpamWord(word string) {
	for i, v := range sf.spamWords {
		if v == word {
			sf.spamWords = append(sf.spamWords[:i], sf.spamWords[i+1:]...)
			break
		}
	}
}

// IsSpam checks if the given email content is considered spam
func (sf *SpamFilter) IsSpam(emailContent string) bool {
	// Check against spam words
	for _, word := range sf.spamWords {
		if strings.Contains(strings.ToLower(emailContent), strings.ToLower(word)) {
			return true
		}
	}

	// Check against blacklist
	for _, re := range sf.blacklistRE {
		if re.MatchString(emailContent) {
			return true
		}
	}

	// Check against whitelist
	for _, whiteItem := range sf.whitelist {
		if strings.Contains(emailContent, whiteItem) {
			return false
		}
	}

	return false
}

// IsBlacklisted checks if the given address or domain is blacklisted
func (sf *SpamFilter) IsBlacklisted(addressOrDomain string) bool {
	for _, re := range sf.blacklistRE {
		if re.MatchString(addressOrDomain) {
			return true
		}
	}
	return false
}

// IsWhitelisted checks if the given address or domain is whitelisted
func (sf *SpamFilter) IsWhitelisted(addressOrDomain string) bool {
	for _, whiteItem := range sf.whitelist {
		if whiteItem == addressOrDomain {
			return true
		}
	}
	return false
}
