package core

import (
	"errors"
	"strings"
)

type SpamFilter struct {
	BlockedWords []string
}

func NewSpamFilter() *SpamFilter {
	return &SpamFilter{
		BlockedWords: []string{},
	}
}

func (sf *SpamFilter) AddBlockedWord(word string) {
	sf.BlockedWords = append(sf.BlockedWords, word)
}

func (sf *SpamFilter) RemoveBlockedWord(word string) {
	for i, w := range sf.BlockedWords {
		if w == word {
			sf.BlockedWords = append(sf.BlockedWords[:i], sf.BlockedWords[i+1:]...)
			break
		}
	}
}

func (sf *SpamFilter) IsSpam(content string) bool {
	for _, word := range sf.BlockedWords {
		if strings.Contains(content, word) {
			return true
		}
	}
	return false
}

func (sf *SpamFilter) FilterMessages(messages []*Message) ([]*Message, error) {
	if len(messages) == 0 {
		return nil, errors.New("no messages to filter")
	}
	var filteredMessages []*Message
	for _, message := range messages {
		if !sf.IsSpam(message.Content) {
			filteredMessages = append(filteredMessages, message)
		}
	}
	return filteredMessages, nil
}
