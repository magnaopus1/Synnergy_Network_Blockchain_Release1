package core

import (
	"errors"
	"strings"
)

type AIAssistance struct {
	assistanceData map[string]string
}

func NewAIAssistance() *AIAssistance {
	return &AIAssistance{
		assistanceData: make(map[string]string),
	}
}

func (ai *AIAssistance) AddAssistance(key, value string) {
	ai.assistanceData[key] = value
}

func (ai *AIAssistance) GetAssistance(key string) (string, error) {
	value, exists := ai.assistanceData[key]
	if !exists {
		return "", errors.New("assistance not found")
	}
	return value, nil
}

func (ai *AIAssistance) ListAssistances() []string {
	var assistances []string
	for key := range ai.assistanceData {
		assistances = append(assistances, key)
	}
	return assistances
}

func (ai *AIAssistance) FilterAssistanceByPrefix(prefix string) []string {
	var filtered []string
	for key := range ai.assistanceData {
		if strings.HasPrefix(key, prefix) {
			filtered = append(filtered, key)
		}
	}
	return filtered
}
