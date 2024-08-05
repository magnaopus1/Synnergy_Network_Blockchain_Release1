package core

import (
	"errors"
	"time"
)

type Message struct {
	ID        string
	From      string
	To        string
	Content   string
	Timestamp time.Time
}

func NewMessage(id, from, to, content string) *Message {
	return &Message{
		ID:        id,
		From:      from,
		To:        to,
		Content:   content,
		Timestamp: time.Now(),
	}
}

type MessageManager struct {
	Messages map[string]*Message
}

func NewMessageManager() *MessageManager {
	return &MessageManager{
		Messages: make(map[string]*Message),
	}
}

func (mm *MessageManager) AddMessage(id, from, to, content string) {
	message := NewMessage(id, from, to, content)
	mm.Messages[id] = message
}

func (mm *MessageManager) GetMessage(id string) (*Message, error) {
	message, exists := mm.Messages[id]
	if !exists {
		return nil, errors.New("message not found")
	}
	return message, nil
}

func (mm *MessageManager) ListMessages() []*Message {
	var messages []*Message
	for _, message := range mm.Messages {
		messages = append(messages, message)
	}
	return messages
}
