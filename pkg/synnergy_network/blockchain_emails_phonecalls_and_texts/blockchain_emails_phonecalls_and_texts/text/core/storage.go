package core

import (
	"errors"
	"time"
)

type Storage struct {
	Data map[string]interface{}
}

func NewStorage() *Storage {
	return &Storage{
		Data: make(map[string]interface{}),
	}
}

func (s *Storage) Save(key string, value interface{}) {
	s.Data[key] = value
}

func (s *Storage) Load(key string) (interface{}, error) {
	value, exists := s.Data[key]
	if !exists {
		return nil, errors.New("key not found")
	}
	return value, nil
}

func (s *Storage) Delete(key string) {
	delete(s.Data, key)
}

func (s *Storage) ListKeys() []string {
	var keys []string
	for key := range s.Data {
		keys = append(keys, key)
	}
	return keys
}

type MessageStorage struct {
	Storage
}

func NewMessageStorage() *MessageStorage {
	return &MessageStorage{
		Storage: *NewStorage(),
	}
}

func (ms *MessageStorage) SaveMessage(id, from, to, content string) {
	message := NewMessage(id, from, to, content)
	ms.Save(id, message)
}

func (ms *MessageStorage) LoadMessage(id string) (*Message, error) {
	value, err := ms.Load(id)
	if err != nil {
		return nil, err
	}
	message, ok := value.(*Message)
	if !ok {
		return nil, errors.New("invalid message type")
	}
	return message, nil
}

func (ms *MessageStorage) DeleteMessage(id string) {
	ms.Delete(id)
}

func (ms *MessageStorage) ListMessageKeys() []string {
	return ms.ListKeys()
}
