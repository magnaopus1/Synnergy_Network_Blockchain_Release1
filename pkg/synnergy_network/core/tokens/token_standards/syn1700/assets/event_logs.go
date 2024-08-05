package assets

import (
    "encoding/json"
    "errors"
    "time"
)

// EventLog represents a log of event-related activities
type EventLog struct {
    EventID   string
    Activity  string
    Timestamp time.Time
}

// EventLogManager manages event logs for SYN1700 tokens
type EventLogManager struct {
    logs map[string][]EventLog // EventID -> EventLogs
}

// NewEventLogManager creates a new EventLogManager
func NewEventLogManager() *EventLogManager {
    return &EventLogManager{
        logs: make(map[string][]EventLog),
    }
}

// AddEventLog adds an event log for a specific event
func (elm *EventLogManager) AddEventLog(eventID, activity string) error {
    if eventID == "" || activity == "" {
        return errors.New("event ID and activity details are required")
    }

    log := EventLog{
        EventID:   eventID,
        Activity:  activity,
        Timestamp: time.Now(),
    }

    elm.logs[eventID] = append(elm.logs[eventID], log)
    return nil
}

// GetEventLogs retrieves all event logs for a specific event
func (elm *EventLogManager) GetEventLogs(eventID string) ([]EventLog, error) {
    logs, exists := elm.logs[eventID]
    if !exists {
        return nil, errors.New("no event logs found for the specified event ID")
    }
    return logs, nil
}

// GetAllEventLogs retrieves all event logs
func (elm *EventLogManager) GetAllEventLogs() map[string][]EventLog {
    return elm.logs
}

// SerializeEventLogs serializes event logs to JSON
func (elm *EventLogManager) SerializeEventLogs(eventID string) (string, error) {
    logs, err := elm.GetEventLogs(eventID)
    if err != nil {
        return "", err
    }

    data, err := json.Marshal(logs)
    if err != nil {
        return "", err
    }
    return string(data), nil
}

// DeserializeEventLogs deserializes event logs from JSON
func (elm *EventLogManager) DeserializeEventLogs(eventID, data string) error {
    var logs []EventLog
    err := json.Unmarshal([]byte(data), &logs)
    if err != nil {
        return err
    }

    elm.logs[eventID] = logs
    return nil
}
