package security

import (
	"errors"
	"time"

	"github.com/synnergy_network/core/tokens/token_standards/syn131/events"
	"github.com/synnergy_network/core/tokens/token_standards/syn131/storage"
)

type RegulatoryCompliance struct {
	eventDispatcher events.EventDispatcher
	storage         storage.Storage
}

type ComplianceData struct {
	UserID         string
	KYCStatus      string
	AMLStatus      string
	LastChecked    time.Time
	ComplianceLogs []ComplianceLog
}

type ComplianceLog struct {
	Timestamp   time.Time
	Event       string
	Description string
}

const (
	KYCApproved  = "APPROVED"
	KYCRejected  = "REJECTED"
	AMLApproved  = "APPROVED"
	AMLRejected  = "REJECTED"
)

func NewRegulatoryCompliance(eventDispatcher events.EventDispatcher, storage storage.Storage) *RegulatoryCompliance {
	return &RegulatoryCompliance{
		eventDispatcher: eventDispatcher,
		storage:         storage,
	}
}

func (rc *RegulatoryCompliance) CheckKYC(userID string) error {
	// Implement actual KYC check logic here
	// Simulating KYC check
	complianceData, err := rc.getComplianceData(userID)
	if err != nil {
		return err
	}

	complianceData.KYCStatus = KYCApproved
	complianceData.LastChecked = time.Now()
	rc.updateComplianceData(userID, complianceData)

	log := ComplianceLog{
		Timestamp:   time.Now(),
		Event:       "KYC Check",
		Description: "KYC check completed and approved.",
	}
	complianceData.ComplianceLogs = append(complianceData.ComplianceLogs, log)

	event := events.Event{
		Type:    events.KYCChecked,
		Payload: map[string]interface{}{"userID": userID, "status": KYCApproved},
	}
	if err := rc.eventDispatcher.Dispatch(event); err != nil {
		return err
	}

	return nil
}

func (rc *RegulatoryCompliance) CheckAML(userID string) error {
	// Implement actual AML check logic here
	// Simulating AML check
	complianceData, err := rc.getComplianceData(userID)
	if err != nil {
		return err
	}

	complianceData.AMLStatus = AMLApproved
	complianceData.LastChecked = time.Now()
	rc.updateComplianceData(userID, complianceData)

	log := ComplianceLog{
		Timestamp:   time.Now(),
		Event:       "AML Check",
		Description: "AML check completed and approved.",
	}
	complianceData.ComplianceLogs = append(complianceData.ComplianceLogs, log)

	event := events.Event{
		Type:    events.AMLChecked,
		Payload: map[string]interface{}{"userID": userID, "status": AMLApproved},
	}
	if err := rc.eventDispatcher.Dispatch(event); err != nil {
		return err
	}

	return nil
}

func (rc *RegulatoryCompliance) LogComplianceEvent(userID, event, description string) error {
	complianceData, err := rc.getComplianceData(userID)
	if err != nil {
		return err
	}

	log := ComplianceLog{
		Timestamp:   time.Now(),
		Event:       event,
		Description: description,
	}
	complianceData.ComplianceLogs = append(complianceData.ComplianceLogs, log)

	rc.updateComplianceData(userID, complianceData)

	return nil
}

func (rc *RegulatoryCompliance) GetComplianceStatus(userID string) (ComplianceData, error) {
	return rc.getComplianceData(userID)
}

func (rc *RegulatoryCompliance) getComplianceData(userID string) (ComplianceData, error) {
	var complianceData ComplianceData
	if err := rc.storage.Get(userID, &complianceData); err != nil {
		return ComplianceData{}, err
	}
	return complianceData, nil
}

func (rc *RegulatoryCompliance) updateComplianceData(userID string, data ComplianceData) error {
	if err := rc.storage.Put(userID, data); err != nil {
		return err
	}
	return nil
}

func (rc *RegulatoryCompliance) EnsureCompliance(userID string) error {
	complianceData, err := rc.getComplianceData(userID)
	if err != nil {
		return err
	}

	if complianceData.KYCStatus != KYCApproved {
		return errors.New("user KYC not approved")
	}

	if complianceData.AMLStatus != AMLApproved {
		return errors.New("user AML not approved")
	}

	return nil
}
