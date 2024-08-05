package energy_efficiency

import (
	"encoding/json"
	"errors"
	"sync"
	"time"
)

// GreenCertification represents a green certification for an entity
type GreenCertification struct {
	ID            string
	EntityID      string
	Description   string
	IssuedDate    time.Time
	ExpiryDate    time.Time
	CertifyingBody string
	IsActive      bool
}

// GreenCertificationProgram manages green certifications
type GreenCertificationProgram struct {
	mu               sync.Mutex
	certifications   map[string]*GreenCertification
	entities         map[string][]*GreenCertification
}

// NewGreenCertificationProgram initializes a new GreenCertificationProgram
func NewGreenCertificationProgram() *GreenCertificationProgram {
	return &GreenCertificationProgram{
		certifications: make(map[string]*GreenCertification),
		entities:       make(map[string][]*GreenCertification),
	}
}

// IssueCertification issues a new green certification to an entity
func (gcp *GreenCertificationProgram) IssueCertification(entityID, description, certifyingBody string, validityDays int) (*GreenCertification, error) {
	gcp.mu.Lock()
	defer gcp.mu.Unlock()

	id := generateID()
	certification := &GreenCertification{
		ID:            id,
		EntityID:      entityID,
		Description:   description,
		IssuedDate:    time.Now(),
		ExpiryDate:    time.Now().AddDate(0, 0, validityDays),
		CertifyingBody: certifyingBody,
		IsActive:      true,
	}

	gcp.certifications[id] = certification
	gcp.entities[entityID] = append(gcp.entities[entityID], certification)
	return certification, nil
}

// RevokeCertification revokes an active green certification
func (gcp *GreenCertificationProgram) RevokeCertification(certificationID string) error {
	gcp.mu.Lock()
	defer gcp.mu.Unlock()

	certification, exists := gcp.certifications[certificationID]
	if !exists {
		return errors.New("certification not found")
	}

	if !certification.IsActive {
		return errors.New("certification is already inactive")
	}

	certification.IsActive = false
	return nil
}

// GetActiveCertifications returns active certifications for an entity
func (gcp *GreenCertificationProgram) GetActiveCertifications(entityID string) ([]*GreenCertification, error) {
	gcp.mu.Lock()
	defer gcp.mu.Unlock()

	var activeCertifications []*GreenCertification
	certifications, exists := gcp.entities[entityID]
	if !exists {
		return nil, errors.New("no certifications found for the entity")
	}

	for _, certification := range certifications {
		if certification.IsActive && certification.ExpiryDate.After(time.Now()) {
			activeCertifications = append(activeCertifications, certification)
		}
	}
	return activeCertifications, nil
}

// GetCertificationHistory returns the certification history for an entity
func (gcp *GreenCertificationProgram) GetCertificationHistory(entityID string) ([]*GreenCertification, error) {
	gcp.mu.Lock()
	defer gcp.mu.Unlock()

	certifications, exists := gcp.entities[entityID]
	if !exists {
		return nil, errors.New("no certifications found for the entity")
	}

	return certifications, nil
}

// BackupData backs up the current state of the green certification program
func (gcp *GreenCertificationProgram) BackupData() (string, error) {
	gcp.mu.Lock()
	defer gcp.mu.Unlock()

	data := struct {
		Certifications map[string]*GreenCertification
		Entities       map[string][]*GreenCertification
	}{
		Certifications: gcp.certifications,
		Entities:       gcp.entities,
	}

	bytes, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	return string(bytes), nil
}

// RestoreData restores the state of the green certification program from a backup
func (gcp *GreenCertificationProgram) RestoreData(data string) error {
	gcp.mu.Lock()
	defer gcp.mu.Unlock()

	var backup struct {
		Certifications map[string]*GreenCertification
		Entities       map[string][]*GreenCertification
	}

	err := json.Unmarshal([]byte(data), &backup)
	if err != nil {
		return err
	}

	gcp.certifications = backup.Certifications
	gcp.entities = backup.Entities
	return nil
}

// generateID generates a unique ID
func generateID() string {
	rand.Seed(time.Now().UnixNano())
	return fmt.Sprintf("%d", rand.Int())
}
