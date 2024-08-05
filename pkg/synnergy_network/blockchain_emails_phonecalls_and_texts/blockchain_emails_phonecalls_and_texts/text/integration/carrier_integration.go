package integration

import (
	"errors"
)

type Carrier struct {
	CarrierID string
	Name      string
	APIToken  string
}

type CarrierManager struct {
	Carriers map[string]*Carrier
}

func NewCarrierManager() *CarrierManager {
	return &CarrierManager{
		Carriers: make(map[string]*Carrier),
	}
}

func (cm *CarrierManager) AddCarrier(carrierID, name, apiToken string) {
	cm.Carriers[carrierID] = &Carrier{
		CarrierID: carrierID,
		Name:      name,
		APIToken:  apiToken,
	}
}

func (cm *CarrierManager) GetCarrier(carrierID string) (*Carrier, error) {
	carrier, exists := cm.Carriers[carrierID]
	if !exists {
		return nil, errors.New("carrier not found")
	}
	return carrier, nil
}

func (cm *CarrierManager) ListCarriers() []*Carrier {
	var carriers []*Carrier
	for _, carrier := range cm.Carriers {
		carriers = append(carriers, carrier)
	}
	return carriers
}

func (cm *CarrierManager) RemoveCarrier(carrierID string) {
	delete(cm.Carriers, carrierID)
}
