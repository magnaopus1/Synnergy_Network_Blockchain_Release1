package governance_framework

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/json"
    "io"

    "github.com/pkg/errors"
)

// GovernanceModel defines the structure for different governance models.
type GovernanceModel struct {
    ModelName        string `json:"model_name"`
    Description      string `json:"description"`
    Specifics        map[string]interface{} `json:"specifics"` // Model specific parameters
}

// GovernanceSystem manages the deployment and operation of various governance models.
type GovernanceSystem struct {
    Models map[string]GovernanceModel
}

// NewGovernanceSystem initializes a governance system with predefined models.
func NewGovernanceSystem() *GovernanceSystem {
    models := make(map[string]GovernanceModel)
    models["direct_democracy"] = GovernanceModel{
        ModelName:    "Direct Democracy",
        Description:  "Allows every member to vote on every decision.",
        Specifics:    map[string]interface{}{"vote_type": "all-inclusive"},
    }
    models["delegated_voting"] = GovernanceModel{
        ModelName:    "Delegated Voting",
        Description:  "Members delegate their voting power to representatives.",
        Specifics:    map[string]interface{}{"delegate_levels": 5},
    }
    models["liquid_democracy"] = GovernanceModel{
        ModelName:    "Liquid Democracy",
        Description:  "A hybrid of direct and delegated voting.",
        Specifics:    map[string]interface{}{"fluid_delegation": true},
    }

    return &GovernanceSystem{Models: models}
}

// AddModel adds a new governance model to the system.
func (gs *GovernanceSystem) AddModel(model GovernanceModel) error {
    if _, exists := gs.Models[model.ModelName]; exists {
        return errors.New("model already exists")
    }
    gs.Models[model.ModelName] = model
    return nil
}

// GetModel retrieves a governance model by name.
func (gs *GovernanceSystem) GetModel(name string) (GovernanceModel, error) {
    model, found := gs.Models[name]
    if !found {
        return GovernanceModel{}, errors.New("model not found")
    }
    return model, nil
}

// SerializeModel serializes the governance model to JSON for storage or network transfer.
func (gs *GovernanceSystem) SerializeModel(modelName string) ([]byte, error) {
    model, found := gs.Models[modelName]
    if !found {
        return nil, errors.New("model not found")
    }
    data, err := json.Marshal(model)
    if err != nil {
        return nil, errors.Wrap(err, "failed to serialize model")
    }
    return data, nil
}

// DeserializeModel deserializes the JSON back into a GovernanceModel.
func DeserializeModel(data []byte) (GovernanceModel, error) {
    var model GovernanceModel
    err := json.Unmarshal(data, &model)
    if err != nil {
        return GovernanceModel{}, errors.Wrap(err, "failed to deserialize model")
    }
    return model, nil
}

// LogModelDetails logs the details of a governance model.
func LogModelDetails(model GovernanceModel) {
    log.Printf("Model Name: %s\nDescription: %s\nDetails: %v\n", model.ModelName, model.Description, model.Specifics)
}
