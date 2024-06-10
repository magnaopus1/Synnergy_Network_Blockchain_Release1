package syn2900

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
)

// Storage interface abstracts the database operations required by handlers.
type Storage interface {
	SaveToken(token InsuranceToken) error
	GetToken(tokenID string) (InsuranceToken, error)
	UpdateToken(token InsuranceToken) error
	DeleteToken(tokenID string) error
	ListActivePolicies() ([]InsuranceToken, error)
	ActivatePolicy(tokenID string) error
	DeactivatePolicy(tokenID string) error
	IssueToken(policy InsurancePolicy) (InsuranceToken, error) // Ensure this is declared

}

// RegisterHandlers sets up the routing for different HTTP endpoints.
func RegisterHandlers(router *mux.Router, store Storage) {
	router.HandleFunc("/tokens", createTokenHandler(store)).Methods("POST")
	router.HandleFunc("/tokens/{tokenId}", getTokenHandler(store)).Methods("GET")
	router.HandleFunc("/tokens/{tokenId}", updateTokenHandler(store)).Methods("PUT")
	router.HandleFunc("/tokens/{tokenId}/activate", activateTokenHandler(store)).Methods("POST")
	router.HandleFunc("/tokens/{tokenId}/deactivate", deactivateTokenHandler(store)).Methods("POST")
	router.HandleFunc("/tokens", listTokensHandler(store)).Methods("GET")
}

func createTokenHandler(store Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var policy InsurancePolicy
		if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		token, err := store.IssueToken(policy)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(token)
	}
}

func getTokenHandler(store Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenID := mux.Vars(r)["tokenId"]
		token, err := store.GetToken(tokenID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		json.NewEncoder(w).Encode(token)
	}
}

func updateTokenHandler(store Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenID := mux.Vars(r)["tokenId"]
		var policy InsurancePolicy
		if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		policy.PolicyID = tokenID // Ensure the policy ID is set correctly
		err := store.UpdateToken(InsuranceToken{TokenID: tokenID, Policy: policy})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

func activateTokenHandler(store Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenID := mux.Vars(r)["tokenId"]
		err := store.ActivatePolicy(tokenID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

func deactivateTokenHandler(store Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenID := mux.Vars(r)["tokenId"]
		err := store.DeactivatePolicy(tokenID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

func listTokensHandler(store Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokens, err := store.ListActivePolicies()
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		json.NewEncoder(w).Encode(tokens)
	}
}

