package wallet_displayApi

import (
	"encoding/json"
	"net/http"
	"synnergy_network/core/wallet/display"
	"synnergy_network/utils/logger"

	"github.com/gorilla/mux"
)

var log *logger.Logger

func init() {
	var err error
	log, err = logger.NewLogger("wallet_displayApi.log")
	if err != nil {
		panic("Failed to initialize logger: " + err.Error())
	}
}

// APIResponse is a standard response structure for the APIs
type APIResponse struct {
	Status  string      `json:"status"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

// HandleARDisplay handles the AR display request for a wallet
func HandleARDisplay(w http.ResponseWriter, r *http.Request) {
	walletID := r.URL.Query().Get("wallet_id")
	if walletID == "" {
		respondWithJSON(w, http.StatusBadRequest, APIResponse{Status: "error", Message: "Wallet ID is required"})
		return
	}

	data, err := display.HandleWalletARDisplay(walletID)
	if err != nil {
		log.Error("Failed to handle AR display: ", err)
		respondWithJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Message: "Failed to handle AR display"})
		return
	}

	respondWithJSON(w, http.StatusOK, APIResponse{Status: "success", Data: data})
}

// HandleThemeCustomization handles theme customization requests
func HandleThemeCustomization(w http.ResponseWriter, r *http.Request) {
	var requestData display.Theme
	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		log.Error("Invalid request data: ", err)
		respondWithJSON(w, http.StatusBadRequest, APIResponse{Status: "error", Message: "Invalid request data"})
		return
	}

	themeMgr := display.NewThemeManager("themes.json")
	if err := themeMgr.LoadThemes(); err != nil {
		log.Error("Failed to load themes: ", err)
		respondWithJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Message: "Failed to load themes"})
		return
	}

	if err := themeMgr.CustomizeTheme(requestData.Name, requestData); err != nil {
		log.Error("Failed to customize theme: ", err)
		respondWithJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Message: "Failed to customize theme"})
		return
	}

	if err := themeMgr.SaveThemes(); err != nil {
		log.Error("Failed to save themes: ", err)
		respondWithJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Message: "Failed to save themes"})
		return
	}

	respondWithJSON(w, http.StatusOK, APIResponse{Status: "success", Message: "Theme customized successfully"})
}

// HandleVoiceCommand handles voice command settings requests
func HandleVoiceCommand(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		settings := display.GetCurrentVoiceSettings()
		respondWithJSON(w, http.StatusOK, APIResponse{Status: "success", Data: settings})

	case "POST":
		var requestData display.VoiceCommandInterface
		if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
			log.Error("Invalid request data: ", err)
			respondWithJSON(w, http.StatusBadRequest, APIResponse{Status: "error", Message: "Invalid request data"})
			return
		}

		if err := display.UpdateSettings(requestData.Enabled, requestData.Locale); err != nil {
			log.Error("Failed to update voice command settings: ", err)
			respondWithJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Message: "Failed to update voice command settings"})
			return
		}
		respondWithJSON(w, http.StatusNoContent, APIResponse{Status: "success", Message: "Voice command settings updated successfully"})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// HandleWidgetManagement handles widget management requests
func HandleWidgetManagement(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		widgets := display.ListWidgets()
		respondWithJSON(w, http.StatusOK, APIResponse{Status: "success", Data: widgets})

	case "POST":
		var requestData struct {
			ID     string `json:"id"`
			Widget fyne.CanvasObject `json:"widget"`
		}
		if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
			log.Error("Invalid request data: ", err)
			respondWithJSON(w, http.StatusBadRequest, APIResponse{Status: "error", Message: "Invalid request data"})
			return
		}

		if err := display.AddWidget(requestData.ID, requestData.Widget); err != nil {
			log.Error("Failed to add widget: ", err)
			respondWithJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Message: "Failed to add widget"})
			return
		}

		respondWithJSON(w, http.StatusCreated, APIResponse{Status: "success", Message: "Widget added successfully"})

	case "DELETE":
		var requestData struct {
			ID string `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
			log.Error("Invalid request data: ", err)
			respondWithJSON(w, http.StatusBadRequest, APIResponse{Status: "error", Message: "Invalid request data"})
			return
		}

		if err := display.RemoveWidget(requestData.ID); err != nil {
			log.Error("Failed to remove widget: ", err)
			respondWithJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Message: "Failed to remove widget"})
			return
		}

		respondWithJSON(w, http.StatusNoContent, APIResponse{Status: "success", Message: "Widget removed successfully"})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// HandleWalletNaming handles wallet naming requests
func HandleWalletNaming(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		alias := r.URL.Query().Get("alias")
		if alias == "" {
			respondWithJSON(w, http.StatusBadRequest, APIResponse{Status: "error", Message: "Alias is required"})
			return
		}

		walletNamingService, err := display.NewWalletNamingService("wallet_aliases.db")
		if err != nil {
			log.Error("Failed to initialize wallet naming service: ", err)
			respondWithJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Message: "Failed to initialize wallet naming service"})
			return
		}

		address, err := walletNamingService.ResolveAlias(alias)
		if err != nil {
			log.Error("Failed to resolve alias: ", err)
			respondWithJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Message: "Failed to resolve alias"})
			return
		}

		respondWithJSON(w, http.StatusOK, APIResponse{Status: "success", Data: address})

	case "POST":
		var requestData struct {
			Alias   string `json:"alias"`
			Address string `json:"address"`
		}
		if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
			log.Error("Invalid request data: ", err)
			respondWithJSON(w, http.StatusBadRequest, APIResponse{Status: "error", Message: "Invalid request data"})
			return
		}

		walletNamingService, err := display.NewWalletNamingService("wallet_aliases.db")
		if err != nil {
			log.Error("Failed to initialize wallet naming service: ", err)
			respondWithJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Message: "Failed to initialize wallet naming service"})
			return
		}

		if err := walletNamingService.RegisterAlias(requestData.Alias, requestData.Address); err != nil {
			log.Error("Failed to register alias: ", err)
			respondWithJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Message: "Failed to register alias"})
			return
		}

		respondWithJSON(w, http.StatusCreated, APIResponse{Status: "success", Message: "Alias registered successfully"})

	case "DELETE":
		var requestData struct {
			Alias string `json:"alias"`
		}
		if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
			log.Error("Invalid request data: ", err)
			respondWithJSON(w, http.StatusBadRequest, APIResponse{Status: "error", Message: "Invalid request data"})
			return
		}

		walletNamingService, err := display.NewWalletNamingService("wallet_aliases.db")
		if err != nil {
			log.Error("Failed to initialize wallet naming service: ", err)
			respondWithJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Message: "Failed to initialize wallet naming service"})
			return
		}

		if err := walletNamingService.RemoveAlias(requestData.Alias); err != nil {
			log.Error("Failed to remove alias: ", err)
			respondWithJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Message: "Failed to remove alias"})
			return
		}

		respondWithJSON(w, http.StatusNoContent, APIResponse{Status: "success", Message: "Alias removed successfully"})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// Set up the API routes
func SetupRoutes(router *mux.Router) {
	router.HandleFunc("/api/ar_display", HandleARDisplay).Methods("GET")
	router.HandleFunc("/api/theme_customization", HandleThemeCustomization).Methods("POST")
	router.HandleFunc("/api/voice_command", HandleVoiceCommand).Methods("GET", "POST")
	router.HandleFunc("/api/widget_management", HandleWidgetManagement).Methods("GET", "POST", "DELETE")
	router.HandleFunc("/api/wallet_naming", HandleWalletNaming).Methods("GET", "POST", "DELETE")
}

// Helper function to respond with JSON
func respondWithJSON(w http.ResponseWriter, status int, payload APIResponse) {
	response, err := json.Marshal(payload)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("HTTP 500: Internal Server Error"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(response)
}
