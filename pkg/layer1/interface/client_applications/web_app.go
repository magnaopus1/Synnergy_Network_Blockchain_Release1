package user_interface

import (
    "net/http"
    "html/template"
    "log"
    "golang.org/x/crypto/scrypt"
    "golang.org/x/crypto/argon2"
)

const (
    Salt = "unique-salt-string"
    KeyLength = 32
)

// WebApp holds the structure for our web application
type WebApp struct {
    Server *http.Server
    Templates *template.Template
}

// NewWebApp initializes and returns a new WebApp instance
func NewWebApp() *WebApp {
    templates := template.Must(template.ParseGlob("templates/*.html"))
    webApp := &WebApp{
        Server: &http.Server{
            Addr: ":8080",
            Handler: nil, // Set this to http.DefaultServeMux or a custom mux
        },
        Templates: templates,
    }
    http.HandleFunc("/", webApp.handleHome)
    http.HandleFunc("/login", webApp.handleLogin)
    http.HandleFunc("/wallet", webApp.handleWallet)
    return webApp
}

// EncryptData encrypts user data using Argon2
func EncryptData(data []byte) []byte {
    salt := []byte(Salt)
    return argon2.IDKey(data, salt, 1, 64*1024, 4, KeyLength)
}

// DecryptData decrypts user data using Scrypt
func DecryptData(data []byte) ([]byte, error) {
    return scrypt.Key(data, []byte(Salt), 16384, 8, 1, KeyLength)
}

// handleHome serves the main page
func (app *WebApp) handleHome(w http.ResponseWriter, r *http.Request) {
    err := app.Templates.ExecuteTemplate(w, "home.html", nil)
    if err != nil {
        http.Error(w, "Error rendering template", http.StatusInternalServerError)
    }
}

// handleLogin handles user logins
func (app *WebApp) handleLogin(w http.ResponseWriter, r *http.Request) {
    // Handle user login logic here
    log.Println("Handling login")
}

// handleWallet handles the wallet interface
func (app *WebApp) handleWallet(w http.ResponseWriter, r *http.Request) {
    // Wallet interaction logic goes here
    log.Println("Wallet page accessed")
}

// Run starts the web server
func (app *WebApp) Run() {
    log.Printf("Starting server on %s\n", app.Server.Addr)
    err := app.Server.ListenAndServe()
    if err != nil {
        log.Fatal("Server failed to start:", err)
    }
}

func main() {
    webApp := NewWebApp()
    webApp.Run()
}
