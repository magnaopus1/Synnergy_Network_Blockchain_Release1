package fraud_detection_and_risk_management

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
)

const (
	testDataSourceName = "user=testuser dbname=testdb sslmode=disable"
)

func setupTestDB(t *testing.T) *sql.DB {
	db, err := sql.Open("postgres", testDataSourceName)
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS threat_intel (
			ip VARCHAR(15) PRIMARY KEY,
			threat_level VARCHAR(10),
			timestamp TIMESTAMP
		)`)
	if err != nil {
		t.Fatalf("Failed to create test table: %v", err)
	}

	return db
}

func teardownTestDB(t *testing.T, db *sql.DB) {
	_, err := db.Exec("DROP TABLE IF EXISTS threat_intel")
	if err != nil {
		t.Fatalf("Failed to drop test table: %v", err)
	}
	db.Close()
}

func TestFetchThreatIntel(t *testing.T) {
	db := setupTestDB(t)
	defer teardownTestDB(t, db)

	ti := &ThreatIntelligence{
		db:                 db,
		threatIntelSources: []string{"http://example.com/intel"},
		alertRecipients:    []string{"admin@example.com"},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"IP": "192.168.1.1", "ThreatLevel": "high", "Timestamp": "2023-01-01T00:00:00Z"}]`))
	}))
	defer ts.Close()

	ti.threatIntelSources = []string{ts.URL}
	ti.FetchThreatIntel()
	time.Sleep(1 * time.Second) // Give some time for goroutines to finish

	var threatLevel string
	err := db.QueryRow("SELECT threat_level FROM threat_intel WHERE ip = $1", "192.168.1.1").Scan(&threatLevel)
	if err != nil {
		t.Fatalf("Failed to fetch threat intel from database: %v", err)
	}

	assert.Equal(t, "high", threatLevel)
}

func TestAnalyzeTransaction(t *testing.T) {
	db := setupTestDB(t)
	defer teardownTestDB(t, db)

	_, err := db.Exec("INSERT INTO threat_intel (ip, threat_level, timestamp) VALUES ($1, $2, $3)",
		"192.168.1.1", "high", time.Now())
	if err != nil {
		t.Fatalf("Failed to insert test data: %v", err)
	}

	ti := &ThreatIntelligence{
		db:                 db,
		threatIntelSources: []string{},
		alertRecipients:    []string{"admin@example.com"},
	}

	transaction := Transaction{
		ID:     "tx123",
		UserID: "192.168.1.1",
	}

	err = ti.AnalyzeTransaction(transaction)
	assert.NoError(t, err)
}

func TestServeThreatIntelDashboard(t *testing.T) {
	db := setupTestDB(t)
	defer teardownTestDB(t, db)

	_, err := db.Exec("INSERT INTO threat_intel (ip, threat_level, timestamp) VALUES ($1, $2, $3)",
		"192.168.1.1", "high", time.Now())
	if err != nil {
		t.Fatalf("Failed to insert test data: %v", err)
	}

	ti := &ThreatIntelligence{
		db:                 db,
		threatIntelSources: []string{},
		alertRecipients:    []string{"admin@example.com"},
	}

	req, err := http.NewRequest("GET", "/threat_intel_dashboard", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(ti.handleThreatIntelDashboard)
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), `"ip":"192.168.1.1"`)
	assert.Contains(t, rr.Body.String(), `"threat_level":"high"`)
}

func TestGetThreatIntelData(t *testing.T) {
	db := setupTestDB(t)
	defer teardownTestDB(t, db)

	_, err := db.Exec("INSERT INTO threat_intel (ip, threat_level, timestamp) VALUES ($1, $2, $3)",
		"192.168.1.1", "high", time.Now())
	if err != nil {
		t.Fatalf("Failed to insert test data: %v", err)
	}

	ti := &ThreatIntelligence{
		db:                 db,
		threatIntelSources: []string{},
		alertRecipients:    []string{"admin@example.com"},
	}

	intelData, err := ti.GetThreatIntelData()
	assert.NoError(t, err)
	assert.Equal(t, 1, len(intelData))
	assert.Equal(t, "192.168.1.1", intelData[0].IP)
	assert.Equal(t, "high", intelData[0].ThreatLevel)
}

func TestServeComprehensiveThreatIntelDashboard(t *testing.T) {
	db := setupTestDB(t)
	defer teardownTestDB(t, db)

	_, err := db.Exec("INSERT INTO threat_intel (ip, threat_level, timestamp) VALUES ($1, $2, $3)",
		"192.168.1.1", "high", time.Now())
	if err != nil {
		t.Fatalf("Failed to insert test data: %v", err)
	}

	ti := &ThreatIntelligence{
		db:                 db,
		threatIntelSources: []string{},
		alertRecipients:    []string{"admin@example.com"},
	}

	req, err := http.NewRequest("GET", "/comprehensive_threat_intel_dashboard", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(ti.handleComprehensiveThreatIntelDashboard)
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), `"ip":"192.168.1.1"`)
	assert.Contains(t, rr.Body.String(), `"threat_level":"high"`)
}
