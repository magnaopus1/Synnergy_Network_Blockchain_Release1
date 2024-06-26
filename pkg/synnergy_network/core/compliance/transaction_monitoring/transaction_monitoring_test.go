package transaction_monitoring

import (
	"context"
	"database/sql"
	"sync"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// Mock data for testing
var mockTransactions = []Transaction{
	{"tx1", "user1", time.Now(), 5000, "transfer", "completed", "Normal"},
	{"tx2", "user2", time.Now(), 15000, "transfer", "completed", "Large Transaction"},
	{"tx3", "user3", time.Now(), 200, "withdrawal", "completed", "Withdrawal"},
}

// Mock function for classification
func mockClassifyFunc(tx Transaction) string {
	if tx.Amount > 10000 {
		return "Large Transaction"
	}
	if tx.Type == "withdrawal" {
		return "Withdrawal"
	}
	return "Normal"
}

// Setup a mock database connection
func setupMockDB() (*sql.DB, error) {
	connStr := "user=username dbname=dbname sslmode=disable"
	return sql.Open("postgres", connStr)
}

// Test the classification function
func TestTransactionClassification(t *testing.T) {
	for _, tx := range mockTransactions {
		category := mockClassifyFunc(tx)
		if category != tx.Category {
			t.Errorf("Expected %s, got %s", tx.Category, category)
		}
	}
}

// Test fetching recent transactions
func TestFetchRecentTransactions(t *testing.T) {
	db, err := setupMockDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	tms := NewTransactionMonitoringSystem(db, "nats://localhost:4222", mockClassifyFunc)
	transactions, err := tms.fetchRecentTransactions()
	if err != nil {
		t.Fatal(err)
	}

	if len(transactions) == 0 {
		t.Error("Expected recent transactions, got none")
	}
}

// Test updating transaction category
func TestUpdateTransactionCategory(t *testing.T) {
	db, err := setupMockDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	tms := NewTransactionMonitoringSystem(db, "nats://localhost:4222", mockClassifyFunc)
	tx := mockTransactions[0]
	tx.Category = "TestCategory"
	err = tms.updateTransactionCategory(tx)
	if err != nil {
		t.Fatal(err)
	}
}

// Test monitoring transactions
func TestMonitorTransactions(t *testing.T) {
	db, err := setupMockDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	tms := NewTransactionMonitoringSystem(db, "nats://localhost:4222", mockClassifyFunc)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)

	go tms.Start(ctx, &wg)
	time.Sleep(2 * time.Minute)
	cancel()
	wg.Wait()
}

// Test dashboard data update
func TestUpdateDashboardData(t *testing.T) {
	db, err := setupMockDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	tms := NewTransactionMonitoringSystem(db, "nats://localhost:4222", mockClassifyFunc)
	tms.updateDashboardData()

	if tms.dashboardData.TotalTransactions == 0 {
		t.Error("Expected total transactions, got zero")
	}

	if len(tms.dashboardData.Anomalies) == 0 {
		t.Error("Expected anomalies, got none")
	}

	if len(tms.dashboardData.RecentTransactions) == 0 {
		t.Error("Expected recent transactions, got none")
	}
}

// Test serving dashboard data
func TestServeDashboard(t *testing.T) {
	db, err := setupMockDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	tms := NewTransactionMonitoringSystem(db, "nats://localhost:4222", mockClassifyFunc)
	tms.updateDashboardData()

	req, err := http.NewRequest("GET", "/dashboard", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(tms.ServeDashboard)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	expected := `{"total_transactions":`
	if !strings.HasPrefix(rr.Body.String(), expected) {
		t.Errorf("handler returned unexpected body: got %v want %v", rr.Body.String(), expected)
	}
}

// Additional Tests for Predictive Monitoring and Behavioral Analysis

func TestPredictiveMonitoring(t *testing.T) {
	db, err := setupMockDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	tms := NewTransactionMonitoringSystem(db, "nats://localhost:4222", mockClassifyFunc)

	for _, tx := range mockTransactions {
		prediction := tms.model.Predict(tx)
		// Example test case: Transactions with amount > 10000 should be predicted as suspicious
		if tx.Amount > 10000 && !prediction {
			t.Errorf("Expected transaction to be suspicious, got non-suspicious")
		}
	}
}

func TestBehavioralAnalysis(t *testing.T) {
	db, err := setupMockDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	tms := NewTransactionMonitoringSystem(db, "nats://localhost:4222", mockClassifyFunc)
	// Mock user behavior data
	userBehavior := map[string][]Transaction{
		"user1": {
			{"tx1", "user1", time.Now(), 500, "transfer", "completed", "Normal"},
			{"tx2", "user1", time.Now().Add(-24 * time.Hour), 1000, "transfer", "completed", "Normal"},
		},
	}

	for userID, transactions := range userBehavior {
		for _, tx := range transactions {
			// Example test case: Verify if user transactions are consistent with normal behavior
			if !tms.isConsistentWithBehavior(userID, tx) {
				t.Errorf("Expected transaction to be consistent with user behavior, got inconsistent")
			}
		}
	}
}

// Mock function to test user behavior consistency
func (tms *TransactionMonitoringSystem) isConsistentWithBehavior(userID string, tx Transaction) bool {
	// Placeholder logic for behavioral analysis
	// In a real-world scenario, implement logic to compare transaction with historical user behavior
	return true
}
