package loan_services

import (
	"errors"
	"math"
	"time"
)

// LoanDetails holds the essential information about a loan.
type LoanDetails struct {
	Principal        float64   // Initial amount of the loan
	AnnualInterest   float64   // Annual interest rate in percentage
	TermMonths       int       // Duration of the loan term in months
	StartDate        time.Time // Start date of the loan
}

// AmortizationSchedule represents a single payment in the schedule.
type AmortizationSchedule struct {
	PaymentNumber int
	Date          time.Time
	PaymentAmount float64
	Interest      float64
	Principal     float64
	Remaining     float64
}

// CalculateMonthlyPayment calculates the monthly payment for a loan using the fixed-rate formula.
func CalculateMonthlyPayment(details LoanDetails) (float64, error) {
	if details.AnnualInterest < 0 || details.TermMonths <= 0 || details.Principal <= 0 {
		return 0, errors.New("invalid loan details provided")
	}
	monthlyInterest := details.AnnualInterest / 12 / 100
	payment := details.Principal * monthlyInterest / (1 - math.Pow(1+monthlyInterest, -float64(details.TermMonths)))
	return payment, nil
}

// GenerateAmortizationSchedule generates the full amortization schedule for the given loan.
func GenerateAmortizationSchedule(details LoanDetails) ([]AmortizationSchedule, error) {
	monthlyPayment, err := CalculateMonthlyPayment(details)
	if err != nil {
		return nil, err
	}

	schedule := make([]AmortizationSchedule, details.TermMonths)
	balance := details.Principal
	for i := 1; i <= details.TermMonths; i++ {
		interest := balance * details.AnnualInterest / 12 / 100
		principal := monthlyPayment - interest
		balance -= principal
		schedule[i-1] = AmortizationSchedule{
			PaymentNumber: i,
			Date:          details.StartDate.AddDate(0, i, 0),
			PaymentAmount: monthlyPayment,
			Interest:      interest,
			Principal:     principal,
			Remaining:     balance,
		}
	}
	return schedule, nil
}

// AdjustLoanForRiskFactors adjusts the interest rate based on risk factors not encapsulated within the original loan details.
func AdjustLoanForRiskFactors(details *LoanDetails, riskFactor float64) {
	details.AnnualInterest += details.AnnualInterest * riskFactor // Adjusting interest rate based on risk
}

// MarshalDetails serializes the LoanDetails into a JSON format.
func MarshalDetails(details LoanDetails) (string, error) {
	data, err := json.Marshal(details)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// UnmarshalDetails deserializes the JSON format into LoanDetails.
func UnmarshalDetails(data string) (LoanDetails, error) {
	var details LoanDetails
	err := json.Unmarshal([]byte(data), &details)
	if err != nil {
		return LoanDetails{}, err
	}
	return details, nil
}
