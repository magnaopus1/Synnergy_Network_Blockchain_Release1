type CollateralAudit interface{
	InitializeAudit
	PerformAudit
	analyzeCompliance
	generateAuditReport
	ViewAuditReport
	ResolveIssues
}

type CollateralLiquidation interface{
	InitializeLiquidation
	PerformLiquidation
	validateCollateralValue
	executeLiquidationProcess
	generateLiquidationReport
	ViewLiquidationReport
	ResolveLiquidationIssues
	InitializeLiquidation
	PerformLiquidation


}

type CollateralMonitoring interface{
	InitializeMonitoring
	PerformMonitoring
	checkForNotifications
	ViewMonitoringReport
	ResolveMonitoringIssues
	
}

type CollateralOption interface{
	InitializeCollateral
	isValidCollateralType
	UpdateCollateralValue
	MonitorCollateral
	fetchUpdatedCollateralValue
	checkForNotifications
	ViewCollateralReport
	ResolveCollateralIssues

}

type CollateralReport interface{
	InitializeReport
	PerformReporting
	generateReportContent
	performComplianceChecks
	provideRecommendations
	ViewReport
	ResolveReportIssues
}

type CollateralSecuring interface{
	InitializeSecuring
	PerformSecuring
	validateCollateral
	secureCollateral
	generateSecuringReport
	ViewSecuringReport
	ResolveSecuringIssues
}

type Collateral interface{
	InitializeCollateral
	isValidCollateralType
	UpdateCollateralValue
	MonitorCollateral
	fetchUpdatedCollateralValue
	checkForNotifications
	ViewCollateralReport
	ResolveCollateralIssues

}

type CollateralValuation interface{
	InitializeValuation
	PerformValuation
	validateCollateral
	performAIValuation
	generateValuationReport
	ViewValuationReport
	ResolveValuationIssues
}

type ComplianceAuditor interface{
	NewComplianceAuditor
	LogAction
	GetAuditLogs
	EncryptAuditLog
	DecryptAuditLog
	RegularAudit
	GenerateAuditReport
	VerifyAuditIntegrity
}

type ComplianceMonitoring interface{
	NewComplianceMonitoring
	GenerateReport
	GetReports
	EncryptComplianceReport
	DecryptComplianceReport
	VerifyCompliance
	MonitorCompliance
}

type ComplianceTraining interface{
	NewComplianceTraining
	CreateModule
	UpdateModule
	DeleteModule
	GetModule
	ListModules
	RecordCompletion
	GetTrainingRecords
	ExportTrainingData
	ImportTrainingData

}

type ComplianceVerification interface{
	NewComplianceVerification
	SubmitRequest
	ProcessRequest
	GetRequest
	GetResponse
	EncryptVerificationRequest
	DecryptVerificationRequest
	EncryptVerificationResponse
	DecryptVerificationResponse
}

type KYCAMLIntegration interface{
	SubmitRequest
	ProcessRequest
	GetRequest
	GetResponse
	EncryptKYCAMLRequest
	DecryptKYCAMLRequest
	EncryptKYCAMLResponse
	DecryptKYCAMLResponse
}

type LegalCompliance interface{
	NewLegalCompliance
	SubmitRequest
	ProcessRequest
	GetRequest
	GetResponse
	EncryptLegalComplianceRequest
	DecryptLegalComplianceRequest
	EncryptLegalComplianceResponse
	DecryptLegalComplianceResponse

}

type RegulatoryReporting interface{
	NewRegulatoryReporting
	CreateReport
	SubmitReport
	ReviewReport
	EncryptReport
	DecryptReport

}

type AlternativeCreditData interface{
	Validate
	EncryptData
	DecryptData
	SaveToBlockchain
	RetrieveAlternativeCreditData
	UpdateAlternativeCreditData
}

type BehavioralAnalytics interface{
	NewBehavioralAnalytics
	AnalyzeBehavior
	fetchTransactionHistory
	identifyPaymentPatterns
	calculateRiskProfile
	UpdateRiskProfile
	GenerateReport
}

type CreditScore interface{
	UpdateCreditScore
	GetCreditScore
	MonitorCreditScores
	saveCreditScore
	GenerateCreditReport
	
}