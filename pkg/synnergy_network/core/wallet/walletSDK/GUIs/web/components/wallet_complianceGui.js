import React, { useState } from 'react';
import { 
  kycVerification, 
  amlCheck, 
  complianceCheck, 
  logTransaction, 
  logAccess, 
  logComplianceEvent, 
  generateReport, 
  submitReport 
} from '../api_service/wallet_compliance_api_service';

const WalletComplianceGui = () => {
  const [userId, setUserId] = useState('');
  const [transaction, setTransaction] = useState({});
  const [resource, setResource] = useState('');
  const [accessType, setAccessType] = useState('');
  const [allowed, setAllowed] = useState(false);
  const [event, setEvent] = useState('');
  const [details, setDetails] = useState('');
  const [startTime, setStartTime] = useState('');
  const [endTime, setEndTime] = useState('');
  const [report, setReport] = useState(null);

  const handleKycVerification = async () => {
    try {
      await kycVerification(userId);
      alert('KYC Verification successful');
    } catch (error) {
      alert('KYC Verification failed');
    }
  };

  const handleAmlCheck = async () => {
    try {
      await amlCheck(userId);
      alert('AML Check successful');
    } catch (error) {
      alert('AML Check failed');
    }
  };

  const handleComplianceCheck = async () => {
    try {
      await complianceCheck(userId);
      alert('Compliance Check successful');
    } catch (error) {
      alert('Compliance Check failed');
    }
  };

  const handleLogTransaction = async () => {
    try {
      await logTransaction(transaction);
      alert('Transaction logged successfully');
    } catch (error) {
      alert('Failed to log transaction');
    }
  };

  const handleLogAccess = async () => {
    try {
      await logAccess(userId, resource, accessType, allowed);
      alert('Access logged successfully');
    } catch (error) {
      alert('Failed to log access');
    }
  };

  const handleLogComplianceEvent = async () => {
    try {
      await logComplianceEvent(event, details);
      alert('Compliance event logged successfully');
    } catch (error) {
      alert('Failed to log compliance event');
    }
  };

  const handleGenerateReport = async () => {
    try {
      const generatedReport = await generateReport(startTime, endTime);
      setReport(generatedReport);
      alert('Report generated successfully');
    } catch (error) {
      alert('Failed to generate report');
    }
  };

  const handleSubmitReport = async () => {
    try {
      await submitReport(report);
      alert('Report submitted successfully');
    } catch (error) {
      alert('Failed to submit report');
    }
  };

  return (
    <div>
      <h1>Wallet Compliance Management</h1>
      <div>
        <label>User ID:</label>
        <input type="text" value={userId} onChange={(e) => setUserId(e.target.value)} />
        <button onClick={handleKycVerification}>KYC Verification</button>
        <button onClick={handleAmlCheck}>AML Check</button>
        <button onClick={handleComplianceCheck}>Compliance Check</button>
      </div>
      <div>
        <label>Transaction Data:</label>
        <textarea value={JSON.stringify(transaction)} onChange={(e) => setTransaction(JSON.parse(e.target.value))} />
        <button onClick={handleLogTransaction}>Log Transaction</button>
      </div>
      <div>
        <label>Resource:</label>
        <input type="text" value={resource} onChange={(e) => setResource(e.target.value)} />
        <label>Access Type:</label>
        <input type="text" value={accessType} onChange={(e) => setAccessType(e.target.value)} />
        <label>Allowed:</label>
        <input type="checkbox" checked={allowed} onChange={(e) => setAllowed(e.target.checked)} />
        <button onClick={handleLogAccess}>Log Access</button>
      </div>
      <div>
        <label>Event:</label>
        <input type="text" value={event} onChange={(e) => setEvent(e.target.value)} />
        <label>Details:</label>
        <input type="text" value={details} onChange={(e) => setDetails(e.target.value)} />
        <button onClick={handleLogComplianceEvent}>Log Compliance Event</button>
      </div>
      <div>
        <label>Start Time (YYYY-MM-DD):</label>
        <input type="date" value={startTime} onChange={(e) => setStartTime(e.target.value)} />
        <label>End Time (YYYY-MM-DD):</label>
        <input type="date" value={endTime} onChange={(e) => setEndTime(e.target.value)} />
        <button onClick={handleGenerateReport}>Generate Report</button>
      </div>
      <div>
        {report && (
          <div>
            <h2>Generated Report</h2>
            <pre>{JSON.stringify(report, null, 2)}</pre>
            <button onClick={handleSubmitReport}>Submit Report</button>
          </div>
        )}
      </div>
    </div>
  );
};

export default WalletComplianceGui;
