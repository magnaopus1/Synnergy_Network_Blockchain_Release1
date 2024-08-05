import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL;

const apiClient = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// KYC Verification
export const kycVerification = async (userId) => {
  try {
    await apiClient.post('/api/v1/compliance/kyc', { user_id: userId });
  } catch (error) {
    console.error('Failed to verify KYC', error);
    throw error;
  }
};

// AML Check
export const amlCheck = async (userId) => {
  try {
    await apiClient.post('/api/v1/compliance/aml', { user_id: userId });
  } catch (error) {
    console.error('Failed to perform AML check', error);
    throw error;
  }
};

// Compliance Check
export const complianceCheck = async (userId) => {
  try {
    await apiClient.post('/api/v1/compliance/check', { user_id: userId });
  } catch (error) {
    console.error('Failed to perform compliance check', error);
    throw error;
  }
};

// Log Transaction
export const logTransaction = async (transaction) => {
  try {
    await apiClient.post('/api/v1/compliance/audit/log_transaction', { transaction });
  } catch (error) {
    console.error('Failed to log transaction', error);
    throw error;
  }
};

// Log Access
export const logAccess = async (userId, resource, accessType, allowed) => {
  try {
    await apiClient.post('/api/v1/compliance/audit/log_access', {
      user_id: userId,
      resource,
      access_type: accessType,
      allowed,
    });
  } catch (error) {
    console.error('Failed to log access', error);
    throw error;
  }
};

// Log Compliance Event
export const logComplianceEvent = async (event, details) => {
  try {
    await apiClient.post('/api/v1/compliance/audit/log_event', {
      event,
      details,
    });
  } catch (error) {
    console.error('Failed to log compliance event', error);
    throw error;
  }
};

// Generate Report
export const generateReport = async (startTime, endTime) => {
  try {
    const response = await apiClient.post('/api/v1/compliance/report/generate', {
      start_time: startTime,
      end_time: endTime,
    });
    return response.data.report;
  } catch (error) {
    console.error('Failed to generate report', error);
    throw error;
  }
};

// Submit Report
export const submitReport = async (report) => {
  try {
    await apiClient.post('/api/v1/compliance/report/submit', { report });
  } catch (error) {
    console.error('Failed to submit report', error);
    throw error;
  }
};
