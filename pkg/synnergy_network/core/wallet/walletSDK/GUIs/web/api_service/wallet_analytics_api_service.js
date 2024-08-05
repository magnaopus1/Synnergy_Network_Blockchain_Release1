// src/services/analyticsApiService.js
import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL;

const apiClient = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Fetch performance metrics
export const getPerformanceMetrics = async () => {
  try {
    const response = await apiClient.get('/api/v1/performance/metrics');
    return response.data;
  } catch (error) {
    console.error('Failed to fetch performance metrics', error);
    throw error;
  }
};

// Log performance metrics
export const logPerformanceMetrics = async (metrics) => {
  try {
    await apiClient.post('/api/v1/performance/metrics', metrics);
  } catch (error) {
    console.error('Failed to log performance metrics', error);
    throw error;
  }
};

// Fetch transaction analytics
export const getTransactionAnalytics = async () => {
  try {
    const response = await apiClient.get('/api/v1/transactions/analytics');
    return response.data;
  } catch (error) {
    console.error('Failed to fetch transaction analytics', error);
    throw error;
  }
};

// Add a new transaction
export const addTransaction = async (transaction) => {
  try {
    await apiClient.post('/api/v1/transactions', transaction);
  } catch (error) {
    console.error('Failed to add transaction', error);
    throw error;
  }
};

// Fetch risk events
export const getRiskEvents = async () => {
  try {
    const response = await apiClient.get('/api/v1/risks');
    return response.data;
  } catch (error) {
    console.error('Failed to fetch risk events', error);
    throw error;
  }
};

// Analyze risks
export const analyzeRisks = async () => {
  try {
    await apiClient.post('/api/v1/risks/analyze');
  } catch (error) {
    console.error('Failed to analyze risks', error);
    throw error;
  }
};

// Log user activity
export const logUserActivity = async (activity) => {
  try {
    await apiClient.post('/api/v1/user/activities', activity);
  } catch (error) {
    console.error('Failed to log user activity', error);
    throw error;
  }
};

// Fetch user activities by user ID
export const getUserActivities = async (userId) => {
  try {
    const response = await apiClient.get(`/api/v1/user/activities/${userId}`);
    return response.data;
  } catch (error) {
    console.error(`Failed to fetch activities for user ${userId}`, error);
    throw error;
  }
};

// Analyze user behavior patterns
export const analyzeUserPatterns = async () => {
  try {
    const response = await apiClient.get('/api/v1/user/patterns');
    return response.data;
  } catch (error) {
    console.error('Failed to analyze user patterns', error);
    throw error;
  }
};
