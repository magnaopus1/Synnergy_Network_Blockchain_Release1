import React, { useState, useEffect } from 'react';
import {
  getPerformanceMetrics,
  getTransactionAnalytics,
  getRiskEvents,
  getUserActivities,
  analyzeUserPatterns,
} from './api_service/wallet_analytics_api_service';
import './wallet_analyticsGui.css'; // Assume you have some basic styling

const WalletAnalyticsGui = () => {
  const [performanceMetrics, setPerformanceMetrics] = useState({});
  const [transactionAnalytics, setTransactionAnalytics] = useState({});
  const [riskEvents, setRiskEvents] = useState([]);
  const [userActivities, setUserActivities] = useState([]);
  const [userPatterns, setUserPatterns] = useState([]);
  const [userId, setUserId] = useState('');

  useEffect(() => {
    fetchPerformanceMetrics();
    fetchTransactionAnalytics();
    fetchRiskEvents();
    fetchUserPatterns();
  }, []);

  const fetchPerformanceMetrics = async () => {
    try {
      const data = await getPerformanceMetrics();
      setPerformanceMetrics(data);
    } catch (error) {
      console.error('Error fetching performance metrics:', error);
    }
  };

  const fetchTransactionAnalytics = async () => {
    try {
      const data = await getTransactionAnalytics();
      setTransactionAnalytics(data);
    } catch (error) {
      console.error('Error fetching transaction analytics:', error);
    }
  };

  const fetchRiskEvents = async () => {
    try {
      const data = await getRiskEvents();
      setRiskEvents(data);
    } catch (error) {
      console.error('Error fetching risk events:', error);
    }
  };

  const fetchUserActivities = async () => {
    if (!userId) return;
    try {
      const data = await getUserActivities(userId);
      setUserActivities(data);
    } catch (error) {
      console.error(`Error fetching activities for user ${userId}:`, error);
    }
  };

  const fetchUserPatterns = async () => {
    try {
      const data = await analyzeUserPatterns();
      setUserPatterns(data);
    } catch (error) {
      console.error('Error analyzing user patterns:', error);
    }
  };

  return (
    <div className="wallet-analytics">
      <h1>Wallet Analytics</h1>
      
      <section className="performance-metrics">
        <h2>Performance Metrics</h2>
        {performanceMetrics ? (
          <div>
            <p>Transaction Processing Times: {performanceMetrics.transactionProcessingTimes}</p>
            <p>Resource Usage: {performanceMetrics.resourceUsage}</p>
          </div>
        ) : (
          <p>Loading...</p>
        )}
      </section>

      <section className="transaction-analytics">
        <h2>Transaction Analytics</h2>
        {transactionAnalytics ? (
          <div>
            <p>Volume: {transactionAnalytics.volume}</p>
            <p>Average Fee: {transactionAnalytics.average_fee}</p>
            <p>Anomalies: {transactionAnalytics.anomalies}</p>
          </div>
        ) : (
          <p>Loading...</p>
        )}
      </section>

      <section className="risk-events">
        <h2>Risk Events</h2>
        {riskEvents.length > 0 ? (
          <ul>
            {riskEvents.map((event, index) => (
              <li key={index}>{event}</li>
            ))}
          </ul>
        ) : (
          <p>Loading...</p>
        )}
      </section>

      <section className="user-activities">
        <h2>User Activities</h2>
        <input
          type="text"
          placeholder="Enter User ID"
          value={userId}
          onChange={(e) => setUserId(e.target.value)}
        />
        <button onClick={fetchUserActivities}>Fetch User Activities</button>
        {userActivities.length > 0 ? (
          <ul>
            {userActivities.map((activity, index) => (
              <li key={index}>{activity}</li>
            ))}
          </ul>
        ) : (
          <p>Loading...</p>
        )}
      </section>

      <section className="user-patterns">
        <h2>User Patterns</h2>
        {userPatterns.length > 0 ? (
          <ul>
            {userPatterns.map((pattern, index) => (
              <li key={index}>{pattern}</li>
            ))}
          </ul>
        ) : (
          <p>Loading...</p>
        )}
      </section>
    </div>
  );
};

export default WalletAnalyticsGui;
