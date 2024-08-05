import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'dart:convert';

class WalletAnalyticsGui extends StatefulWidget {
  @override
  _WalletAnalyticsGuiState createState() => _WalletAnalyticsGuiState();
}

class _WalletAnalyticsGuiState extends State<WalletAnalyticsGui> {
  Map<String, dynamic> performanceMetrics = {};
  Map<String, dynamic> transactionAnalytics = {};
  List<dynamic> riskEvents = [];
  List<dynamic> userActivities = [];
  List<dynamic> userPatterns = [];

  @override
  void initState() {
    super.initState();
    fetchPerformanceMetrics();
    fetchTransactionAnalytics();
    fetchRiskEvents();
    fetchUserActivities("user_id");
    fetchUserPatterns();
  }

  Future<void> fetchPerformanceMetrics() async {
    final response = await http.get(Uri.parse('http://your_api_url/api/v1/performance/metrics'));
    if (response.statusCode == 200) {
      setState(() {
        performanceMetrics = json.decode(response.body)['data'];
      });
    } else {
      throw Exception('Failed to load performance metrics');
    }
  }

  Future<void> fetchTransactionAnalytics() async {
    final response = await http.get(Uri.parse('http://your_api_url/api/v1/transactions/analytics'));
    if (response.statusCode == 200) {
      setState(() {
        transactionAnalytics = json.decode(response.body)['data'];
      });
    } else {
      throw Exception('Failed to load transaction analytics');
    }
  }

  Future<void> fetchRiskEvents() async {
    final response = await http.get(Uri.parse('http://your_api_url/api/v1/risks'));
    if (response.statusCode == 200) {
      setState(() {
        riskEvents = json.decode(response.body)['data'];
      });
    } else {
      throw Exception('Failed to load risk events');
    }
  }

  Future<void> fetchUserActivities(String userId) async {
    final response = await http.get(Uri.parse('http://your_api_url/api/v1/user/activities/$userId'));
    if (response.statusCode == 200) {
      setState(() {
        userActivities = json.decode(response.body)['data'];
      });
    } else {
      throw Exception('Failed to load user activities');
    }
  }

  Future<void> fetchUserPatterns() async {
    final response = await http.get(Uri.parse('http://your_api_url/api/v1/user/patterns'));
    if (response.statusCode == 200) {
      setState(() {
        userPatterns = json.decode(response.body)['data'];
      });
    } else {
      throw Exception('Failed to load user patterns');
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('Wallet Analytics'),
      ),
      body: SingleChildScrollView(
        child: Padding(
          padding: const EdgeInsets.all(16.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text('Performance Metrics', style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
              if (performanceMetrics.isNotEmpty) ...[
                Text('Transaction Processing Times: ${performanceMetrics['TransactionProcessingTimes']}'),
                Text('Resource Usage: ${performanceMetrics['ResourceUsage']}'),
              ] else
                CircularProgressIndicator(),
              SizedBox(height: 20),
              Text('Transaction Analytics', style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
              if (transactionAnalytics.isNotEmpty) ...[
                Text('Volume: ${transactionAnalytics['volume']}'),
                Text('Average Fee: ${transactionAnalytics['average_fee']}'),
                Text('Anomalies: ${transactionAnalytics['anomalies']}'),
              ] else
                CircularProgressIndicator(),
              SizedBox(height: 20),
              Text('Risk Events', style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
              if (riskEvents.isNotEmpty) ...[
                for (var event in riskEvents) Text('Event: $event'),
              ] else
                CircularProgressIndicator(),
              SizedBox(height: 20),
              Text('User Activities', style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
              if (userActivities.isNotEmpty) ...[
                for (var activity in userActivities) Text('Activity: $activity'),
              ] else
                CircularProgressIndicator(),
              SizedBox(height: 20),
              Text('User Patterns', style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
              if (userPatterns.isNotEmpty) ...[
                for (var pattern in userPatterns) Text('Pattern: $pattern'),
              ] else
                CircularProgressIndicator(),
            ],
          ),
        ),
      ),
    );
  }
}
