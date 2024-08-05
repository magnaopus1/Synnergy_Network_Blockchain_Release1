import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'dart:convert';

class WalletNotificationGui extends StatefulWidget {
  @override
  _WalletNotificationGuiState createState() => _WalletNotificationGuiState();
}

class _WalletNotificationGuiState extends State<WalletNotificationGui> {
  final TextEditingController typeController = TextEditingController();
  final TextEditingController descriptionController = TextEditingController();
  final TextEditingController userIDController = TextEditingController();
  final TextEditingController messageTitleController = TextEditingController();
  final TextEditingController messageContentController = TextEditingController();
  final TextEditingController emailEnabledController = TextEditingController();
  final TextEditingController pushEnabledController = TextEditingController();
  final TextEditingController smsEnabledController = TextEditingController();
  final TextEditingController securityAlertsController = TextEditingController();
  final TextEditingController transactionUpdatesController = TextEditingController();
  final TextEditingController performanceMetricsController = TextEditingController();
  final TextEditingController alertIDController = TextEditingController();

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('Wallet Notification Management'),
      ),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: ListView(
          children: [
            TextField(
              controller: typeController,
              decoration: InputDecoration(labelText: 'Alert Type (0: Security, 1: Transaction, 2: System)'),
            ),
            TextField(
              controller: descriptionController,
              decoration: InputDecoration(labelText: 'Alert Description'),
            ),
            ElevatedButton(
              onPressed: handleAddAlert,
              child: Text('Add Alert'),
            ),
            ElevatedButton(
              onPressed: handleListAlerts,
              child: Text('List Alerts'),
            ),
            TextField(
              controller: alertIDController,
              decoration: InputDecoration(labelText: 'Alert ID'),
            ),
            ElevatedButton(
              onPressed: handleHandleAlert,
              child: Text('Handle Alert'),
            ),
            TextField(
              controller: userIDController,
              decoration: InputDecoration(labelText: 'User ID'),
            ),
            TextField(
              controller: messageTitleController,
              decoration: InputDecoration(labelText: 'Message Title'),
            ),
            TextField(
              controller: messageContentController,
              decoration: InputDecoration(labelText: 'Message Content'),
            ),
            ElevatedButton(
              onPressed: handleSendNotification,
              child: Text('Send Notification'),
            ),
            TextField(
              controller: emailEnabledController,
              decoration: InputDecoration(labelText: 'Email Enabled (true/false)'),
            ),
            TextField(
              controller: pushEnabledController,
              decoration: InputDecoration(labelText: 'Push Enabled (true/false)'),
            ),
            TextField(
              controller: smsEnabledController,
              decoration: InputDecoration(labelText: 'SMS Enabled (true/false)'),
            ),
            TextField(
              controller: securityAlertsController,
              decoration: InputDecoration(labelText: 'Security Alerts (true/false)'),
            ),
            TextField(
              controller: transactionUpdatesController,
              decoration: InputDecoration(labelText: 'Transaction Updates (true/false)'),
            ),
            TextField(
              controller: performanceMetricsController,
              decoration: InputDecoration(labelText: 'Performance Metrics (true/false)'),
            ),
            ElevatedButton(
              onPressed: handleUpdateNotificationSettings,
              child: Text('Update Notification Settings'),
            ),
            ElevatedButton(
              onPressed: handleConnectWebSocket,
              child: Text('Connect WebSocket'),
            ),
          ],
        ),
      ),
    );
  }

  Future<void> handleAddAlert() async {
    final response = await http.post(
      Uri.parse('http://your_api_url/api/add_alert'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'type': int.parse(typeController.text),
        'description': descriptionController.text,
      }),
    );

    if (response.statusCode == 200) {
      _showDialog('Add Alert', 'Alert added successfully');
    } else {
      _showDialog('Error', 'Failed to add alert');
    }
  }

  Future<void> handleListAlerts() async {
    final response = await http.get(
      Uri.parse('http://your_api_url/api/list_alerts'),
    );

    if (response.statusCode == 200) {
      final alerts = json.decode(response.body)['data'];
      _showDialog('List Alerts', alerts.toString());
    } else {
      _showDialog('Error', 'Failed to list alerts');
    }
  }

  Future<void> handleHandleAlert() async {
    final response = await http.post(
      Uri.parse('http://your_api_url/api/handle_alert/${alertIDController.text}'),
    );

    if (response.statusCode == 200) {
      _showDialog('Handle Alert', 'Alert handled successfully');
    } else {
      _showDialog('Error', 'Failed to handle alert');
    }
  }

  Future<void> handleSendNotification() async {
    final response = await http.post(
      Uri.parse('http://your_api_url/api/send_notification'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'user_id': userIDController.text,
        'message': {
          'title': messageTitleController.text,
          'content': messageContentController.text,
        },
      }),
    );

    if (response.statusCode == 200) {
      _showDialog('Send Notification', 'Notification sent successfully');
    } else {
      _showDialog('Error', 'Failed to send notification');
    }
  }

  Future<void> handleUpdateNotificationSettings() async {
    final response = await http.post(
      Uri.parse('http://your_api_url/api/update_notification_settings'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'email_enabled': emailEnabledController.text == 'true',
        'push_enabled': pushEnabledController.text == 'true',
        'sms_enabled': smsEnabledController.text == 'true',
        'security_alerts': securityAlertsController.text == 'true',
        'transaction_updates': transactionUpdatesController.text == 'true',
        'performance_metrics': performanceMetricsController.text == 'true',
      }),
    );

    if (response.statusCode == 200) {
      _showDialog('Update Notification Settings', 'Settings updated successfully');
    } else {
      _showDialog('Error', 'Failed to update settings');
    }
  }

  Future<void> handleConnectWebSocket() async {
    final response = await http.get(
      Uri.parse('http://your_api_url/api/connect_websocket'),
    );

    if (response.statusCode == 200) {
      _showDialog('Connect WebSocket', 'WebSocket connection established');
    } else {
      _showDialog('Error', 'Failed to connect to WebSocket');
    }
  }

  void _showDialog(String title, String content) {
    showDialog(
      context: context,
      builder: (BuildContext context) {
        return AlertDialog(
          title: Text(title),
          content: SingleChildScrollView(
            child: ListBody(
              children: <Widget>[
                Text(content),
              ],
            ),
          ),
          actions: <Widget>[
            TextButton(
              child: Text('Close'),
              onPressed: () {
                Navigator.of(context).pop();
              },
            ),
          ],
        );
      },
    );
  }
}
