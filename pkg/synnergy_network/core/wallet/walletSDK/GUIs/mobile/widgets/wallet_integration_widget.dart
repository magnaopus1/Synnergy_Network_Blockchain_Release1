import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'dart:convert';

class WalletIntegrationWidget extends StatefulWidget {
  @override
  _WalletIntegrationWidgetState createState() => _WalletIntegrationWidgetState();
}

class _WalletIntegrationWidgetState extends State<WalletIntegrationWidget> {
  final TextEditingController walletAddressController = TextEditingController();
  final TextEditingController fromAddressController = TextEditingController();
  final TextEditingController toAddressController = TextEditingController();
  final TextEditingController amountController = TextEditingController();
  final TextEditingController privateKeyController = TextEditingController();
  final TextEditingController sourceChainController = TextEditingController();
  final TextEditingController targetChainController = TextEditingController();
  final TextEditingController apiURLController = TextEditingController();

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('Wallet Integration Management'),
      ),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: ListView(
          children: [
            TextField(
              controller: walletAddressController,
              decoration: InputDecoration(labelText: 'Wallet Address'),
            ),
            ElevatedButton(
              onPressed: handleCheckBalance,
              child: Text('Check Balance'),
            ),
            TextField(
              controller: fromAddressController,
              decoration: InputDecoration(labelText: 'From Address'),
            ),
            TextField(
              controller: toAddressController,
              decoration: InputDecoration(labelText: 'To Address'),
            ),
            TextField(
              controller: amountController,
              decoration: InputDecoration(labelText: 'Amount'),
            ),
            TextField(
              controller: privateKeyController,
              decoration: InputDecoration(labelText: 'Private Key'),
            ),
            ElevatedButton(
              onPressed: handleSendTransaction,
              child: Text('Send Transaction'),
            ),
            ElevatedButton(
              onPressed: handleSyncWithBlockchain,
              child: Text('Sync with Blockchain'),
            ),
            TextField(
              controller: sourceChainController,
              decoration: InputDecoration(labelText: 'Source Chain'),
            ),
            TextField(
              controller: targetChainController,
              decoration: InputDecoration(labelText: 'Target Chain'),
            ),
            ElevatedButton(
              onPressed: handleCrossChainTransfer,
              child: Text('Cross-Chain Transfer'),
            ),
            TextField(
              controller: apiURLController,
              decoration: InputDecoration(labelText: 'External API URL'),
            ),
            ElevatedButton(
              onPressed: handleExternalAPISync,
              child: Text('Sync with External API'),
            ),
          ],
        ),
      ),
    );
  }

  Future<void> handleCheckBalance() async {
    final response = await http.get(
      Uri.parse('http://your_api_url/api/check_balance?wallet_address=${walletAddressController.text}'),
    );

    if (response.statusCode == 200) {
      final balance = json.decode(response.body)['data'];
      showDialog(
        context: context,
        builder: (BuildContext context) {
          return AlertDialog(
            title: Text('Wallet Balance'),
            content: SingleChildScrollView(
              child: ListBody(
                children: <Widget>[
                  Text('Balance: $balance'),
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
    } else {
      throw Exception('Failed to check balance');
    }
  }

  Future<void> handleSendTransaction() async {
    final response = await http.post(
      Uri.parse('http://your_api_url/api/send_transaction'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'from': fromAddressController.text,
        'to': toAddressController.text,
        'amount': double.parse(amountController.text),
        'private_key': privateKeyController.text,
      }),
    );

    if (response.statusCode == 200) {
      showDialog(
        context: context,
        builder: (BuildContext context) {
          return AlertDialog(
            title: Text('Transaction Status'),
            content: SingleChildScrollView(
              child: ListBody(
                children: <Widget>[
                  Text('Transaction sent successfully'),
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
    } else {
      throw Exception('Failed to send transaction');
    }
  }

  Future<void> handleSyncWithBlockchain() async {
    final response = await http.post(
      Uri.parse('http://your_api_url/api/sync_blockchain'),
    );

    if (response.statusCode == 200) {
      showDialog(
        context: context,
        builder: (BuildContext context) {
          return AlertDialog(
            title: Text('Blockchain Sync'),
            content: SingleChildScrollView(
              child: ListBody(
                children: <Widget>[
                  Text('Synced with blockchain successfully'),
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
    } else {
      throw Exception('Failed to sync with blockchain');
    }
  }

  Future<void> handleCrossChainTransfer() async {
    final response = await http.post(
      Uri.parse('http://your_api_url/api/cross_chain_transfer'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'source_chain': sourceChainController.text,
        'target_chain': targetChainController.text,
        'from_addr': fromAddressController.text,
        'to_addr': toAddressController.text,
        'amount': double.parse(amountController.text),
      }),
    );

    if (response.statusCode == 200) {
      final txID = json.decode(response.body)['data'];
      showDialog(
        context: context,
        builder: (BuildContext context) {
          return AlertDialog(
            title: Text('Cross-Chain Transfer'),
            content: SingleChildScrollView(
              child: ListBody(
                children: <Widget>[
                  Text('Transaction ID: $txID'),
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
    } else {
      throw Exception('Failed to transfer assets');
    }
  }

  Future<void> handleExternalAPISync() async {
    final response = await http.post(
      Uri.parse('http://your_api_url/api/external_api_sync'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'url': apiURLController.text,
      }),
    );

    if (response.statusCode == 200) {
      showDialog(
        context: context,
        builder: (BuildContext context) {
          return AlertDialog(
            title: Text('External API Sync'),
            content: SingleChildScrollView(
              child: ListBody(
                children: <Widget>[
                  Text('Synced with external API successfully'),
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
    } else {
      throw Exception('Failed to sync with external API');
    }
  }
}
