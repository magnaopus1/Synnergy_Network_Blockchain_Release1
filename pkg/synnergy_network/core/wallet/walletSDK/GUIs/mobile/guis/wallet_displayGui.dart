import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'dart:convert';

class WalletDisplayGui extends StatefulWidget {
  @override
  _WalletDisplayGuiState createState() => _WalletDisplayGuiState();
}

class _WalletDisplayGuiState extends State<WalletDisplayGui> {
  final TextEditingController walletIdController = TextEditingController();
  final TextEditingController themeNameController = TextEditingController();
  final TextEditingController aliasController = TextEditingController();
  final TextEditingController addressController = TextEditingController();
  bool voiceCommandEnabled = false;
  String voiceCommandLocale = 'en-US';

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('Wallet Display Management'),
      ),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: ListView(
          children: [
            TextField(
              controller: walletIdController,
              decoration: InputDecoration(labelText: 'Wallet ID'),
            ),
            ElevatedButton(
              onPressed: handleARDisplay,
              child: Text('Handle AR Display'),
            ),
            TextField(
              controller: themeNameController,
              decoration: InputDecoration(labelText: 'Theme Name'),
            ),
            ElevatedButton(
              onPressed: handleThemeCustomization,
              child: Text('Customize Theme'),
            ),
            SwitchListTile(
              title: Text('Enable Voice Command'),
              value: voiceCommandEnabled,
              onChanged: (bool value) {
                setState(() {
                  voiceCommandEnabled = value;
                });
              },
            ),
            TextField(
              controller: TextEditingController(text: voiceCommandLocale),
              decoration: InputDecoration(labelText: 'Voice Command Locale'),
              onChanged: (value) {
                voiceCommandLocale = value;
              },
            ),
            ElevatedButton(
              onPressed: handleVoiceCommand,
              child: Text('Update Voice Command Settings'),
            ),
            TextField(
              controller: aliasController,
              decoration: InputDecoration(labelText: 'Alias'),
            ),
            TextField(
              controller: addressController,
              decoration: InputDecoration(labelText: 'Address'),
            ),
            ElevatedButton(
              onPressed: () => handleWalletNaming('POST'),
              child: Text('Register Wallet Alias'),
            ),
            ElevatedButton(
              onPressed: () => handleWalletNaming('DELETE'),
              child: Text('Remove Wallet Alias'),
            ),
          ],
        ),
      ),
    );
  }

  Future<void> handleARDisplay() async {
    final response = await http.get(
      Uri.parse('http://your_api_url/api/ar_display?wallet_id=${walletIdController.text}'),
    );

    if (response.statusCode == 200) {
      final data = json.decode(response.body)['data'];
      showDialog(
        context: context,
        builder: (BuildContext context) {
          return AlertDialog(
            title: Text('AR Display Data'),
            content: SingleChildScrollView(
              child: ListBody(
                children: <Widget>[
                  Text('Data: $data'),
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
      throw Exception('Failed to handle AR display');
    }
  }

  Future<void> handleThemeCustomization() async {
    final response = await http.post(
      Uri.parse('http://your_api_url/api/theme_customization'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'name': themeNameController.text}),
    );

    if (response.statusCode == 200) {
      showDialog(
        context: context,
        builder: (BuildContext context) {
          return AlertDialog(
            title: Text('Theme Customization'),
            content: SingleChildScrollView(
              child: ListBody(
                children: <Widget>[
                  Text('Theme customized successfully'),
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
      throw Exception('Failed to customize theme');
    }
  }

  Future<void> handleVoiceCommand() async {
    final response = await http.post(
      Uri.parse('http://your_api_url/api/voice_command'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'enabled': voiceCommandEnabled, 'locale': voiceCommandLocale}),
    );

    if (response.statusCode == 204) {
      showDialog(
        context: context,
        builder: (BuildContext context) {
          return AlertDialog(
            title: Text('Voice Command Settings'),
            content: SingleChildScrollView(
              child: ListBody(
                children: <Widget>[
                  Text('Voice command settings updated successfully'),
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
      throw Exception('Failed to update voice command settings');
    }
  }

  Future<void> handleWalletNaming(String method) async {
    var url = 'http://your_api_url/api/wallet_naming';
    var body = jsonEncode({'alias': aliasController.text});

    if (method == 'POST') {
      body = jsonEncode({'alias': aliasController.text, 'address': addressController.text});
    }

    final response = await http.Request(method, Uri.parse(url))
      ..headers['Content-Type'] = 'application/json'
      ..body = body;

    final streamedResponse = await http.Client().send(response);

    if (streamedResponse.statusCode == 201 || streamedResponse.statusCode == 204) {
      showDialog(
        context: context,
        builder: (BuildContext context) {
          return AlertDialog(
            title: Text('Wallet Naming'),
            content: SingleChildScrollView(
              child: ListBody(
                children: <Widget>[
                  Text(method == 'POST' ? 'Alias registered successfully' : 'Alias removed successfully'),
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
      throw Exception('Failed to handle wallet naming');
    }
  }
}
