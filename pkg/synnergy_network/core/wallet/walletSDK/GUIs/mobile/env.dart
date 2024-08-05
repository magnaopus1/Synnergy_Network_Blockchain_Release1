import 'package:flutter_dotenv/flutter_dotenv.dart';

class EnvironmentConfig {
  static String get apiUrl => dotenv.env['API_URL'] ?? 'https://default-api-url.com';
  static String get apiKey => dotenv.env['API_KEY'] ?? 'default-api-key';
  static String get encryptionKey => dotenv.env['ENCRYPTION_KEY'] ?? 'default-encryption-key';
  static String get wsUrl => dotenv.env['WS_URL'] ?? 'wss://default-ws-url.com';
  static String get smtpServer => dotenv.env['SMTP_SERVER'] ?? 'smtp.default.com';
  static String get smtpUser => dotenv.env['SMTP_USER'] ?? 'user@default.com';
  static String get smtpPassword => dotenv.env['SMTP_PASSWORD'] ?? 'default-password';
}
