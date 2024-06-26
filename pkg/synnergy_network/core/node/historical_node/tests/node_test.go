# Historical Node Configuration File

[general]
node_name = "historical_node_1"  # Unique name for the historical node
log_level = "info"               # Log level: trace, debug, info, warn, error
data_dir = "/var/lib/historical_node/data"  # Directory to store blockchain data
backup_dir = "/var/lib/historical_node/backup"  # Directory to store backups

[network]
port = 8080                      # Port for the node to listen on
max_connections = 1000           # Maximum number of concurrent connections
encryption = "AES"               # Encryption method for data in transit

[security]
use_tls = true                   # Enable TLS for secure communication
tls_cert_file = "/etc/historical_node/tls/cert.pem"  # Path to TLS certificate file
tls_key_file = "/etc/historical_node/tls/key.pem"    # Path to TLS key file
enable_firewall = true           # Enable firewall for additional security
allowed_ips = ["192.168.1.0/24", "10.0.0.0/16"]  # Allowed IP ranges for connections

[storage]
storage_engine = "rocksdb"       # Storage engine for blockchain data
max_storage_size_gb = 10240      # Maximum storage size in GB
storage_compression = "lz4"      # Compression algorithm for stored data
backup_frequency_hours = 24      # Frequency of full backups in hours

[backup]
backup_method = "multi-tier"     # Backup method: single-tier, multi-tier
on_site_backup = true            # Enable on-site backups
off_site_backup = true           # Enable off-site backups
cloud_backup = true              # Enable cloud backups
cloud_provider = "aws"           # Cloud provider for backups: aws, gcp, azure
cloud_backup_bucket = "historical-node-backup"  # Cloud storage bucket name

[access_control]
enable_dynamic_acls = true       # Enable dynamic access control lists
default_permission = "read-only" # Default permission for new connections
admin_users = ["admin1", "admin2"]  # List of admin users with full access
audit_log_enabled = true         # Enable audit logging for access control

[monitoring]
enable_monitoring = true         # Enable monitoring of the node
monitoring_port = 9090           # Port for the monitoring interface
metrics_collection_interval = 60 # Interval for collecting metrics in seconds
enable_alerts = true             # Enable alerts for monitoring
alert_recipients = ["admin@example.com"]  # Email addresses for alert notifications

[performance]
cpu_cores = 16                   # Number of CPU cores to utilize
memory_gb = 128                  # Amount of RAM in GB
io_optimization = true           # Enable IO optimization for faster data access
query_cache_size_mb = 1024       # Cache size for query results in MB

[security_monitoring]
enable_real_time_security = true # Enable real-time security monitoring
security_log_dir = "/var/log/historical_node/security"  # Directory for security logs
incident_response_team = ["security@example.com"]  # Contact for security incidents

[compliance]
enable_compliance_mode = true    # Enable compliance mode
compliance_log_dir = "/var/log/historical_node/compliance"  # Directory for compliance logs
regulatory_bodies = ["finra", "sec"]  # List of regulatory bodies to comply with

[research_access]
enable_research_api = true       # Enable API access for research purposes
api_rate_limit = 1000            # API rate limit requests per second
allowed_research_ips = ["198.51.100.0/24"]  # IP ranges allowed for research access
data_anonymization = true        # Enable data anonymization for research API

[logging]
log_file = "/var/log/historical_node/historical_node.log"  # Path to the main log file
log_rotation_size_mb = 100      # Log rotation size in MB
log_retention_days = 30         # Number of days to retain old logs
enable_debug_logging = false    # Enable or disable debug logging
