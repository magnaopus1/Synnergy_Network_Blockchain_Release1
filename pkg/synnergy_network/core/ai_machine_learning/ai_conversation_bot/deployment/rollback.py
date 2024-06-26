import os
import logging
import yaml
from shutil import copy2
from pathlib import Path

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load configuration files
CONFIG_DIR = '/Users/admin/Desktop/synnergy_network/pkg/synnergy_network/core/ai_machine_learning/ai_conversation_bot/config/'

def load_config(file_name):
    try:
        with open(os.path.join(CONFIG_DIR, file_name), 'r') as file:
            return yaml.safe_load(file)
    except Exception as e:
        logger.error(f"Error loading config {file_name}: {e}")
        return None

# Load specific configurations
deployment_config = load_config('deployment_config.yaml')

def rollback_model():
    """Function to rollback the AI conversation bot to a previous stable version."""
    logger.info("Starting rollback process...")

    current_model_dir = Path(deployment_config['current_model_dir'])
    backup_model_dir = Path(deployment_config['backup_model_dir'])

    if not backup_model_dir.exists():
        logger.error(f"Backup model directory {backup_model_dir} does not exist.")
        return

    try:
        # Copy files from backup to current model directory
        for file_name in os.listdir(backup_model_dir):
            full_file_name = os.path.join(backup_model_dir, file_name)
            if os.path.isfile(full_file_name):
                copy2(full_file_name, current_model_dir)
        logger.info(f"Model rollback to {backup_model_dir} completed successfully.")
    except Exception as e:
        logger.error(f"Failed to rollback model: {e}")

def log_rollback_action():
    """Function to log the rollback action with a timestamp."""
    logs_dir = Path(deployment_config['rollback_logs_directory'])
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_file = logs_dir / f"rollback_log_{datetime.now().strftime('%Y%m%d%H%M%S')}.log"

    try:
        with open(log_file, 'w') as file:
            file.write(f"Rollback Timestamp: {datetime.now()}\n")
            file.write(f"Action: Rolled back to model version from {deployment_config['backup_model_dir']}\n")
        logger.info(f"Rollback action logged in {log_file}")
    except Exception as e:
        logger.error(f"Failed to log rollback action: {e}")

if __name__ == '__main__':
    rollback_model()
    log_rollback_action()
