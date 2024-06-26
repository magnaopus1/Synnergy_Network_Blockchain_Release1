import os
import logging
import yaml
from pathlib import Path
from datetime import datetime

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

def pause_bot():
    """Function to pause the AI conversation bot."""
    logger.info("Starting bot pause process...")

    pause_flag_file = Path(deployment_config['pause_flag_file'])
    
    if pause_flag_file.exists():
        logger.warning(f"Pause flag file {pause_flag_file} already exists. Bot might already be paused.")
        return

    try:
        pause_flag_file.touch()
        logger.info(f"Pause flag file {pause_flag_file} created successfully.")
    except Exception as e:
        logger.error(f"Failed to create pause flag file {pause_flag_file}: {e}")
        return

    logger.info("AI conversation bot is now paused.")

def log_pause_action():
    """Function to log the pause action with a timestamp."""
    logs_dir = Path(deployment_config['pause_logs_directory'])
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_file = logs_dir / f"pause_log_{datetime.now().strftime('%Y%m%d%H%M%S')}.log"

    try:
        with open(log_file, 'w') as file:
            file.write(f"Pause Timestamp: {datetime.now()}\n")
            file.write("Action: AI conversation bot paused.\n")
        logger.info(f"Pause action logged in {log_file}")
    except Exception as e:
        logger.error(f"Failed to log pause action: {e}")

if __name__ == '__main__':
    pause_bot()
    log_pause_action()
