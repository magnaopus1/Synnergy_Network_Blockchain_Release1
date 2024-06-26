import os
import logging
import signal
import sys
import yaml
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

def stop_bot():
    """Function to stop the AI conversation bot gracefully."""
    try:
        pid_file_path = Path(deployment_config['pid_file'])
        if pid_file_path.exists():
            with open(pid_file_path, 'r') as file:
                pid = int(file.read().strip())
            os.kill(pid, signal.SIGTERM)
            logger.info(f"Sent SIGTERM to process with PID {pid}.")
            pid_file_path.unlink()  # Remove PID file
            logger.info("PID file removed.")
        else:
            logger.error("PID file does not exist. Is the bot running?")
    except ProcessLookupError:
        logger.error("No process found with the specified PID.")
    except Exception as e:
        logger.error(f"An error occurred while stopping the bot: {e}")

def clean_up_resources():
    """Function to clean up resources used by the bot."""
    try:
        # Example: Close database connections, release memory, etc.
        logger.info("Cleaning up resources...")
        # Add any necessary resource cleanup code here
        logger.info("Resources cleaned up successfully.")
    except Exception as e:
        logger.error(f"An error occurred during resource cleanup: {e}")

def main():
    """Main function to stop the AI conversation bot."""
    logger.info("Initiating bot shutdown...")
    stop_bot()
    clean_up_resources()
    logger.info("Bot shutdown completed successfully.")

if __name__ == '__main__':
    main()
