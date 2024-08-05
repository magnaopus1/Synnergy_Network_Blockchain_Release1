import os
import logging
import yaml
import shutil
import subprocess
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
model_storage_config = load_config('model_storage_config.yaml')
deployment_config = load_config('deployment_config.yaml')

def backup_current_model():
    """Backup the current model before upgrading."""
    try:
        current_model_path = Path(model_storage_config['current_model_path'])
        backup_path = Path(model_storage_config['backup_path'])
        if current_model_path.exists():
            shutil.copytree(current_model_path, backup_path / current_model_path.name)
            logger.info(f"Backed up current model to {backup_path / current_model_path.name}.")
        else:
            logger.error(f"Current model path {current_model_path} does not exist.")
    except Exception as e:
        logger.error(f"An error occurred while backing up the current model: {e}")

def load_new_model():
    """Load the new model from the specified path."""
    try:
        new_model_path = Path(model_storage_config['new_model_path'])
        current_model_path = Path(model_storage_config['current_model_path'])
        if new_model_path.exists():
            if current_model_path.exists():
                shutil.rmtree(current_model_path)
            shutil.copytree(new_model_path, current_model_path)
            logger.info(f"New model loaded from {new_model_path} to {current_model_path}.")
        else:
            logger.error(f"New model path {new_model_path} does not exist.")
    except Exception as e:
        logger.error(f"An error occurred while loading the new model: {e}")

def restart_bot():
    """Restart the bot to apply the new model."""
    try:
        stop_script = Path(deployment_config['scripts']['stop'])
        start_script = Path(deployment_config['scripts']['start'])

        if stop_script.exists() and start_script.exists():
            subprocess.run(['python', str(stop_script)], check=True)
            subprocess.run(['python', str(start_script)], check=True)
            logger.info("Bot successfully restarted with the new model.")
        else:
            logger.error("Stop or start script does not exist.")
    except subprocess.CalledProcessError as e:
        logger.error(f"An error occurred while restarting the bot: {e}")

def main():
    """Main function to upgrade the AI conversation bot model."""
    logger.info("Starting the model upgrade process...")
    backup_current_model()
    load_new_model()
    restart_bot()
    logger.info("Model upgrade process completed successfully.")

if __name__ == '__main__':
    main()
