import logging
import logging.config
import yaml
import os

class LoggingSetup:
    def __init__(self, config_path: str):
        self.config_path = config_path
        self.load_logging_config()

    def load_logging_config(self):
        with open(self.config_path, 'r') as file:
            config = yaml.safe_load(file)
        logging.config.dictConfig(config)

    def get_logger(self, logger_name: str) -> logging.Logger:
        return logging.getLogger(logger_name)

    @staticmethod
    def create_default_logging_config() -> dict:
        return {
            'version': 1,
            'disable_existing_loggers': False,
            'formatters': {
                'standard': {
                    'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                },
                'detailed': {
                    'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s [in %(pathname)s:%(lineno)d]'
                }
            },
            'handlers': {
                'default': {
                    'level': 'INFO',
                    'class': 'logging.StreamHandler',
                    'formatter': 'standard'
                },
                'file_handler': {
                    'level': 'DEBUG',
                    'class': 'logging.FileHandler',
                    'filename': 'logs/ai_conversation_bot.log',
                    'formatter': 'detailed',
                    'encoding': 'utf8'
                }
            },
            'loggers': {
                '': {
                    'handlers': ['default', 'file_handler'],
                    'level': 'DEBUG',
                    'propagate': True
                },
                'ai_conversation_bot': {
                    'handlers': ['default', 'file_handler'],
                    'level': 'DEBUG',
                    'propagate': False
                }
            }
        }

    def save_default_logging_config(self):
        config = self.create_default_logging_config()
        with open(self.config_path, 'w') as file:
            yaml.dump(config, file)

if __name__ == "__main__":
    config_file_path = "/Users/admin/Desktop/synnergy_network/pkg/synnergy_network/core/ai_machine_learning/ai_conversation_bot/config/logging_monitoring_config.yaml"
    logging_setup = LoggingSetup(config_file_path)

    # Save default config if the file doesn't exist
    if not os.path.exists(config_file_path):
        logging_setup.save_default_logging_config()

    # Example of getting a logger and logging a message
    logger = logging_setup.get_logger("ai_conversation_bot")
    logger.info("Logging setup completed and logger initialized successfully.")
