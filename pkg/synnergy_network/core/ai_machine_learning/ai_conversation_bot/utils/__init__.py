"""
Utils Module for AI Conversation Bot
"""

import os
import logging
import yaml

from .adaptive_learning import AdaptiveLearning
from .data_preprocessing import DataPreprocessing
from .educational_modules import EducationalModules
from .feedback_loop import FeedbackLoop
from .logging_setup import LoggingSetup
from .multi_language_support import MultiLanguageSupport
from .performance_monitoring import PerformanceMonitoring
from .real_time_data_access import RealTimeDataAccess
from .scalability_settings import ScalabilitySettings
from .sentiment_analysis import SentimentAnalysis
from .transaction_assistance import TransactionAssistance
from .voice_interaction import VoiceInteraction

class AIConversationBotUtils:
    def __init__(self, config_dir: str):
        self.config_dir = config_dir
        self.configs = self.load_configs()
        self.setup_logging()
        self.adaptive_learning = AdaptiveLearning(self.configs['adaptive_learning'])
        self.data_preprocessing = DataPreprocessing(self.configs['data_preprocessing'])
        self.educational_modules = EducationalModules(self.configs['educational_modules'])
        self.feedback_loop = FeedbackLoop(self.configs['feedback_loop'])
        self.multi_language_support = MultiLanguageSupport(self.configs['multi_language_support'])
        self.performance_monitoring = PerformanceMonitoring(self.configs['performance_monitoring'])
        self.real_time_data_access = RealTimeDataAccess(self.configs['real_time_data_access'])
        self.scalability_settings = ScalabilitySettings(self.configs['scalability_settings'])
        self.sentiment_analysis = SentimentAnalysis(self.configs['sentiment_analysis'])
        self.transaction_assistance = TransactionAssistance(self.configs['transaction_assistance'])
        self.voice_interaction = VoiceInteraction(self.configs['voice_interaction'])

    def load_configs(self) -> dict:
        configs = {}
        for config_file in os.listdir(self.config_dir):
            if config_file.endswith('.yaml'):
                config_name = config_file.split('.')[0]
                with open(os.path.join(self.config_dir, config_file), 'r') as file:
                    configs[config_name] = yaml.safe_load(file)
        return configs

    def setup_logging(self):
        logging_config = self.configs.get('logging_monitoring', {})
        log_file = logging_config.get('log_file', 'ai_conversation_bot.log')
        log_level = logging_config.get('log_level', logging.INFO)
        logging.basicConfig(filename=log_file, level=log_level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger('AIConversationBotUtils')

    def initialize_components(self):
        self.logger.info("Initializing AI Conversation Bot Components...")
        self.adaptive_learning.initialize()
        self.data_preprocessing.initialize()
        self.educational_modules.initialize()
        self.feedback_loop.initialize()
        self.multi_language_support.initialize()
        self.performance_monitoring.initialize()
        self.real_time_data_access.initialize()
        self.scalability_settings.initialize()
        self.sentiment_analysis.initialize()
        self.transaction_assistance.initialize()
        self.voice_interaction.initialize()

if __name__ == "__main__":
    config_directory = "/Users/admin/Desktop/synnergy_network/pkg/synnergy_network/core/ai_machine_learning/ai_conversation_bot/config"
    ai_utils = AIConversationBotUtils(config_directory)
    ai_utils.initialize_components()
    ai_utils.logger.info("AI Conversation Bot Utils successfully initialized.")
