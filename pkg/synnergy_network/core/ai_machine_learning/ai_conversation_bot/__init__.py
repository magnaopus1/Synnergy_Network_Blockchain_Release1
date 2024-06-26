"""
AI Conversation Bot Initialization
"""

import os
import logging
import yaml
from .models.context_management import ContextManagement
from .models.general_language_understanding import GeneralLanguageUnderstanding
from .models.intent_recognition import IntentRecognition
from .models.multi_language_support import MultiLanguageSupport
from .models.personalization import Personalization
from .models.real_time_data_access import RealTimeDataAccess
from .models.response_generation import ResponseGeneration
from .models.security_models import SecurityModels
from .models.sentiment_analysis import SentimentAnalysis
from .models.voice_interaction import VoiceInteraction
from .utils.adaptive_learning import AdaptiveLearning
from .utils.data_preprocessing import DataPreprocessing
from .utils.educational_modules import EducationalModules
from .utils.feedback_loop import FeedbackLoop
from .utils.logging_setup import LoggingSetup
from .utils.performance_monitoring import PerformanceMonitoring
from .utils.real_time_data_access import RealTimeDataAccessUtils
from .utils.scalability_settings import ScalabilitySettings
from .utils.transaction_assistance import TransactionAssistance

class AIConversationBot:
    def __init__(self, config_dir: str):
        self.config_dir = config_dir
        self.configs = self.load_configs()
        self.setup_logging()
        self.context_management = ContextManagement(self.configs['context_management'])
        self.general_language_understanding = GeneralLanguageUnderstanding(self.configs['general_language_understanding'])
        self.intent_recognition = IntentRecognition(self.configs['intent_recognition'])
        self.multi_language_support = MultiLanguageSupport(self.configs['multi_language_support'])
        self.personalization = Personalization(self.configs['personalization'])
        self.real_time_data_access = RealTimeDataAccess(self.configs['real_time_data_access'])
        self.response_generation = ResponseGeneration(self.configs['response_generation'])
        self.security_models = SecurityModels(self.configs['security_models'])
        self.sentiment_analysis = SentimentAnalysis(self.configs['sentiment_analysis'])
        self.voice_interaction = VoiceInteraction(self.configs['voice_interaction'])
        self.adaptive_learning = AdaptiveLearning(self.configs['adaptive_learning'])
        self.data_preprocessing = DataPreprocessing(self.configs['data_preprocessing'])
        self.educational_modules = EducationalModules(self.configs['educational_modules'])
        self.feedback_loop = FeedbackLoop(self.configs['feedback_loop'])
        self.performance_monitoring = PerformanceMonitoring(self.configs['performance_monitoring'])
        self.real_time_data_access_utils = RealTimeDataAccessUtils(self.configs['real_time_data_access'])
        self.scalability_settings = ScalabilitySettings(self.configs['scalability_settings'])
        self.transaction_assistance = TransactionAssistance(self.configs['transaction_assistance'])

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
        self.logger = logging.getLogger('AIConversationBot')
        self.logger.info("Logging is set up.")

    def initialize_components(self):
        self.logger.info("Initializing AI Conversation Bot Components...")
        self.context_management.initialize()
        self.general_language_understanding.initialize()
        self.intent_recognition.initialize()
        self.multi_language_support.initialize()
        self.personalization.initialize()
        self.real_time_data_access.initialize()
        self.response_generation.initialize()
        self.security_models.initialize()
        self.sentiment_analysis.initialize()
        self.voice_interaction.initialize()
        self.adaptive_learning.initialize()
        self.data_preprocessing.initialize()
        self.educational_modules.initialize()
        self.feedback_loop.initialize()
        self.performance_monitoring.initialize()
        self.real_time_data_access_utils.initialize()
        self.scalability_settings.initialize()
        self.transaction_assistance.initialize()
        self.logger.info("All components initialized successfully.")

if __name__ == "__main__":
    config_directory = "/Users/admin/Desktop/synnergy_network/pkg/synnergy_network/core/ai_machine_learning/ai_conversation_bot/config"
    ai_conversation_bot = AIConversationBot(config_directory)
    ai_conversation_bot.initialize_components()
    ai_conversation_bot.logger.info("AI Conversation Bot successfully initialized.")
