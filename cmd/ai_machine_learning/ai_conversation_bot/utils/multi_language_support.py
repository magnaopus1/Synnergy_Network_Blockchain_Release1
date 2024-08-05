import logging
import os
import yaml
from typing import List, Dict
from langdetect import detect
from googletrans import Translator

class MultiLanguageSupport:
    def __init__(self, config_path: str):
        self.config_path = config_path
        self.config = self.load_config()
        self.translator = Translator()
        self.supported_languages = self.config.get('supported_languages', [])
        self.default_language = self.config.get('default_language', 'en')

    def load_config(self) -> Dict:
        with open(self.config_path, 'r') as file:
            config = yaml.safe_load(file)
        return config

    def detect_language(self, text: str) -> str:
        detected_lang = detect(text)
        if detected_lang not in self.supported_languages:
            logging.warning(f"Detected language '{detected_lang}' is not supported. Falling back to default language '{self.default_language}'.")
            return self.default_language
        return detected_lang

    def translate_text(self, text: str, target_language: str) -> str:
        if target_language not in self.supported_languages:
            logging.warning(f"Target language '{target_language}' is not supported. Falling back to default language '{self.default_language}'.")
            target_language = self.default_language
        translated = self.translator.translate(text, dest=target_language).text
        return translated

    def translate_batch(self, texts: List[str], target_language: str) -> List[str]:
        translations = [self.translate_text(text, target_language) for text in texts]
        return translations

    def ensure_supported_language(self, language: str) -> str:
        if language not in self.supported_languages:
            logging.warning(f"Language '{language}' is not supported. Falling back to default language '{self.default_language}'.")
            return self.default_language
        return language

    def add_supported_language(self, language: str):
        if language not in self.supported_languages:
            self.supported_languages.append(language)
            self.save_config()
            logging.info(f"Added new supported language: {language}")

    def remove_supported_language(self, language: str):
        if language in self.supported_languages:
            self.supported_languages.remove(language)
            self.save_config()
            logging.info(f"Removed supported language: {language}")

    def save_config(self):
        with open(self.config_path, 'w') as file:
            yaml.dump(self.config, file)

    def set_default_language(self, language: str):
        self.default_language = self.ensure_supported_language(language)
        self.config['default_language'] = self.default_language
        self.save_config()
        logging.info(f"Set default language to: {self.default_language}")

if __name__ == "__main__":
    config_file_path = "/Users/admin/Desktop/synnergy_network/pkg/synnergy_network/core/ai_machine_learning/ai_conversation_bot/config/multi_language_config.yaml"
    multi_language_support = MultiLanguageSupport(config_file_path)

    # Example Usage
    sample_text = "Hello, how are you?"
    detected_lang = multi_language_support.detect_language(sample_text)
    translated_text = multi_language_support.translate_text(sample_text, 'es')

    print(f"Detected Language: {detected_lang}")
    print(f"Translated Text: {translated_text}")
