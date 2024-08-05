import os
import json
import yaml
from typing import Dict, Any

class EducationalModules:
    def __init__(self, config_path: str):
        self.config = self.load_config(config_path)
        self.tutorials = self.load_tutorials(self.config['tutorials_path'])
        self.faqs = self.load_faqs(self.config['faqs_path'])
        self.market_data = self.load_market_data(self.config['market_data_path'])

    def load_config(self, config_path: str) -> Dict[str, Any]:
        with open(config_path, 'r') as file:
            config = yaml.safe_load(file)
        return config

    def load_tutorials(self, tutorials_path: str) -> Dict[str, str]:
        with open(tutorials_path, 'r') as file:
            tutorials = json.load(file)
        return tutorials

    def load_faqs(self, faqs_path: str) -> Dict[str, str]:
        with open(faqs_path, 'r') as file:
            faqs = json.load(file)
        return faqs

    def load_market_data(self, market_data_path: str) -> Dict[str, Any]:
        with open(market_data_path, 'r') as file:
            market_data = json.load(file)
        return market_data

    def get_tutorial(self, topic: str) -> str:
        return self.tutorials.get(topic, "Tutorial not found. Please try another topic.")

    def get_faq_answer(self, question: str) -> str:
        return self.faqs.get(question, "FAQ not found. Please try another question.")

    def get_market_data(self, data_type: str) -> Any:
        return self.market_data.get(data_type, "Market data not available.")

    def add_tutorial(self, topic: str, content: str):
        self.tutorials[topic] = content
        self.save_tutorials()

    def add_faq(self, question: str, answer: str):
        self.faqs[question] = answer
        self.save_faqs()

    def save_tutorials(self):
        with open(self.config['tutorials_path'], 'w') as file:
            json.dump(self.tutorials, file)

    def save_faqs(self):
        with open(self.config['faqs_path'], 'w') as file:
            json.dump(self.faqs, file)

    def update_market_data(self, data_type: str, data: Any):
        self.market_data[data_type] = data
        self.save_market_data()

    def save_market_data(self):
        with open(self.config['market_data_path'], 'w') as file:
            json.dump(self.market_data, file)

if __name__ == "__main__":
    config_path = "/Users/admin/Desktop/synnergy_network/pkg/synnergy_network/core/ai_machine_learning/ai_conversation_bot/config/educational_modules_config.yaml"
    edu_modules = EducationalModules(config_path)

    # Examples of using the educational module
    print(edu_modules.get_tutorial("blockchain"))
    print(edu_modules.get_faq_answer("What is DeFi?"))
    print(edu_modules.get_market_data("bitcoin_price"))
    
    edu_modules.add_tutorial("smart_contracts", "A smart contract is a self-executing contract with the terms of the agreement directly written into code.")
    edu_modules.add_faq("How does staking work?", "Staking involves holding funds in a cryptocurrency wallet to support the operations of a blockchain network. Users are rewarded for their participation.")
    edu_modules.update_market_data("ethereum_price", 2000.75)
