import logging
import os
import yaml
import time
import psutil
import datetime
from typing import Dict, Any, List
import numpy as np

class PerformanceMonitoring:
    def __init__(self, config_path: str):
        self.config_path = config_path
        self.config = self.load_config()
        self.setup_logging()
        self.metrics = {
            'cpu_usage': [],
            'memory_usage': [],
            'response_times': [],
            'error_rates': [],
            'uptime': [],
        }

    def load_config(self) -> Dict:
        with open(self.config_path, 'r') as file:
            config = yaml.safe_load(file)
        return config

    def setup_logging(self):
        logging_config = self.config.get('logging', {})
        logging.basicConfig(
            filename=logging_config.get('log_file', 'performance_monitoring.log'),
            level=logging_config.get('log_level', logging.INFO),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('PerformanceMonitoring')

    def log_performance(self):
        self.log_cpu_usage()
        self.log_memory_usage()
        self.log_uptime()
        self.log_response_times()
        self.log_error_rates()

    def log_cpu_usage(self):
        cpu_usage = psutil.cpu_percent(interval=1)
        self.metrics['cpu_usage'].append(cpu_usage)
        self.logger.info(f"CPU Usage: {cpu_usage}%")

    def log_memory_usage(self):
        memory_info = psutil.virtual_memory()
        memory_usage = memory_info.percent
        self.metrics['memory_usage'].append(memory_usage)
        self.logger.info(f"Memory Usage: {memory_usage}%")

    def log_uptime(self):
        uptime_seconds = time.time() - psutil.boot_time()
        uptime_str = str(datetime.timedelta(seconds=uptime_seconds))
        self.metrics['uptime'].append(uptime_seconds)
        self.logger.info(f"Uptime: {uptime_str}")

    def log_response_times(self, response_time: float = None):
        if response_time:
            self.metrics['response_times'].append(response_time)
            self.logger.info(f"Response Time: {response_time}ms")
        else:
            response_time = np.mean(self.metrics['response_times'])
            self.logger.info(f"Average Response Time: {response_time}ms")

    def log_error_rates(self, error_rate: float = None):
        if error_rate:
            self.metrics['error_rates'].append(error_rate)
            self.logger.info(f"Error Rate: {error_rate}%")
        else:
            error_rate = np.mean(self.metrics['error_rates'])
            self.logger.info(f"Average Error Rate: {error_rate}%")

    def monitor(self):
        while True:
            self.log_performance()
            time.sleep(self.config.get('monitoring_interval', 60))

    def get_metrics_summary(self) -> Dict[str, Any]:
        summary = {
            'cpu_usage': {
                'min': np.min(self.metrics['cpu_usage']),
                'max': np.max(self.metrics['cpu_usage']),
                'average': np.mean(self.metrics['cpu_usage'])
            },
            'memory_usage': {
                'min': np.min(self.metrics['memory_usage']),
                'max': np.max(self.metrics['memory_usage']),
                'average': np.mean(self.metrics['memory_usage'])
            },
            'response_times': {
                'min': np.min(self.metrics['response_times']),
                'max': np.max(self.metrics['response_times']),
                'average': np.mean(self.metrics['response_times'])
            },
            'error_rates': {
                'min': np.min(self.metrics['error_rates']),
                'max': np.max(self.metrics['error_rates']),
                'average': np.mean(self.metrics['error_rates'])
            },
            'uptime': {
                'total': np.sum(self.metrics['uptime']),
                'average': np.mean(self.metrics['uptime'])
            }
        }
        return summary

if __name__ == "__main__":
    config_file_path = "/Users/admin/Desktop/synnergy_network/pkg/synnergy_network/core/ai_machine_learning/ai_conversation_bot/config/performance_monitoring_config.yaml"
    performance_monitoring = PerformanceMonitoring(config_file_path)
    performance_monitoring.monitor()
