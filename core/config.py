# core/config.py
import yaml
import os

class Config:
    def __init__(self):
        self.OLLAMA_HOST = "http://localhost:11434"
        self.FAST_MODEL = "llama3.2:3b"
        self.DEEP_MODEL = "llama3.1:8b"
        self.TARGET_URL = ""
        self.SCAN_TIMEOUT = 30
        self.DB_PATH = "database/security_tool.db"
        self.REPORT_OUTPUT_DIR = "reports/"
        self.LOG_LEVEL = "INFO"
        self.AUTHORIZED_TARGETS = []

    def set_target(self, url):
        self.TARGET_URL = url

    def add_authorized_target(self, url):
        self.AUTHORIZED_TARGETS.append(url)

    def is_authorized(self, url):
        return any(url.startswith(t) for t in self.AUTHORIZED_TARGETS)

    def display(self):
        print(f"""
        ========== Current Configuration ==========
        Ollama Host     : {self.OLLAMA_HOST}
        Fast Model      : {self.FAST_MODEL}
        Deep Model      : {self.DEEP_MODEL}
        Target URL      : {self.TARGET_URL}
        Scan Timeout    : {self.SCAN_TIMEOUT}s
        DB Path         : {self.DB_PATH}
        Report Dir      : {self.REPORT_OUTPUT_DIR}
        ===========================================
        """)

# Global config instance
config = Config()