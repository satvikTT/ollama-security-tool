# test_core.py
from core.config import config
from core.authorization import AuthorizationChecker
from llm.ollama_client import OllamaClient

# Test 1: Config
print("=== Testing Config ===")
config.display()

# Test 2: Authorization
print("=== Testing Authorization ===")
auth = AuthorizationChecker()
print(auth.check_authorization("http://localhost/dvwa"))   # Should be ✅
print(auth.check_authorization("http://google.com"))       # Should be ❌

# Test 3: Ollama Client
print("=== Testing Ollama Client ===")
llm = OllamaClient()
llm.test_connection()