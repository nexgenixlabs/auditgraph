"""
Pytest configuration and shared fixtures for AuditGraph tests.
"""
import os
import sys

# Ensure the app package is importable when running tests
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv

# Load environment variables for all tests
load_dotenv()
