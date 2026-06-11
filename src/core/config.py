"""
Lab 11 — Configuration & API Key Setup
"""
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


def setup_api_key():
    """Load Google API key from .env or environment, then set Gemini flags."""
    os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "0"
    print("API key loaded from .env or environment.")


# Allowed banking topics (used by topic_filter)
ALLOWED_TOPICS = [
    "banking", "account", "transaction", "transfer",
    "loan", "interest", "savings", "credit",
    "deposit", "withdrawal", "balance", "payment",
    "tai khoan", "giao dich", "tiet kiem", "lai suat",
    "chuyen tien", "the tin dung", "so du", "vay",
    "ngan hang", "atm",
]

# Blocked topics (immediate reject)
BLOCKED_TOPICS = [
    "hack", "exploit", "weapon", "drug", "illegal",
    "violence", "gambling", "bomb", "kill", "steal",
]
