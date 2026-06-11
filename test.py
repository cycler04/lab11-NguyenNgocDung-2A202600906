import os
from dotenv import load_dotenv
load_dotenv()  # Load .env file if present

print(os.environ.get("GOOGLE_API_KEY", "GOOGLE_API_KEY not set"))