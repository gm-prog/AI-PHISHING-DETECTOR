import os
from dotenv import load_dotenv

# Load environment variables from .env if present
load_dotenv()

class Settings:
    # Gemini API Key for AI Analysis (optional — scans work without it)
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")

    # VirusTotal API Key (free tier: 500 requests/day)
    # Get yours at: https://www.virustotal.com/gui/sign-in
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")


    # CORS configuration
    ALLOWED_ORIGINS: str = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173,http://localhost:3000")

    # Server configuration
    HOST: str = os.getenv("HOST", "127.0.0.1")
    PORT: int = int(os.getenv("PORT", "8000"))

settings = Settings()

