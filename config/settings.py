import os
from typing import Optional
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
env_path = Path(__file__).parent.parent / ".env"
load_dotenv(env_path)


class Settings:
    """Application settings"""

    # API Configuration
    API_HOST: str = os.getenv("API_HOST", "0.0.0.0")
    API_PORT: int = int(os.getenv("API_PORT", "8000"))
    API_RELOAD: bool = os.getenv("API_RELOAD", "true").lower() == "true"

    # OpenAI Configuration
    OPENAI_API_KEY: Optional[str] = os.getenv("OPENAI_API_KEY")
    OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-3.5-turbo")
    OPENAI_TEMPERATURE: float = float(os.getenv("OPENAI_TEMPERATURE", "0.1"))
    OPENAI_MAX_TOKENS: int = int(os.getenv("OPENAI_MAX_TOKENS", "1000"))

    # OSV Configuration
    OSV_API_BASE_URL: str = os.getenv("OSV_API_BASE_URL", "https://api.osv.dev")

    # Repository Configuration
    REPO_CLONE_TIMEOUT: int = int(os.getenv("REPO_CLONE_TIMEOUT", "300"))
    MAX_DEPENDENCIES: int = int(os.getenv("MAX_DEPENDENCIES", "1000"))

    # Analysis Configuration
    TRIAGE_CONFIDENCE_THRESHOLD: float = float(os.getenv("TRIAGE_CONFIDENCE_THRESHOLD", "0.7"))

    # Logging Configuration
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    @classmethod
    def validate(cls) -> list[str]:
        """Validate required settings"""
        errors = []

        if not cls.OPENAI_API_KEY:
            errors.append("OPENAI_API_KEY is required for LLM-based triage")

        if cls.MAX_DEPENDENCIES <= 0:
            errors.append("MAX_DEPENDENCIES must be positive")

        if cls.TRIAGE_CONFIDENCE_THRESHOLD < 0 or cls.TRIAGE_CONFIDENCE_THRESHOLD > 1:
            errors.append("TRIAGE_CONFIDENCE_THRESHOLD must be between 0 and 1")

        return errors


# Global settings instance
settings = Settings()
