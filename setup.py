#!/usr/bin/env python3
"""
Setup script for Minotaur - helps users configure their environment
"""

import os
import sys
from pathlib import Path


def create_env_file():
    """Create .env file from template if it doesn't exist"""
    env_file = Path(".env")
    env_example = Path("env.example")

    if env_file.exists():
        print("✅ .env file already exists")
        return True

    if not env_example.exists():
        print("❌ env.example file not found")
        return False

    # Copy env.example to .env
    with open(env_example, 'r') as src:
        content = src.read()

    with open(env_file, 'w') as dst:
        dst.write(content)

    print("✅ Created .env file from template")
    print("📝 Please edit .env and add your OpenAI API key")
    return True


def check_env_file():
    """Check if .env file has required configuration"""
    env_file = Path(".env")

    if not env_file.exists():
        print("❌ .env file not found")
        return False

    with open(env_file, 'r') as f:
        content = f.read()

    if "your-openai-api-key-here" in content:
        print("⚠️  Please update your OpenAI API key in .env file")
        return False

    if "OPENAI_API_KEY=" in content and "your-openai-api-key-here" not in content:
        print("✅ .env file appears to be configured")
        return True

    print("❌ OPENAI_API_KEY not found in .env file")
    return False


def main():
    """Main setup function"""
    print("🔧 Minotaur Setup")
    print("=" * 50)

    # Create .env file if it doesn't exist
    if not create_env_file():
        sys.exit(1)

    # Check configuration
    if not check_env_file():
        print("\n📋 Next steps:")
        print("1. Edit .env file and add your OpenAI API key")
        print("2. Run: pip install -r requirements.txt")
        print("3. Run: python cli.py https://github.com/user/repo")
        sys.exit(1)

    print("\n🎉 Setup complete! You can now run Minotaur:")
    print("• CLI: python cli.py https://github.com/user/repo")
    print("• API: uvicorn app.main:app --reload")


if __name__ == "__main__":
    main()
