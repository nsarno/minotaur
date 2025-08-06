#!/usr/bin/env python3
"""
Minotaur CLI - Command line interface for dependency threat analysis
"""

import asyncio
import json
import sys
import argparse
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from app.core.analysis_engine import AnalysisEngine
from app.models.analysis import AnalysisRequest
from config.settings import settings


def print_report(report, output_format: str = "json"):
    """Print analysis report in specified format"""
    if output_format == "json":
        print(json.dumps(report.dict(), indent=2, default=str))
    elif output_format == "summary":
        print(f"\n=== Minotaur Analysis Report ===")
        print(f"Repository: {report.repo_url}")
        print(f"Analysis Time: {report.analysis_timestamp}")
        print(f"Dependencies Analyzed: {report.dependencies_analyzed}")
        print(f"Vulnerabilities Found: {report.vulnerabilities_found}")
        print(f"Real Threats: {report.real_threats}")
        print(f"Analysis Duration: {report.analysis_duration:.2f} seconds")

        if report.vulnerability_reports:
            print(f"\n=== Vulnerability Summary ===")
            print(f"Critical: {report.critical_count}")
            print(f"High: {report.high_count}")
            print(f"Medium: {report.medium_count}")
            print(f"Low: {report.low_count}")

            print(f"\n=== Real Threats ===")
            for vuln_report in report.vulnerability_reports:
                if vuln_report.is_real_threat:
                    print(f"• {vuln_report.dependency} {vuln_report.dependency_version}")
                    print(f"  {vuln_report.vulnerability.id}: {vuln_report.vulnerability.summary}")
                    print(f"  Threat Level: {vuln_report.threat_level}")
                    print(f"  Recommendation: {vuln_report.recommendation}")
                    print()

        if report.errors:
            print(f"\n=== Errors ===")
            for error in report.errors:
                print(f"• {error}")


def check_configuration():
    """Check current configuration"""
    print("🔍 Minotaur Configuration Check")
    print("=" * 40)

    # Check .env file
    env_file = Path(".env")
    if env_file.exists():
        print("✅ .env file found")

        with open(env_file, 'r') as f:
            content = f.read()

        if "OPENAI_API_KEY=" in content and "your-openai-api-key-here" not in content:
            print("✅ OpenAI API key configured")
        else:
            print("❌ OpenAI API key not configured")
    else:
        print("❌ .env file not found")

    # Check requirements
    try:
        import fastapi
        import langchain
        import aiohttp
        print("✅ Required packages installed")
    except ImportError as e:
        print(f"❌ Missing package: {e}")

    # Check settings
    errors = settings.validate()
    if errors:
        print("❌ Configuration errors found:")
        for error in errors:
            print(f"  • {error}")
    else:
        print("✅ Configuration is valid")

    print("\n💡 Run 'minotaur --setup' to configure the tool")


async def analyze_repository(
    repo_url: str,
    include_transitive: bool = True,
    max_dependencies: Optional[int] = None,
    triage_threshold: float = 0.7,
    output_format: str = "json",
    save_report: Optional[str] = None
) -> None:
    """Analyze a repository for vulnerabilities"""

    # Validate settings
    errors = settings.validate()
    if errors:
        print("Configuration errors:")
        for error in errors:
            print(f"• {error}")
        print("\nMake sure you have created a .env file with your configuration.")
        print("You can copy env.example to .env and update the values.")
        sys.exit(1)

    # Create analysis request
    request = AnalysisRequest(
        repo_url=repo_url,
        include_transitive=include_transitive,
        max_dependencies=max_dependencies or settings.MAX_DEPENDENCIES,
        triage_threshold=triage_threshold
    )

    # Initialize analysis engine
    engine = AnalysisEngine(
        max_dependencies=request.max_dependencies,
        osv_api_url=settings.OSV_API_BASE_URL,
        openai_api_key=settings.OPENAI_API_KEY
    )

    try:
        print(f"Analyzing repository: {repo_url}")
        print("This may take a few minutes...")

        # Perform analysis
        report = await engine.analyze_repository(request)

        # Print results
        print_report(report, output_format)

        # Save report if requested
        if save_report:
            with open(save_report, 'w') as f:
                json.dump(report.dict(), f, indent=2, default=str)
            print(f"\n📄 Report saved to: {save_report}")

        # Exit with error code if real threats found
        if report.real_threats > 0:
            sys.exit(1)
        else:
            sys.exit(0)

    except Exception as e:
        print(f"Analysis failed: {e}")
        sys.exit(1)


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Minotaur - Dependency Threat Radar",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://github.com/user/repo
  %(prog)s https://github.com/user/repo --format summary
  %(prog)s https://github.com/user/repo --no-transitive --max-deps 500
  %(prog)s --setup  # Run initial setup
  %(prog)s --check  # Check configuration
        """
    )

    parser.add_argument(
        "repo_url",
        nargs="?",
        help="GitHub repository URL to analyze"
    )

    parser.add_argument(
        "--no-transitive",
        action="store_true",
        help="Exclude transitive dependencies from analysis"
    )

    parser.add_argument(
        "--max-deps",
        type=int,
        help="Maximum number of dependencies to analyze"
    )

    parser.add_argument(
        "--triage-threshold",
        type=float,
        default=0.7,
        help="Minimum confidence threshold for triage (0.0-1.0)"
    )

    parser.add_argument(
        "--format",
        choices=["json", "summary"],
        default="json",
        help="Output format (default: json)"
    )

    parser.add_argument(
        "--setup",
        action="store_true",
        help="Run initial setup and configuration"
    )

    parser.add_argument(
        "--check",
        action="store_true",
        help="Check current configuration"
    )

    parser.add_argument(
        "--save-report",
        type=str,
        help="Save report to specified file"
    )

    args = parser.parse_args()

    # Handle setup command
    if args.setup:
        from setup import main as setup_main
        setup_main()
        return

    # Handle check command
    if args.check:
        check_configuration()
        return

    # Validate that repo_url is provided for analysis
    if not args.repo_url:
        parser.error("Repository URL is required for analysis. Use --help for more information.")

    # Run analysis
    asyncio.run(analyze_repository(
        repo_url=args.repo_url,
        include_transitive=not args.no_transitive,
        max_dependencies=args.max_deps,
        triage_threshold=args.triage_threshold,
        output_format=args.format,
        save_report=args.save_report
    ))


if __name__ == "__main__":
    main()
