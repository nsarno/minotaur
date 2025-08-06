#!/usr/bin/env python3
"""
Example script demonstrating how to use Minotaur programmatically
"""

import asyncio
import json
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from app.core.analysis_engine import AnalysisEngine
from app.models.analysis import AnalysisRequest


async def analyze_example_repository():
    """Example of analyzing a repository programmatically"""

    # Initialize the analysis engine
    engine = AnalysisEngine(
        max_dependencies=100,
        osv_api_url="https://api.osv.dev",
        openai_api_key=os.getenv("OPENAI_API_KEY")  # Load from .env file
    )

    # Create analysis request
    request = AnalysisRequest(
        repo_url="https://github.com/example/repo",
        include_transitive=True,
        max_dependencies=100,
        triage_threshold=0.7
    )

    try:
        print("Starting analysis...")

        # Perform the analysis
        report = await engine.analyze_repository(request)

        # Print summary
        print(f"\nAnalysis completed!")
        print(f"Repository: {report.repo_url}")
        print(f"Dependencies analyzed: {report.dependencies_analyzed}")
        print(f"Vulnerabilities found: {report.vulnerabilities_found}")
        print(f"Real threats: {report.real_threats}")
        print(f"Analysis duration: {report.analysis_duration:.2f} seconds")

        # Print detailed results
        if report.vulnerability_reports:
            print(f"\nVulnerability Details:")
            for vuln_report in report.vulnerability_reports:
                print(f"\n• {vuln_report.dependency} {vuln_report.dependency_version}")
                print(f"  Vulnerability: {vuln_report.vulnerability.id}")
                print(f"  Summary: {vuln_report.vulnerability.summary}")
                print(f"  Is Real Threat: {vuln_report.is_real_threat}")
                print(f"  Threat Level: {vuln_report.threat_level}")
                print(f"  Recommendation: {vuln_report.recommendation}")
                print(f"  Confidence: {vuln_report.triage_confidence:.2f}")

        # Save report to file
        with open("analysis_report.json", "w") as f:
            json.dump(report.dict(), f, indent=2, default=str)
        print(f"\nDetailed report saved to analysis_report.json")

    except Exception as e:
        print(f"Analysis failed: {e}")


if __name__ == "__main__":
    asyncio.run(analyze_example_repository())
