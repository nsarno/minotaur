import time
import uuid
from pathlib import Path
from typing import List, Dict, Any, Tuple
from datetime import datetime

from ..models.analysis import AnalysisRequest, AnalysisResponse, TriageResult
from ..models.dependency import Dependency
from ..models.vulnerability import Vulnerability, VulnerabilityReport, ThreatLevel
from ..services.repository_service import RepositoryService
from ..services.dependency_service import DependencyService
from ..services.vulnerability_service import VulnerabilityService
from ..services.triage_service import TriageService


class AnalysisEngine:
    """Main analysis engine that orchestrates the vulnerability analysis workflow"""

    def __init__(
        self,
        max_dependencies: int = 1000,
        osv_api_url: str = "https://api.osv.dev",
        openai_api_key: str = None
    ):
        self.max_dependencies = max_dependencies
        self.osv_api_url = osv_api_url
        self.openai_api_key = openai_api_key

        # Initialize services
        self.repository_service = RepositoryService()
        self.dependency_service = DependencyService(max_dependencies=max_dependencies)
        self.triage_service = TriageService(openai_api_key=openai_api_key)

    async def analyze_repository(self, request: AnalysisRequest) -> AnalysisResponse:
        """
        Perform complete vulnerability analysis of a GitHub repository

        Args:
            request: Analysis request with repository URL and parameters

        Returns:
            AnalysisResponse with complete vulnerability report
        """
        start_time = time.time()
        report_id = str(uuid.uuid4())
        errors = []

        try:
            # Step 1: Clone repository
            repo_path = await self.repository_service.clone_repository(str(request.repo_url))

            # Step 2: Extract dependencies
            dependencies = await self.dependency_service.extract_dependencies(repo_path)

            if not dependencies:
                return AnalysisResponse(
                    report_id=report_id,
                    repo_url=str(request.repo_url),
                    analysis_timestamp=datetime.now(),
                    dependencies_analyzed=0,
                    vulnerabilities_found=0,
                    real_threats=0,
                    analysis_duration=time.time() - start_time,
                    errors=["No dependencies found in repository"]
                )

            # Step 3: Check which dependencies are actually used
            dependency_usage = {}
            for dep in dependencies:
                dependency_usage[dep.name] = self.dependency_service.is_dependency_used(dep, repo_path)

            # Step 4: Query vulnerabilities
            all_vulnerabilities = await self._analyze_vulnerabilities(dependencies)

            # Step 5: Generate repository context for triage
            repo_context = self._generate_repo_context(repo_path, dependencies)

            # Step 6: Perform LLM-based triage
            vulnerability_reports = []
            for vuln, dep in all_vulnerabilities:
                triage_result = await self.triage_service.triage_vulnerability(
                    vuln, dep, repo_context, dependency_usage.get(dep.name, True)
                )

                # Create vulnerability report
                report = VulnerabilityReport(
                    vulnerability=vuln,
                    dependency=dep.name,
                    dependency_version=dep.version,
                    is_real_threat=triage_result.is_real_threat,
                    threat_level=triage_result.threat_level,
                    impact_summary=triage_result.impact_summary,
                    recommendation=triage_result.recommendation,
                    evidence={
                        "is_direct_dependency": dep.is_direct,
                        "is_dependency_used": dependency_usage.get(dep.name, True),
                        "triage_confidence": triage_result.confidence,
                        "triage_reasoning": triage_result.reasoning
                    },
                    triage_confidence=triage_result.confidence
                )
                vulnerability_reports.append(report)

            # Step 7: Calculate summary statistics
            real_threats = sum(1 for report in vulnerability_reports if report.is_real_threat)
            threat_counts = self._calculate_threat_counts(vulnerability_reports)

            # Step 8: Clean up
            self.repository_service.cleanup()

            analysis_duration = time.time() - start_time

            return AnalysisResponse(
                report_id=report_id,
                repo_url=str(request.repo_url),
                analysis_timestamp=datetime.now(),
                dependencies_analyzed=len(dependencies),
                vulnerabilities_found=len(vulnerability_reports),
                real_threats=real_threats,
                critical_count=threat_counts.get(ThreatLevel.CRITICAL, 0),
                high_count=threat_counts.get(ThreatLevel.HIGH, 0),
                medium_count=threat_counts.get(ThreatLevel.MEDIUM, 0),
                low_count=threat_counts.get(ThreatLevel.LOW, 0),
                vulnerability_reports=vulnerability_reports,
                dependencies=dependencies,
                analysis_duration=analysis_duration,
                errors=errors
            )

        except Exception as e:
            # Clean up on error
            self.repository_service.cleanup()
            errors.append(f"Analysis failed: {str(e)}")

            return AnalysisResponse(
                report_id=report_id,
                repo_url=str(request.repo_url),
                analysis_timestamp=datetime.now(),
                dependencies_analyzed=0,
                vulnerabilities_found=0,
                real_threats=0,
                analysis_duration=time.time() - start_time,
                errors=errors
            )

    async def _analyze_vulnerabilities(self, dependencies: List[Dependency]) -> List[Tuple[Vulnerability, Dependency]]:
        """
        Queries vulnerabilities for a list of dependencies using the OSV API.
        Returns a list of tuples (Vulnerability, Dependency).
        """
        all_vulnerabilities = []
        async with VulnerabilityService(self.osv_api_url) as vuln_service:
            vuln_by_dependency = await vuln_service.get_vulnerabilities_batch(dependencies)

            # Flatten vulnerabilities and filter by version
            for dep_name, vulnerabilities in vuln_by_dependency.items():
                for vuln in vulnerabilities:
                    # Find the corresponding dependency
                    dep = next((d for d in dependencies if d.name == dep_name), None)
                    if dep and vuln_service.is_vulnerability_affecting_version(vuln, dep):
                        all_vulnerabilities.append((vuln, dep))
        return all_vulnerabilities

    def _generate_repo_context(self, repo_path: Path, dependencies: List[Dependency]) -> str:
        """Generate context about the repository for LLM triage"""
        context_parts = []

        # Repository structure
        context_parts.append(f"Repository contains {len(dependencies)} dependencies")

        # Dependency types
        npm_count = sum(1 for d in dependencies if d.dependency_type == "npm")
        python_count = sum(1 for d in dependencies if d.dependency_type == "python")

        if npm_count > 0:
            context_parts.append(f"JavaScript/Node.js dependencies: {npm_count}")
        if python_count > 0:
            context_parts.append(f"Python dependencies: {python_count}")

        # Direct vs transitive
        direct_count = sum(1 for d in dependencies if d.is_direct)
        transitive_count = len(dependencies) - direct_count
        context_parts.append(f"Direct dependencies: {direct_count}, Transitive: {transitive_count}")

        # Repository files (basic analysis)
        file_extensions = set()
        for file_path in repo_path.rglob('*'):
            if file_path.is_file():
                file_extensions.add(file_path.suffix)

        if file_extensions:
            context_parts.append(f"File types found: {', '.join(sorted(file_extensions))}")

        return "\n".join(context_parts)

    def _calculate_threat_counts(self, vulnerability_reports: List[VulnerabilityReport]) -> Dict[ThreatLevel, int]:
        """Calculate counts by threat level"""
        counts = {}
        for report in vulnerability_reports:
            level = report.threat_level
            counts[level] = counts.get(level, 0) + 1
        return counts
