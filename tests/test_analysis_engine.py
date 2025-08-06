import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from datetime import datetime

from app.core.analysis_engine import AnalysisEngine
from app.models.analysis import AnalysisRequest, AnalysisResponse
from app.models.dependency import Dependency, DependencyType
from app.models.vulnerability import Vulnerability, VulnerabilityReport, ThreatLevel


class TestAnalysisEngine:
    """Test cases for AnalysisEngine"""

    @pytest.fixture
    def engine(self):
        return AnalysisEngine(
            max_dependencies=100,
            osv_api_url="https://api.osv.dev",
            openai_api_key="test-key"
        )

    @pytest.fixture
    def sample_request(self):
        return AnalysisRequest(
            repo_url="https://github.com/testuser/testrepo",
            include_transitive=True,
            max_dependencies=100,
            triage_threshold=0.7
        )

    @pytest.fixture
    def sample_dependencies(self):
        return [
            Dependency(
                name="requests",
                version="2.25.0",
                dependency_type=DependencyType.PYTHON,
                is_direct=True
            ),
            Dependency(
                name="express",
                version="4.17.1",
                dependency_type=DependencyType.NPM,
                is_direct=True
            )
        ]

    @pytest.fixture
    def sample_vulnerabilities(self):
        return [
            Vulnerability(
                id="CVE-2023-1234",
                summary="Test vulnerability in requests",
                description="This is a test vulnerability",
                severity="HIGH",
                affected_packages=[{"name": "requests", "ecosystem": "PyPI"}],
                references=[],
                published=None,
                modified=None,
                database_specific={}
            )
        ]

    @pytest.mark.asyncio
    async def test_analyze_repository_success(self, engine, sample_request, sample_dependencies, sample_vulnerabilities):
        """Test successful repository analysis - simplified version"""
        # Mock all the services
        with patch.object(engine.repository_service, 'clone_repository') as mock_clone, \
             patch.object(engine.dependency_service, 'extract_dependencies') as mock_extract, \
             patch.object(engine.dependency_service, 'is_dependency_used') as mock_usage, \
             patch.object(engine.triage_service, 'triage_vulnerability') as mock_triage:

            # Setup mocks
            mock_clone.return_value = MagicMock()
            mock_extract.return_value = sample_dependencies
            mock_usage.return_value = True

            # Mock triage service
            mock_triage.return_value = MagicMock(
                is_real_threat=True,
                threat_level=ThreatLevel.HIGH,
                impact_summary="Test impact",
                recommendation="Update package",
                confidence=0.8,
                reasoning="Test reasoning"
            )

            # Mock the entire vulnerability analysis step
            with patch.object(engine, '_analyze_vulnerabilities') as mock_vuln_analysis:
                mock_vuln_analysis.return_value = [
                    (sample_vulnerabilities[0], sample_dependencies[0])
                ]

                # Perform analysis
                response = await engine.analyze_repository(sample_request)

                # Verify response
                assert isinstance(response, AnalysisResponse)
                assert response.repo_url == str(sample_request.repo_url)
                assert response.dependencies_analyzed == 2
                assert response.vulnerabilities_found == 1
                assert response.real_threats == 1
                assert response.analysis_duration > 0
                assert len(response.errors) == 0

    @pytest.mark.asyncio
    async def test_analyze_repository_no_dependencies(self, engine, sample_request):
        """Test analysis when no dependencies are found"""
        with patch.object(engine.repository_service, 'clone_repository') as mock_clone, \
             patch.object(engine.dependency_service, 'extract_dependencies') as mock_extract:

            mock_clone.return_value = MagicMock()
            mock_extract.return_value = []

            response = await engine.analyze_repository(sample_request)

            assert response.dependencies_analyzed == 0
            assert response.vulnerabilities_found == 0
            assert response.real_threats == 0
            assert "No dependencies found" in response.errors[0]

    @pytest.mark.asyncio
    async def test_analyze_repository_error(self, engine, sample_request):
        """Test analysis when an error occurs"""
        with patch.object(engine.repository_service, 'clone_repository') as mock_clone:
            mock_clone.side_effect = Exception("Test error")

            response = await engine.analyze_repository(sample_request)

            assert response.dependencies_analyzed == 0
            assert response.vulnerabilities_found == 0
            assert response.real_threats == 0
            assert "Analysis failed" in response.errors[0]

    def test_generate_repo_context(self, engine, sample_dependencies):
        """Test repository context generation"""
        repo_path = MagicMock()

        # Mock file extensions
        mock_files = [
            MagicMock(suffix='.py'),
            MagicMock(suffix='.js'),
            MagicMock(suffix='.json'),
            MagicMock(suffix='.md')
        ]
        repo_path.rglob.return_value = mock_files

        context = engine._generate_repo_context(repo_path, sample_dependencies)

        assert "2 dependencies" in context
        assert "JavaScript/Node.js dependencies: 1" in context
        assert "Python dependencies: 1" in context
        assert "Direct dependencies: 2, Transitive: 0" in context
        assert ".py" in context
        assert ".js" in context

    def test_calculate_threat_counts(self, engine):
        """Test threat level counting"""
        # Create a proper Vulnerability object
        mock_vuln = Vulnerability(
            id="CVE-TEST",
            summary="Test vulnerability",
            description="Test description",
            severity="HIGH",
            affected_packages=[],
            references=[],
            published=None,
            modified=None,
            database_specific={}
        )

        reports = [
            VulnerabilityReport(
                vulnerability=mock_vuln,
                dependency="test1",
                dependency_version="1.0.0",
                is_real_threat=True,
                threat_level=ThreatLevel.HIGH,
                impact_summary="Test",
                recommendation="Test",
                evidence={},
                triage_confidence=0.8
            ),
            VulnerabilityReport(
                vulnerability=mock_vuln,
                dependency="test2",
                dependency_version="1.0.0",
                is_real_threat=False,
                threat_level=ThreatLevel.MEDIUM,
                impact_summary="Test",
                recommendation="Test",
                evidence={},
                triage_confidence=0.6
            ),
            VulnerabilityReport(
                vulnerability=mock_vuln,
                dependency="test3",
                dependency_version="1.0.0",
                is_real_threat=True,
                threat_level=ThreatLevel.HIGH,
                impact_summary="Test",
                recommendation="Test",
                evidence={},
                triage_confidence=0.9
            )
        ]

        counts = engine._calculate_threat_counts(reports)

        assert counts[ThreatLevel.HIGH] == 2
        assert counts[ThreatLevel.MEDIUM] == 1
        assert ThreatLevel.LOW not in counts
        assert ThreatLevel.CRITICAL not in counts

    @pytest.mark.asyncio
    async def test_analyze_repository_with_transitive_dependencies(self, engine, sample_request):
        """Test analysis with transitive dependencies - simplified version"""
        dependencies = [
            Dependency(
                name="requests",
                version="2.25.0",
                dependency_type=DependencyType.PYTHON,
                is_direct=True
            ),
            Dependency(
                name="urllib3",
                version="1.26.0",
                dependency_type=DependencyType.PYTHON,
                is_direct=False,
                parent="requests"
            )
        ]

        with patch.object(engine.repository_service, 'clone_repository') as mock_clone, \
             patch.object(engine.dependency_service, 'extract_dependencies') as mock_extract, \
             patch.object(engine.dependency_service, 'is_dependency_used') as mock_usage, \
             patch.object(engine.triage_service, 'triage_vulnerability') as mock_triage:

            mock_clone.return_value = MagicMock()
            mock_extract.return_value = dependencies
            mock_usage.return_value = True

            mock_triage.return_value = MagicMock(
                is_real_threat=False,
                threat_level=ThreatLevel.LOW,
                impact_summary="No impact",
                recommendation="No action needed",
                confidence=0.9,
                reasoning="No vulnerabilities found"
            )

            # Mock the entire vulnerability analysis step
            with patch.object(engine, '_analyze_vulnerabilities') as mock_vuln_analysis:
                mock_vuln_analysis.return_value = []  # No vulnerabilities

                response = await engine.analyze_repository(sample_request)

                assert response.dependencies_analyzed == 2
                assert response.vulnerabilities_found == 0
                assert response.real_threats == 0
