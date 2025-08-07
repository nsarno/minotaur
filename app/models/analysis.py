from datetime import datetime
from typing import Dict, List, Optional, Any

from pydantic import BaseModel, ConfigDict, HttpUrl

from app.models.dependency import Dependency
from app.models.vulnerability import VulnerabilityReport, ThreatLevel


class AnalysisRequest(BaseModel):
    """Request for repository analysis"""
    repo_url: HttpUrl
    include_transitive: bool = True
    max_dependencies: int = 1000
    triage_threshold: float = 0.7

    model_config = ConfigDict(from_attributes=True)


class TriageResult(BaseModel):
    """Result of LLM-based vulnerability triage"""
    is_real_threat: bool
    threat_level: ThreatLevel
    impact_summary: str
    recommendation: str
    confidence: float
    reasoning: str

    model_config = ConfigDict(from_attributes=True)


class AnalysisResponse(BaseModel):
    """Response from repository analysis"""
    report_id: str
    repo_url: str
    analysis_timestamp: datetime
    dependencies_analyzed: int
    vulnerabilities_found: int
    real_threats: int
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    vulnerability_reports: List[VulnerabilityReport] = []
    dependencies: List[Dependency] = []
    analysis_duration: float
    errors: List[str] = []

    model_config = ConfigDict(from_attributes=True)
