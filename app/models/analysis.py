from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, Field, HttpUrl

from .vulnerability import VulnerabilityReport, ThreatLevel
from .dependency import Dependency


class AnalysisRequest(BaseModel):
    """Request to analyze a GitHub repository"""
    repo_url: HttpUrl = Field(..., description="GitHub repository URL")
    include_transitive: bool = Field(default=True, description="Include transitive dependencies")
    max_dependencies: Optional[int] = Field(default=1000, description="Maximum dependencies to analyze")
    triage_threshold: float = Field(default=0.7, ge=0.0, le=1.0, description="Minimum confidence for triage")


class TriageResult(BaseModel):
    """Result of LLM-based vulnerability triage"""
    is_real_threat: bool = Field(..., description="Whether vulnerability is exploitable")
    threat_level: ThreatLevel = Field(..., description="Assessed threat level")
    impact_summary: str = Field(..., description="Summary of potential impact")
    recommendation: str = Field(..., description="Recommended action")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in assessment")
    reasoning: str = Field(..., description="LLM reasoning for the assessment")


class AnalysisResponse(BaseModel):
    """Response from repository analysis"""
    report_id: str = Field(..., description="Unique report identifier")
    repo_url: str = Field(..., description="Analyzed repository URL")
    analysis_timestamp: datetime = Field(..., description="When analysis was performed")
    dependencies_analyzed: int = Field(..., description="Number of dependencies analyzed")
    vulnerabilities_found: int = Field(..., description="Total vulnerabilities found")
    real_threats: int = Field(..., description="Number of actual threats")

    # Summary by threat level
    critical_count: int = Field(default=0, description="Critical vulnerabilities")
    high_count: int = Field(default=0, description="High severity vulnerabilities")
    medium_count: int = Field(default=0, description="Medium severity vulnerabilities")
    low_count: int = Field(default=0, description="Low severity vulnerabilities")

    # Detailed results
    vulnerability_reports: List[VulnerabilityReport] = Field(default_factory=list, description="Detailed vulnerability reports")
    dependencies: List[Dependency] = Field(default_factory=list, description="All analyzed dependencies")

    # Analysis metadata
    analysis_duration: float = Field(..., description="Analysis duration in seconds")
    errors: List[str] = Field(default_factory=list, description="Any errors encountered")

    class Config:
        use_enum_values = True
