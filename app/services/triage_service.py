import os
from typing import List, Dict, Any
from langchain_openai import OpenAI
from langchain.prompts import PromptTemplate
from langchain.output_parsers import PydanticOutputParser
import json

from ..models.dependency import Dependency
from ..models.vulnerability import Vulnerability, ThreatLevel
from ..models.analysis import TriageResult


class TriageService:
    """Service for LLM-based vulnerability triage"""

    def __init__(self, openai_api_key: str = None):
        self.openai_api_key = openai_api_key or os.getenv("OPENAI_API_KEY")
        if not self.openai_api_key:
            raise ValueError("OpenAI API key is required for triage service")

        self.llm = OpenAI(
            api_key=self.openai_api_key,
            temperature=0.1,  # Low temperature for consistent results
            max_tokens=1000
        )

        # Create the prompt template
        self.prompt_template = PromptTemplate(
            input_variables=[
                "vulnerability_id",
                "vulnerability_summary",
                "vulnerability_description",
                "dependency_name",
                "dependency_version",
                "dependency_type",
                "is_direct_dependency",
                "is_dependency_used",
                "repo_context"
            ],
            template="""
You are a cybersecurity expert analyzing a vulnerability in a software dependency. Your task is to determine if this vulnerability represents a real threat in the specific context provided.

Vulnerability Information:
- ID: {vulnerability_id}
- Summary: {vulnerability_summary}
- Description: {vulnerability_description}

Dependency Information:
- Name: {dependency_name}
- Version: {dependency_version}
- Type: {dependency_type}
- Is Direct Dependency: {is_direct_dependency}
- Is Dependency Used in Code: {is_dependency_used}

Repository Context:
{repo_context}

Based on this information, analyze whether this vulnerability represents a real threat in this specific context. Consider:

1. Whether the vulnerability is actually exploitable given how the dependency is used
2. The severity and impact of the vulnerability
3. Whether the dependency is actually imported/used in the codebase
4. The specific context of the repository (type of application, etc.)

Provide your analysis in the following JSON format:
{{
    "is_real_threat": true/false,
    "threat_level": "critical/high/medium/low/info",
    "impact_summary": "Brief summary of potential impact",
    "recommendation": "Specific action to take",
    "confidence": 0.0-1.0,
    "reasoning": "Detailed explanation of your assessment"
}}

Analysis:
"""
        )

        # Create output parser
        self.output_parser = PydanticOutputParser(pydantic_object=TriageResult)

    async def triage_vulnerability(
        self,
        vulnerability: Vulnerability,
        dependency: Dependency,
        repo_context: str,
        is_dependency_used: bool
    ) -> TriageResult:
        """
        Triage a vulnerability using LLM analysis

        Args:
            vulnerability: The vulnerability to analyze
            dependency: The affected dependency
            repo_context: Context about the repository
            is_dependency_used: Whether the dependency is actually used

        Returns:
            TriageResult with the analysis
        """
        try:
            # Prepare the prompt
            prompt = self.prompt_template.format(
                vulnerability_id=vulnerability.id,
                vulnerability_summary=vulnerability.summary,
                vulnerability_description=vulnerability.description or "No description available",
                dependency_name=dependency.name,
                dependency_version=dependency.version,
                dependency_type=dependency.dependency_type,
                is_direct_dependency=dependency.is_direct,
                is_dependency_used=is_dependency_used,
                repo_context=repo_context
            )

            # Get LLM response
            response = await self.llm.agenerate([prompt])
            response_text = response.generations[0][0].text.strip()

            # Parse the response
            try:
                # Try to extract JSON from the response
                json_start = response_text.find('{')
                json_end = response_text.rfind('}') + 1
                if json_start >= 0 and json_end > json_start:
                    json_str = response_text[json_start:json_end]
                    triage_data = json.loads(json_str)

                    return TriageResult(
                        is_real_threat=triage_data["is_real_threat"],
                        threat_level=ThreatLevel(triage_data["threat_level"]),
                        impact_summary=triage_data["impact_summary"],
                        recommendation=triage_data["recommendation"],
                        confidence=triage_data["confidence"],
                        reasoning=triage_data["reasoning"]
                    )
                else:
                    raise ValueError("No JSON found in response")

            except (json.JSONDecodeError, KeyError, ValueError) as e:
                # Fallback to default triage if parsing fails
                return self._fallback_triage(vulnerability, dependency, is_dependency_used)

        except Exception as e:
            print(f"Error in LLM triage for {vulnerability.id}: {e}")
            return self._fallback_triage(vulnerability, dependency, is_dependency_used)

    def _fallback_triage(
        self,
        vulnerability: Vulnerability,
        dependency: Dependency,
        is_dependency_used: bool
    ) -> TriageResult:
        """
        Fallback triage logic when LLM analysis fails

        Args:
            vulnerability: The vulnerability to analyze
            dependency: The affected dependency
            is_dependency_used: Whether the dependency is actually used

        Returns:
            TriageResult with basic analysis
        """
        # Simple rule-based triage
        is_real_threat = is_dependency_used and dependency.is_direct

        # Determine threat level based on severity
        severity = vulnerability.severity or "unknown"
        if severity.lower() in ["critical", "high"]:
            threat_level = ThreatLevel.HIGH if is_real_threat else ThreatLevel.MEDIUM
        elif severity.lower() == "medium":
            threat_level = ThreatLevel.MEDIUM if is_real_threat else ThreatLevel.LOW
        else:
            threat_level = ThreatLevel.LOW

        impact_summary = f"Vulnerability in {dependency.name} {dependency.version}"
        if is_real_threat:
            recommendation = f"Update {dependency.name} to a patched version"
        else:
            recommendation = "Monitor for updates but no immediate action required"

        return TriageResult(
            is_real_threat=is_real_threat,
            threat_level=threat_level,
            impact_summary=impact_summary,
            recommendation=recommendation,
            confidence=0.5,  # Lower confidence for fallback
            reasoning="Fallback analysis used due to LLM processing error"
        )

    async def triage_vulnerabilities_batch(
        self,
        vulnerabilities: List[Vulnerability],
        dependencies: List[Dependency],
        repo_context: str,
        dependency_usage: Dict[str, bool]
    ) -> List[TriageResult]:
        """
        Triage multiple vulnerabilities in parallel

        Args:
            vulnerabilities: List of vulnerabilities to analyze
            dependencies: List of affected dependencies
            repo_context: Context about the repository
            dependency_usage: Dictionary mapping dependency names to usage status

        Returns:
            List of triage results
        """
        # Create a mapping of dependency names to dependency objects
        dep_map = {dep.name: dep for dep in dependencies}

        # Process vulnerabilities in parallel
        tasks = []
        for vuln in vulnerabilities:
            # Find the corresponding dependency
            dep_name = None
            for affected in vuln.affected_packages:
                if affected.get("name") in dep_map:
                    dep_name = affected.get("name")
                    break

            if dep_name and dep_name in dep_map:
                task = self.triage_vulnerability(
                    vuln,
                    dep_map[dep_name],
                    repo_context,
                    dependency_usage.get(dep_name, True)
                )
                tasks.append(task)

        # Execute all triage tasks
        results = []
        for task in tasks:
            try:
                result = await task
                results.append(result)
            except Exception as e:
                print(f"Error in batch triage: {e}")
                # Add a fallback result
                results.append(self._fallback_triage(vuln, dep_map[dep_name], True))

        return results
