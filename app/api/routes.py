import os
from typing import Dict, Any
from fastapi import APIRouter, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse

from ..models.analysis import AnalysisRequest, AnalysisResponse
from ..core.analysis_engine import AnalysisEngine

router = APIRouter()

# In-memory storage for reports (in production, use a database)
reports_storage: Dict[str, AnalysisResponse] = {}

# Initialize analysis engine
analysis_engine = AnalysisEngine(
    max_dependencies=int(os.getenv("MAX_DEPENDENCIES", "1000")),
    osv_api_url=os.getenv("OSV_API_BASE_URL", "https://api.osv.dev"),
    openai_api_key=os.getenv("OPENAI_API_KEY")
)


@router.post("/analyze", response_model=AnalysisResponse)
async def analyze_repository(request: AnalysisRequest):
    """
    Analyze a GitHub repository for vulnerabilities

    This endpoint performs a complete vulnerability analysis:
    1. Clones the repository
    2. Extracts dependencies
    3. Queries vulnerability databases
    4. Performs LLM-based triage
    5. Returns a comprehensive report
    """
    try:
        # Perform the analysis
        response = await analysis_engine.analyze_repository(request)

        # Store the report
        reports_storage[response.report_id] = response

        return response

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.get("/reports/{report_id}", response_model=AnalysisResponse)
async def get_report(report_id: str):
    """
    Retrieve a specific analysis report by ID
    """
    if report_id not in reports_storage:
        raise HTTPException(status_code=404, detail="Report not found")

    return reports_storage[report_id]


@router.get("/health")
async def health_check():
    """
    Health check endpoint
    """
    return {
        "status": "healthy",
        "service": "minotaur",
        "version": "1.0.0"
    }


@router.get("/reports")
async def list_reports():
    """
    List all available reports
    """
    return {
        "reports": [
            {
                "report_id": report_id,
                "repo_url": report.repo_url,
                "analysis_timestamp": report.analysis_timestamp,
                "vulnerabilities_found": report.vulnerabilities_found,
                "real_threats": report.real_threats
            }
            for report_id, report in reports_storage.items()
        ]
    }


@router.delete("/reports/{report_id}")
async def delete_report(report_id: str):
    """
    Delete a specific report
    """
    if report_id not in reports_storage:
        raise HTTPException(status_code=404, detail="Report not found")

    del reports_storage[report_id]
    return {"message": "Report deleted successfully"}
