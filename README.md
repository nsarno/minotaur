# Minotaur - Dependency Threat Radar

A cybersecurity tool that analyzes public GitHub repositories to identify and prioritize known vulnerabilities in dependencies based on their actual risk in the specific codebase.

## Features

- **Repository Analysis**: Clones and analyzes any public GitHub repository
- **Multi-language Support**: Supports JavaScript (npm) and Python (pip/poetry) dependencies
- **Vulnerability Detection**: Queries OSV.dev for known CVEs affecting dependencies
- **Intelligent Triage**: Uses LLM analysis to determine if vulnerabilities are actually exploitable
- **Structured Reporting**: Generates detailed reports with threat levels and actionable recommendations

## Architecture

```
minotaur/
├── app/                    # FastAPI application
│   ├── api/               # API endpoints
│   ├── core/              # Core business logic
│   ├── models/            # Pydantic models
│   └── services/          # External service integrations
├── tests/                 # Test suite
├── config/                # Configuration files
└── reports/               # Generated reports
```

## Quick Start

1. **Install dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

2. **Set up environment variables**:

   ```bash
   # Run the setup script (recommended)
   python setup.py

   # Or manually copy and configure
   cp env.example .env
   # Edit .env and add your OpenAI API key
   ```

3. **Run the application**:

   ```bash
   uvicorn app.main:app --reload
   ```

4. **Analyze a repository**:

   **Using the CLI tool:**

   ```bash
   # Simple analysis
   python minotaur https://github.com/username/repo-name

   # Interactive mode
   python minotaur-interactive

   # With options
   python minotaur https://github.com/username/repo-name --format summary --save-report report.json

   # Check configuration
   python minotaur --check

   # Run setup
   python minotaur --setup
   ```

   **Using the API:**

   ```bash
   curl -X POST "http://localhost:8000/api/v1/analyze" \
        -H "Content-Type: application/json" \
        -d '{"repo_url": "https://github.com/username/repo-name"}'
   ```

## CLI Usage

Minotaur provides two CLI tools for easy usage:

### Command Line Interface (`minotaur`)

```bash
# Basic usage
python minotaur https://github.com/username/repo-name

# Options
python minotaur https://github.com/username/repo-name \
  --format summary \
  --no-transitive \
  --max-deps 500 \
  --save-report report.json

# Configuration
python minotaur --setup    # Run initial setup
python minotaur --check    # Check configuration
```

### Interactive Interface (`minotaur-interactive`)

```bash
python minotaur-interactive
```

The interactive tool guides you through the analysis process with prompts for:

- Repository URL
- Analysis options
- Output format
- Report saving

## API Endpoints

- `POST /api/v1/analyze` - Analyze a GitHub repository for vulnerabilities
- `GET /api/v1/health` - Health check endpoint
- `GET /api/v1/reports/{report_id}` - Retrieve a specific analysis report
- `GET /api/v1/reports` - List all available reports
- `DELETE /api/v1/reports/{report_id}` - Delete a specific report

## Configuration

The tool can be configured via environment variables in a `.env` file. Copy `env.example` to `.env` and update the values:

### Required Configuration

- `OPENAI_API_KEY`: Required for LLM-based vulnerability triage

### Optional Configuration

- `OPENAI_MODEL`: OpenAI model to use (default: gpt-3.5-turbo)
- `OPENAI_TEMPERATURE`: LLM temperature setting (default: 0.1)
- `OPENAI_MAX_TOKENS`: Maximum tokens for LLM responses (default: 1000)
- `OSV_API_BASE_URL`: OSV.dev API base URL (default: https://api.osv.dev)
- `REPO_CLONE_TIMEOUT`: Timeout for repository cloning in seconds (default: 300)
- `MAX_DEPENDENCIES`: Maximum number of dependencies to analyze (default: 1000)
- `TRIAGE_CONFIDENCE_THRESHOLD`: Minimum confidence for triage (default: 0.7)
- `API_HOST`: API server host (default: 0.0.0.0)
- `API_PORT`: API server port (default: 8000)
- `LOG_LEVEL`: Logging level (default: INFO)

## Testing

Run the test suite:

```bash
pytest tests/
```

## License

MIT License
