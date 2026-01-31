# AuditGraph Backend - Directory Structure

Reference document for the enterprise-grade Python project structure.

## Directory Layout

```
backend/
├── pyproject.toml              # Package metadata, dependencies, tool config
├── requirements.txt            # Pinned dependencies for production
├── .env                        # Environment variables (not in git)
├── .env.example                # Template for environment variables
│
├── app/                        # Main application package
│   ├── __init__.py
│   ├── main.py                 # Flask application entry point
│   ├── database.py             # Database connection and operations
│   ├── scheduler.py            # Background task scheduling
│   │
│   ├── api/                    # HTTP API layer
│   │   ├── __init__.py
│   │   ├── routes.py           # Flask blueprint registration
│   │   └── handlers.py         # Request handlers / controllers
│   │
│   ├── engines/                # Business logic engines
│   │   ├── __init__.py         # Exports: DriftDetector
│   │   ├── drift_detector.py   # Change detection between runs
│   │   └── discovery/          # Azure discovery engine
│   │       ├── __init__.py
│   │       ├── azure_discovery.py
│   │       ├── models.py
│   │       ├── activity_tracker.py
│   │       └── credential_checker.py
│   │
│   ├── core/                   # Shared utilities and helpers
│   │   └── __init__.py
│   │
│   ├── db/                     # Database abstraction layer
│   │   └── __init__.py
│   │
│   └── services/               # Service layer (external integrations)
│       └── __init__.py
│
├── tests/                      # Test suite (isolated from source)
│   ├── __init__.py
│   ├── conftest.py             # Pytest fixtures and configuration
│   ├── test_discovery.py       # Discovery engine tests
│   └── test_drift.py           # Drift detection tests
│
├── scripts/                    # Utility shell scripts
│   └── ...
│
├── migrations/                 # Database migration files
│   └── ...
│
└── venv/                       # Virtual environment (not in git)
```

## Layer Responsibilities

| Layer | Directory | Purpose |
|-------|-----------|---------|
| **API** | `app/api/` | HTTP routes, request/response handling |
| **Services** | `app/services/` | External API integrations, business orchestration |
| **Engines** | `app/engines/` | Core business logic, algorithms |
| **Core** | `app/core/` | Shared utilities, helpers, constants |
| **DB** | `app/db/` | Database models, queries, migrations |

## Import Patterns

```python
# From anywhere in the project
from app.database import Database
from app.engines import DriftDetector
from app.engines.discovery.azure_discovery import AzureDiscoveryEngine
from app.api.handlers import get_identities
```

## Running the Application

```bash
# Install as editable package
pip install -e .

# Install with dev dependencies
pip install -e ".[dev]"

# Run the Flask app
python -m app.main

# Run tests
pytest

# Run specific test file
pytest tests/test_discovery.py

# Run tests with coverage
pytest --cov=app
```

## Adding New Components

### New Engine
1. Create file in `app/engines/` (e.g., `compliance_checker.py`)
2. Add export to `app/engines/__init__.py`
3. Create tests in `tests/test_compliance.py`

### New API Endpoint
1. Add handler in `app/api/handlers.py`
2. Register route in `app/api/routes.py`
3. Add tests in `tests/test_api.py`

### New Service Integration
1. Create file in `app/services/` (e.g., `slack_notifier.py`)
2. Add export to `app/services/__init__.py`

## File Naming Conventions

| Type | Pattern | Example |
|------|---------|---------|
| Module | `snake_case.py` | `drift_detector.py` |
| Test | `test_<module>.py` | `test_drift.py` |
| Class | `PascalCase` | `DriftDetector` |
| Function | `snake_case` | `compare_runs()` |
| Constant | `UPPER_SNAKE` | `MAX_RETRY_COUNT` |

---

*Document created: 2026-01-31*
*Structure version: 1.0*
