# Enterprise Security Scanner Foundation

This project establishes the foundational architecture for the enterprise security scanner.

## Features
- **Dependency Injection**: Powered by `dependency-injector`.
- **Configuration Management**: Powered by `pydantic-settings` and `PyYAML`.
- **Structured Logging**: Powered by `structlog`.
- **Error Handling**: Custom exception hierarchy.
- **Application Lifecycle**: Managed service startup and shutdown.

## Quickstart

### Prerequisites
- Python 3.13+
- Poetry

### Installation
```bash
poetry install
```

### Running Tests
```bash
poetry run pytest tests/
```
