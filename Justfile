# Justfile — task runner for the E2E Chat project
# Install: https://github.com/casey/just

# Default: list tasks
default:
    @just --list

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

# Copy .env.example to .env (run once)
setup:
    cp .env.example .env
    @echo "Edit .env with your secrets before running docker-compose up"

# ---------------------------------------------------------------------------
# Docker
# ---------------------------------------------------------------------------

# Start all services
up:
    docker-compose up -d

# Start with rebuild
up-build:
    docker-compose up -d --build

# Stop all services
down:
    docker-compose down

# View logs
logs service="":
    docker-compose logs -f {{service}}

# ---------------------------------------------------------------------------
# Backend (local dev without Docker)
# ---------------------------------------------------------------------------

# Install Python dependencies
install-backend:
    cd backend && uv pip install -e ".[dev]"

# Run backend dev server
dev-backend:
    cd backend && uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Run crypto test suite
test-crypto:
    cd backend && python -m pytest tests/test_crypto.py -v

# Run all tests with coverage
test:
    cd backend && python -m pytest --cov=app --cov-report=term-missing -v

# Lint backend
lint-backend:
    cd backend && ruff check .

# Type-check backend
typecheck-backend:
    cd backend && mypy app/

# ---------------------------------------------------------------------------
# Frontend (local dev)
# ---------------------------------------------------------------------------

# Install frontend dependencies
install-frontend:
    cd frontend && npm install

# Run frontend dev server
dev-frontend:
    cd frontend && npm run dev

# Build frontend
build-frontend:
    cd frontend && npm run build

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

# Run database migrations (create tables)
migrate:
    cd backend && python -c "import asyncio; from app.models.Base import init_db; asyncio.run(init_db())"

# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

# Generate a new SECRET_KEY
gen-secret:
    python -c "import secrets; print(secrets.token_hex(32))"

# Check Docker services health
health:
    @echo "=== Service Health ==="
    @curl -sf http://localhost:8000/health | python -m json.tool || echo "Backend: UNREACHABLE"
    @docker-compose ps
