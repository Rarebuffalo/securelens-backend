.PHONY: setup dev-server cli-install test db-migrate lint clean

setup:
	pip install -r requirements.txt
	pip install -e cli/

dev-server:
	uvicorn app.main:app --reload

cli-install:
	pip install -e cli/

test:
	pytest tests/ -v

db-migrate:
	alembic upgrade head

lint:
	pip install -q black ruff
	black --check app/ cli/ tests/
	ruff check app/ cli/ tests/

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
