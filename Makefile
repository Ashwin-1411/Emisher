.PHONY: test lint fmt run ext-build ext-test

# Windows without make: run the same commands from the `backend/` directory by hand.
test:
	cd backend && python -m pytest -q

lint:
	cd backend && python -m ruff check . && python -m ruff format --check .

fmt:
	cd backend && python -m ruff check --fix . && python -m ruff format .

run:
	cd backend && python -m uvicorn app.main:app --reload

ext-build:
	cd extension && npm install && npm run build

ext-test:
	cd extension && npm test
