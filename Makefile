.PHONY: install dev test lint format skylos clean

install:
	pip install -e .

dev:
	pip install -e ".[dev]"
	pre-commit install

test:
	pytest tests/ -v

lint:
	ruff check src/ tests/
	ruff format --check src/ tests/

format:
	ruff check --fix src/ tests/
	ruff format src/ tests/

skylos:
	@python -c "\
	import pathlib, importlib.util; \
	spec = importlib.util.find_spec('skylos.visitors.languages.go.go'); \
	p = pathlib.Path(spec.origin) if spec else None; \
	p and 'try:' not in p.read_text() and p.write_text(p.read_text().replace( \
	  'from skylos.engines.go_runner import run_go_engine_for_module', \
	  'try:\n    from skylos.engines.go_runner import run_go_engine_for_module\nexcept ModuleNotFoundError:\n    run_go_engine_for_module = None')) \
	" 2>/dev/null || true
	skylos src/

clean:
	rm -rf build/ dist/ *.egg-info src/*.egg-info .pytest_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
