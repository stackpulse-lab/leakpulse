.PHONY: test lint scan build clean

test:
	python3 run_tests.py

lint:
	python3 -m compileall -q src tests
	PYTHONPATH=src python3 -c "import leakpulse, leakpulse.cli, leakpulse.scanner, leakpulse.rules, leakpulse.entropy"

scan:
	PYTHONPATH=src python3 -m leakpulse scan . --history 0 --fail-on high

build:
	python3 -m build

clean:
	rm -rf build dist src/*.egg-info .pytest_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
