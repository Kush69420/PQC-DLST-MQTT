.PHONY: all setup test benchmarks reproduce clean

PYTHON = venv/bin/python
PIP = venv/bin/pip
PYTEST = venv/bin/pytest

all: reproduce

setup:
	@echo "Setting up virtual environment and installing dependencies..."
	python3 -m venv venv
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt

test:
	@echo "Running verification unit tests..."
	$(PYTEST) tests/

benchmarks:
	@echo "Running all simulation benchmarks..."
	@mkdir -p results
	$(PYTHON) -m benchmarks.r1_microbenchmarks
	$(PYTHON) -m benchmarks.r2_communication
	$(PYTHON) -m benchmarks.r3_scalability
	$(PYTHON) -m benchmarks.plot_r3
	$(PYTHON) -m benchmarks.r4_latency

reproduce: test benchmarks
	@echo "================================================================================"
	@echo "All benchmarks completed successfully! Summary results are saved in 'results/'."
	@echo "================================================================================"

clean:
	rm -rf __pycache__ benchmarks/__pycache__ src/__pycache__ src/*/__pycache__ tests/__pycache__
	rm -f server.crt server.key
