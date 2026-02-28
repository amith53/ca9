#!/usr/bin/env bash
# Sets up the demo environment: venv, deps, tests with coverage.
# Run from the repo root: bash demo/setup_demo.sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"

echo "=== Setting up demo environment ==="

# Create isolated venv for the demo
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtualenv at demo/.venv ..."
    python3 -m venv "$VENV_DIR"
fi

source "$VENV_DIR/bin/activate"

echo "Installing demo dependencies ..."
pip install -q -r "$SCRIPT_DIR/requirements.txt"

echo "Installing ca9 + test tools ..."
pip install -q -e "$REPO_ROOT[dev]"
pip install -q coverage

SITE_PKGS="$(python3 -c "import site; print(site.getsitepackages()[0])")"

echo ""
echo "Running demo tests with coverage ..."
cd "$SCRIPT_DIR"

# Measure coverage of the app + key dependency packages
coverage run \
    --source="$SCRIPT_DIR,$SITE_PKGS/flask,$SITE_PKGS/requests,$SITE_PKGS/werkzeug,$SITE_PKGS/jinja2,$SITE_PKGS/yaml,$SITE_PKGS/colorama,$SITE_PKGS/urllib3,$SITE_PKGS/certifi,$SITE_PKGS/dateutil,$SITE_PKGS/markdown" \
    -m pytest test_app.py -v 2>&1 | grep -v "CoverageWarning"

coverage json -o coverage.json
cd "$REPO_ROOT"

echo ""
echo "=== Setup complete ==="
echo "Coverage data written to demo/coverage.json"
echo ""
echo "Now run the demo:"
echo "  bash demo/run_demo.sh"
