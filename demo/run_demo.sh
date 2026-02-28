#!/usr/bin/env bash
# ca9 demo — run from repo root: bash demo/run_demo.sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"

if [ ! -d "$VENV_DIR" ]; then
    echo "Demo not set up yet. Run:  bash demo/setup_demo.sh"
    exit 1
fi

source "$VENV_DIR/bin/activate"
cd "$REPO_ROOT"

echo "================================================"
echo "  ca9 — CVE Reachability Analysis Demo"
echo "================================================"
echo ""
echo "This is a real Flask weather dashboard with 19 pinned dependencies."
echo "The app only imports: flask, requests, yaml, colorama"
echo ""

if [ -f "$SCRIPT_DIR/coverage.json" ]; then
    echo "Scanning installed packages for real CVEs via OSV.dev,"
    echo "then checking reachability with real coverage data ..."
    echo ""
    ca9 scan --repo "$SCRIPT_DIR" --coverage "$SCRIPT_DIR/coverage.json" -v
else
    echo "Scanning installed packages for real CVEs via OSV.dev ..."
    echo ""
    ca9 scan --repo "$SCRIPT_DIR" -v
fi
