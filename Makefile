# HEEL — one-command bring-up (spec §11). Pure stdlib: no installs needed.
PY ?= python3

.PHONY: demo test mcp rest scenarios clean help

help:
	@echo "make demo   - synthetic coverage backtest + auth-gate proof (over the MCP boundary)"
	@echo "make test   - acceptance + safety tests (auth gate, scope tamper-evidence, coverage)"
	@echo "make mcp    - run the MCP server (stdio JSON-RPC) for a real MCP client"
	@echo "make rest   - run the thin REST API (same auth gate) on :8780"
	@echo "make scenarios - print the seed scenario library"

demo:
	$(PY) run_demo.py

test:
	$(PY) -m unittest discover -s tests -p 'test_*.py' -v

mcp:
	$(PY) -m heel.mcp_server

rest:
	$(PY) -m heel.rest

scenarios:
	$(PY) -m heel.cli scenarios

clean:
	find . -name '__pycache__' -type d -prune -exec rm -rf {} + ; rm -rf .heel
