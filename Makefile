# HEEL — one-command bring-up (spec §11). Pure stdlib: no installs needed.
PY ?= python3

.PHONY: demo test mcp scenarios clean help

help:
	@echo "make demo   - synthetic coverage backtest + auth-gate proof (over the MCP boundary)"
	@echo "make test   - acceptance + safety tests (auth gate, scope tamper-evidence, coverage)"
	@echo "make mcp    - run the MCP server (stdio JSON-RPC) for a real MCP client"
	@echo "make scenarios - print the seed scenario library"

demo:
	$(PY) run_demo.py

test:
	$(PY) -m unittest discover -s tests -p 'test_*.py' -v

mcp:
	$(PY) -m heel.mcp_server

scenarios:
	$(PY) -m heel.cli scenarios

clean:
	find . -name '__pycache__' -type d -prune -exec rm -rf {} + ; rm -rf .heel
