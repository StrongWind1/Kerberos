.PHONY: docs serve lint lint-ps test test-js test-ps html a11y check clean distclean

# Scratch output for the HTML and accessibility checks; never deployed.
SITE := site
PORT := 8765

docs:
	uv run --locked --group docs mkdocs build --strict

serve:
	uv run --group docs mkdocs serve

# --- lint ---------------------------------------------------------------------
lint: lint-ps
	uvx yamllint@1.38.0 --strict -c .yamllint.yml .
	uvx ruff@0.17.3 check hooks tools
	uvx ruff@0.17.3 format --check hooks tools
	npm run --silent lint

# Every PowerShell file and every powershell block in the docs must be unchanged by
# Invoke-Formatter and clean under Invoke-ScriptAnalyzer (PSScriptAnalyzerSettings.psd1).
lint-ps:
	pwsh -NoProfile -File tools/Test-PowerShellStyle.ps1
	python3 tools/ps_snippets.py

# --- tests --------------------------------------------------------------------
test: test-js test-ps

test-js:
	npm test --silent

test-ps:
	pwsh -NoProfile -Command "\$$c = New-PesterConfiguration; \$$c.Run.Path = 'tests/ps'; \$$c.Run.Exit = \$$true; Invoke-Pester -Configuration \$$c"

# --- built-site checks ----------------------------------------------------------
# Nu HTML Checker over every built page: zero errors, warnings or info messages.
html: docs
	npm run --silent html

# pa11y at WCAG 2 AAA over every page in the sitemap, light and dark schemes.
a11y: docs
	npm run --silent a11y

check: docs lint test html a11y

clean:
	rm -rf $(SITE)/ .cache/ .ruff_cache/ .pytest_cache/
	find . -path ./.venv -prune -o -path ./node_modules -prune -o -type d -name '__pycache__' -exec rm -rf {} +
	find . -path ./.venv -prune -o -path ./node_modules -prune -o -type f -name '*.py[co]' -exec rm -f {} +

distclean: clean
	rm -rf .venv/ node_modules/
