.PHONY: docs serve clean

docs:
	uv run --group docs mkdocs build --strict

serve:
	uv run --group docs mkdocs serve

clean:
	rm -rf site/ .cache
