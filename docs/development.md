# Development

FastSMTP is a uv workspace with two packages: `fastsmtp` (server) and `fastsmtp-cli` (remote client).

```bash
# Install dev dependencies for both workspace packages
uv sync --all-packages --dev

# Run tests
uv run pytest

# Run tests with coverage
uv run pytest --cov=fastsmtp --cov-report=term-missing

# Lint and format
uv run ruff check .
uv run ruff format .
```

## Documentation

This site is built with [Zensical](https://zensical.org/). To work on it locally:

```bash
# Install docs dependencies
uv sync --group docs

# Live-preview at http://localhost:8000
uv run zensical serve

# Build the static site into site/
uv run zensical build --clean
```

The site is deployed to GitHub Pages automatically on every push to `main` by the `Documentation` workflow.

## License

AGPL-3.0 — see the [LICENSE](https://github.com/jsenecal/fastsmtp/blob/main/LICENSE) file for details.
