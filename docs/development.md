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

## Migration tests

Most tests build their schema straight from the models with
`Base.metadata.create_all`, so the Alembic chain never runs. `fastsmtp/tests/test_migrations.py`
covers it separately: it applies the chain to a throwaway database, rolls it back to base and
re-applies it, then diffs the result against `Base.metadata` and fails on any difference. A model
change merged without its migration fails there instead of on deploy.

Those tests are marked `migrations` and always run in CI. Each one needs its own database and
shells out to `alembic`, so deselect them when that overhead is not worth it locally:

```bash
uv run pytest -m "not migrations"
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
