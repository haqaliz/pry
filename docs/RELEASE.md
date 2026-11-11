# Release Checklist

The PyPI name `pry` is already taken. The distribution is **`pry-scanner`**; the installed
command is still **`pry`**.

## Before tagging

1. `git switch master && git pull --ff-only`
2. Update the version in both places:
   - `pyproject.toml` → `project.version`
   - `src/pry/__init__.py` → `__version__`
3. Update `CHANGELOG.md` with the new version and date.
4. Run:
   ```bash
   uv sync --frozen
   uv run pytest -q
   PRY_DOCKER_TESTS=1 uv run pytest -q -m docker
   uv build
   uvx twine check dist/*
   ```
5. Commit, push, and tag:
   ```bash
   git add pyproject.toml src/pry/__init__.py CHANGELOG.md
   git commit -m "release: vX.Y.Z"
   git push origin master
   git tag -a vX.Y.Z -m "Pry vX.Y.Z"
   git push origin vX.Y.Z
   ```

The tag triggers `.github/workflows/release.yml`, which runs the tests, builds the wheel and
sdist, and creates or updates the GitHub release with generated notes and the artifacts.

## PyPI (optional, one-time setup)

Trusted publishing is used; there is no long-lived token.

1. On PyPI, create the project `pry-scanner` and configure a trusted publisher for:
   - owner: `haqaliz`
   - repository: `pry`
   - workflow: `release.yml`
   - environment: `pypi`
2. In the GitHub repository, create an environment named `pypi`.
3. Add a repository variable `PYPI_PUBLISH` with value `true`.

The `pypi` job is skipped unless that variable is `true`. To publish manually:

```bash
uv build
uvx twine upload dist/*   # TWINE_USERNAME=__token__, TWINE_PASSWORD=pypi-...
```

## Verify the release

```bash
uv tool install pry-scanner
pry --version
pry --help
```

Or from the GitHub tag before PyPI is configured:

```bash
uv tool install "pry-scanner @ git+https://github.com/haqaliz/pry@vX.Y.Z"
```

## After release

- Confirm the GitHub release has `pry_scanner-X.Y.Z-py3-none-any.whl` and the sdist.
- Run one local fixture scan and one `--headers` scan as a smoke test.
- Update the README install line if the distribution name changes.
