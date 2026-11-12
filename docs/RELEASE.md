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

## PyPI (one-time setup)

Trusted publishing is used; there is no long-lived token in GitHub.

1. On PyPI, open <https://pypi.org/manage/account/publishing/> and add a **pending trusted
   publisher** for a new project. PyPI creates the project on the first publish.
   - PyPI project name: `pry-scanner`
   - Owner: `haqaliz`
   - Repository name: `pry`
   - Workflow name: `release.yml`
   - Environment name: `pypi`
2. In GitHub, open **Settings → Environments → New environment** and create `pypi`. No secret
   is required. Optionally add required reviewers.
3. In **Settings → Secrets and variables → Actions → Variables**, add `PYPI_PUBLISH` with value
   `true`.
4. Push a tag `vX.Y.Z`. The `pypi` job is skipped unless `PYPI_PUBLISH` is `true`. It publishes
   the exact wheel and sdist built and tested by the `build` job.

The PyPI name `pry` is taken. Do not change the distribution name to `pry`.

### First publish (v0.1.1)

`v0.1.0` was not published to PyPI. `v0.1.1` is the first release through trusted publishing.
If a future tag predates a workflow fix, upload manually once:

```bash
uv build
uvx twine upload dist/*   # TWINE_USERNAME=__token__, TWINE_PASSWORD=pypi-...
```

Manual upload is only the fallback; tags use the workflow.

### Manual upload

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

After the first PyPI publish, move `uv tool install pry-scanner` above the GitHub-tag install in
the README.

Or from the GitHub tag before PyPI is configured:

```bash
uv tool install "pry-scanner @ git+https://github.com/haqaliz/pry@vX.Y.Z"
```

## After release

- Confirm the GitHub release has `pry_scanner-X.Y.Z-py3-none-any.whl` and the sdist.
- Run one local fixture scan and one `--headers` scan as a smoke test.
- Update the README install line if the distribution name changes.
