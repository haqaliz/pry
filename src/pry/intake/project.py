"""Decide what a repository is, copy exactly what will run, and hash the copy."""

import hashlib
import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from pry.intake.errors import (
    COPY_FAILED,
    REPO_NOT_FOUND,
    UNSUPPORTED_PROJECT,
    IntakeError,
)

EXCLUDED = frozenset(
    {
        ".git",
        "node_modules",
        ".venv",
        "dist",
        "build",
        ".next",
        "__pycache__",
        ".pytest_cache",
    }
)

STATIC_IMAGE = "python:3.9-slim"
NODE_IMAGE = "node:22-bookworm-slim"
STATIC_PORT = 8000
NODE_PORT = 3000

_NPM_INSTALL = ["npm", "install", "--no-audit", "--no-fund"]
_NPM_CI = ["npm", "ci"]


@dataclass(frozen=True)
class ProjectSpec:
    kind: str
    image: str
    port: int
    install: Optional[List[str]]
    build: Optional[List[str]]
    start: List[str]
    package_manager: Optional[str]


def _static_spec() -> ProjectSpec:
    return ProjectSpec(
        kind="static",
        image=STATIC_IMAGE,
        port=STATIC_PORT,
        install=None,
        build=None,
        start=[
            "python",
            "-m",
            "http.server",
            "8000",
            "--directory",
            "/app",
            "--bind",
            "127.0.0.1",
        ],
        package_manager=None,
    )


def _script(scripts: dict, name: str) -> Optional[str]:
    value = scripts.get(name)
    if isinstance(value, str) and value.strip():
        return value
    return None


def _load_package_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise IntakeError(
            UNSUPPORTED_PROJECT, "invalid package.json: %s" % exc
        ) from exc
    if not isinstance(data, dict):
        raise IntakeError(UNSUPPORTED_PROJECT, "package.json is not an object")
    return data


def _node_spec(root: Path, data: dict) -> Optional[ProjectSpec]:
    scripts = data.get("scripts")
    if not isinstance(scripts, dict):
        return None

    start = _script(scripts, "start")
    dev = _script(scripts, "dev")
    command = ["npm", "run", "start"] if start else None
    if command is None and dev:
        command = ["npm", "run", "dev"]
    if command is None:
        return None

    if (root / "package-lock.json").is_file():
        install = list(_NPM_CI)
    elif (root / "yarn.lock").exists() or (root / "pnpm-lock.yaml").exists():
        raise IntakeError(
            UNSUPPORTED_PROJECT,
            "only npm is supported; found a yarn or pnpm lockfile",
        )
    else:
        install = list(_NPM_INSTALL)

    build = ["npm", "run", "build"] if _script(scripts, "build") else None
    return ProjectSpec(
        kind="node",
        image=NODE_IMAGE,
        port=NODE_PORT,
        install=install,
        build=build,
        start=command,
        package_manager="npm",
    )


def detect_project(root: Path) -> ProjectSpec:
    root = Path(root)
    package_json = root / "package.json"
    if package_json.is_file():
        spec = _node_spec(root, _load_package_json(package_json))
        if spec is not None:
            return spec
    if (root / "index.html").is_file():
        return _static_spec()
    raise IntakeError(
        UNSUPPORTED_PROJECT, "no static index.html or npm start/dev script in %s" % root
    )


def copy_repo(src: Path) -> Path:
    src = Path(src)
    if not src.is_dir():
        raise IntakeError(REPO_NOT_FOUND, "not a directory: %s" % src)

    dest = Path(tempfile.mkdtemp(prefix="pry-intake-"))
    try:
        shutil.copytree(
            str(src),
            str(dest),
            symlinks=True,
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns(*EXCLUDED),
        )
    except (OSError, shutil.Error) as exc:
        shutil.rmtree(str(dest), ignore_errors=True)
        raise IntakeError(COPY_FAILED, "cannot copy %s: %s" % (src, exc)) from exc
    return dest


def _hash_tree(root: Path, current: Path, digest) -> None:
    with os.scandir(str(current)) as scan:
        entries = sorted(scan, key=lambda entry: entry.name)

    for entry in entries:
        if entry.name in EXCLUDED:
            continue
        relative = os.path.relpath(entry.path, str(root))
        name = os.fsencode(relative.replace(os.sep, "/"))
        if entry.is_symlink():
            digest.update(name)
            digest.update(b"\0link\0")
            digest.update(os.fsencode(os.readlink(entry.path)))
            digest.update(b"\0")
        elif entry.is_dir(follow_symlinks=False):
            _hash_tree(root, Path(entry.path), digest)
        elif entry.is_file(follow_symlinks=False):
            digest.update(name)
            digest.update(b"\0file\0")
            with open(entry.path, "rb") as handle:
                for chunk in iter(lambda: handle.read(65536), b""):
                    digest.update(chunk)
            digest.update(b"\0")


def tree_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    try:
        _hash_tree(Path(root), Path(root), digest)
    except OSError as exc:
        raise IntakeError(COPY_FAILED, "cannot hash %s: %s" % (root, exc)) from exc
    return digest.hexdigest()
