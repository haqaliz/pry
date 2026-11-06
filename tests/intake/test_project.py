"""Project detection, copy, and tree hash tests (AT1/AT2/AT10/AT11/AT12)."""

import json
import os
import shutil

import pytest

from pry.intake.errors import UNSUPPORTED_PROJECT, IntakeError
from pry.intake.project import ProjectSpec, copy_repo, detect_project, tree_sha256

EXCLUDED = [
    ".git",
    "node_modules",
    ".venv",
    "dist",
    "build",
    ".next",
    "__pycache__",
    ".pytest_cache",
]

STATIC_START = [
    "python",
    "-m",
    "http.server",
    "8000",
    "--directory",
    "/app",
    "--bind",
    "127.0.0.1",
]


def _write_package(root, scripts, **extra):
    data = {"scripts": scripts}
    data.update(extra)
    (root / "package.json").write_text(json.dumps(data))


def _cleanup(path):
    shutil.rmtree(path, ignore_errors=True)


def test_detect_static_site(tmp_path):
    (tmp_path / "index.html").write_text("<h1>hi</h1>")

    assert detect_project(tmp_path) == ProjectSpec(
        kind="static",
        image="python:3.9-slim",
        port=8000,
        install=None,
        build=None,
        start=STATIC_START,
        package_manager=None,
    )


def test_detect_node_with_start_script(tmp_path):
    _write_package(tmp_path, {"start": "node server.js"})

    spec = detect_project(tmp_path)

    assert spec.kind == "node"
    assert spec.image == "node:22-bookworm-slim"
    assert spec.port == 3000
    assert spec.install == ["npm", "install", "--no-audit", "--no-fund"]
    assert spec.build is None
    assert spec.start == ["npm", "run", "start"]
    assert spec.package_manager == "npm"


def test_detect_node_with_build_and_start(tmp_path):
    _write_package(tmp_path, {"build": "next build", "start": "next start"})

    spec = detect_project(tmp_path)

    assert spec.build == ["npm", "run", "build"]
    assert spec.start == ["npm", "run", "start"]


def test_detect_node_with_only_dev_script(tmp_path):
    _write_package(tmp_path, {"dev": "next dev"})

    spec = detect_project(tmp_path)

    assert spec.start == ["npm", "run", "dev"]


def test_package_lock_uses_npm_ci(tmp_path):
    _write_package(tmp_path, {"start": "node server.js"})
    (tmp_path / "package-lock.json").write_text("{}")

    assert detect_project(tmp_path).install == ["npm", "ci"]


@pytest.mark.parametrize("lockfile", ["yarn.lock", "pnpm-lock.yaml"])
def test_foreign_lockfile_is_unsupported(tmp_path, lockfile):
    _write_package(tmp_path, {"start": "node server.js"})
    (tmp_path / lockfile).write_text("")

    with pytest.raises(IntakeError) as exc:
        detect_project(tmp_path)

    assert exc.value.cause == UNSUPPORTED_PROJECT


def test_invalid_package_json_is_unsupported(tmp_path):
    (tmp_path / "package.json").write_text("{not json")

    with pytest.raises(IntakeError) as exc:
        detect_project(tmp_path)

    assert exc.value.cause == UNSUPPORTED_PROJECT


def test_non_string_script_is_unsupported(tmp_path):
    _write_package(tmp_path, {"start": 5})

    with pytest.raises(IntakeError) as exc:
        detect_project(tmp_path)

    assert exc.value.cause == UNSUPPORTED_PROJECT


def test_empty_directory_is_unsupported(tmp_path):
    with pytest.raises(IntakeError) as exc:
        detect_project(tmp_path)

    assert exc.value.cause == UNSUPPORTED_PROJECT


def test_index_html_falls_back_to_static_when_no_script(tmp_path):
    (tmp_path / "index.html").write_text("<h1>hi</h1>")
    _write_package(tmp_path, {})

    assert detect_project(tmp_path).kind == "static"


def _populate_tree(root):
    (root / "app").mkdir(parents=True)
    (root / "app" / "main.py").write_text("print('hi')\n")
    (root / "README.md").write_text("hello\n")
    for name in EXCLUDED:
        (root / name).mkdir()
        (root / name / "junk.txt").write_text("junk\n")


def test_copy_repo_copies_working_tree_and_excludes_generated(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    _populate_tree(source)
    before = tree_sha256(source)

    copied = copy_repo(source)
    try:
        assert copied != source
        assert (copied / "app" / "main.py").read_text() == "print('hi')\n"
        assert (copied / "README.md").read_text() == "hello\n"
        for name in EXCLUDED:
            assert not (copied / name).exists()
        assert tree_sha256(source) == before
    finally:
        _cleanup(copied)


def test_copy_repo_copies_symlinks_as_symlinks(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "real.txt").write_text("real\n")
    os.symlink("real.txt", source / "link.txt")

    copied = copy_repo(source)
    try:
        link = copied / "link.txt"
        assert link.is_symlink()
        assert os.readlink(link) == "real.txt"
        assert not (copied / "real.txt").is_symlink()
    finally:
        _cleanup(copied)


def test_tree_hash_is_stable_across_copies(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    _populate_tree(source)

    first = copy_repo(source)
    second = copy_repo(source)
    try:
        assert tree_sha256(first) == tree_sha256(second)
    finally:
        _cleanup(first)
        _cleanup(second)


def test_tree_hash_changes_when_a_file_changes(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.txt").write_text("one")

    first = tree_sha256(source)
    (source / "app.txt").write_text("two")

    assert tree_sha256(source) != first


def test_tree_hash_ignores_excluded_directories(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.txt").write_text("one")
    before = tree_sha256(source)

    (source / "node_modules").mkdir()
    (source / "node_modules" / "junk.js").write_text("junk")

    assert tree_sha256(source) == before


def test_tree_hash_hashes_symlink_target_strings(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "a.txt").write_text("same")
    (source / "b.txt").write_text("same")
    os.symlink("a.txt", source / "link")
    first = tree_sha256(source)

    os.remove(source / "link")
    os.symlink("b.txt", source / "link")

    assert tree_sha256(source) != first
