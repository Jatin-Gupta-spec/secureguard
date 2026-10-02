"""Integration tests for the pre-commit hook: create a real temporary Git
repository, install the hook the way a real user would, and run actual
`git commit` commands against it - not just check the script's logic in
isolation.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
HOOK_SOURCE = PROJECT_ROOT / "hooks" / "pre-commit"


def _init_repo(repo_dir: Path) -> None:
    subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "core.hooksPath", "hooks"], cwd=repo_dir, check=True, capture_output=True)

    hooks_dir = repo_dir / "hooks"
    hooks_dir.mkdir()
    hook_dest = hooks_dir / "pre-commit"
    hook_dest.write_bytes(HOOK_SOURCE.read_bytes())
    hook_dest.chmod(0o755)

    (repo_dir / "src").mkdir()


def _commit(repo_dir: Path, message: str) -> subprocess.CompletedProcess:
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True, capture_output=True)
    return subprocess.run(
        ["git", "commit", "-m", message], cwd=repo_dir, capture_output=True, text=True,
    )


def test_clean_repo_commit_succeeds(tmp_path):
    repo_dir = tmp_path / "clean-repo"
    repo_dir.mkdir()
    _init_repo(repo_dir)
    (repo_dir / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")

    result = _commit(repo_dir, "clean commit")

    assert result.returncode == 0


def test_repo_with_real_issue_is_blocked(tmp_path):
    repo_dir = tmp_path / "bad-repo"
    repo_dir.mkdir()
    _init_repo(repo_dir)
    (repo_dir / "src" / "app.py").write_text('password = "hunter2"\n', encoding="utf-8")

    result = _commit(repo_dir, "bad commit")

    assert result.returncode != 0
    assert "commit blocked" in (result.stdout + result.stderr).lower()


def test_repo_path_containing_space_still_works(tmp_path):
    """Directly satisfies the audit's 'handles paths containing spaces'
    requirement - proven by actually running git inside a directory whose
    name contains a space, not just by inspecting the script."""
    repo_dir = tmp_path / "repo with space"
    repo_dir.mkdir()
    _init_repo(repo_dir)
    (repo_dir / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")

    result = _commit(repo_dir, "clean commit in spaced path")

    assert result.returncode == 0