from __future__ import annotations

import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


def is_git_url(value: str) -> bool:
    lower = value.lower()
    return lower.startswith("https://") or lower.startswith("http://") or lower.startswith("git@")


@contextmanager
def materialize_target(value: str) -> Iterator[Path]:
    if not is_git_url(value):
        yield Path(value).expanduser().resolve()
        return

    with tempfile.TemporaryDirectory(prefix="gateshield-") as directory:
        root = Path(directory) / "repository"
        result = subprocess.run(
            ["git", "clone", "--depth", "1", value, str(root)],
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            raise RuntimeError((result.stderr or result.stdout or "git clone failed").strip())
        yield root
