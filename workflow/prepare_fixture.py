#!/usr/bin/env python3
"""Prepare a tiny local Git repository before the observer is attached."""
from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


def run(argv: list[str], cwd: Path | None = None) -> None:
    subprocess.run(argv, cwd=cwd, check=True, stdout=subprocess.DEVNULL)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", required=True, type=Path)
    args = parser.parse_args()
    repo = args.dir.resolve()
    repo.mkdir(parents=True, exist_ok=True)

    if (repo / ".git").exists():
        raise SystemExit(f"refusing to reuse an existing Git repository: {repo}")

    (repo / "seed.txt").write_text("AgentCaptureBench fixture\n", encoding="utf-8")
    run(["git", "init", "--quiet", str(repo)])
    run(["git", "-C", str(repo), "config", "user.name", "AgentCaptureBench Test"])
    run(["git", "-C", str(repo), "config", "user.email", "agentcapturebench@example.invalid"])
    run(["git", "-C", str(repo), "add", "seed.txt"])
    run(["git", "-C", str(repo), "commit", "--quiet", "-m", "fixture seed"])
    print(f"Prepared fixture repository: {repo}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
