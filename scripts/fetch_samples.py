"""Fetch the sample repositories used for validation and prediction runs.

Clones into samples/ (gitignored). Strapi uses a partial clone so the full
repository is available for historical commit mining without downloading
every blob up front.
"""

import subprocess
import sys
from pathlib import Path

SAMPLES = [
    {
        "name": "strapi",
        "url": "https://github.com/strapi/strapi.git",
        # partial clone: history + trees now, blobs on demand
        "args": ["--filter=blob:none"],
    },
    {
        "name": "turtlebot3",
        "url": "https://github.com/ROBOTIS-GIT/turtlebot3.git",
        "args": [],
    },
]


def main() -> None:
    samples_dir = Path(__file__).resolve().parent.parent / "samples"
    samples_dir.mkdir(exist_ok=True)

    for sample in SAMPLES:
        target = samples_dir / sample["name"]
        if target.exists():
            print(f"[skip] {sample['name']} already cloned")
            continue
        print(f"[clone] {sample['url']} -> {target}")
        result = subprocess.run(
            ["git", "clone", *sample["args"], sample["url"], str(target)],
        )
        if result.returncode != 0:
            print(f"[error] failed to clone {sample['name']}", file=sys.stderr)
            sys.exit(1)

    print("done.")


if __name__ == "__main__":
    main()
