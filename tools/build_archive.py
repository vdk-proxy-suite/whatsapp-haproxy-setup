#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import stat
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
OUTPUT = ROOT.parent / f"{ROOT.name}-standalone-{VERSION}.zip"
EXCLUDES = {"AGENTS.md", "__pycache__", ".pytest_cache", ".git", ".agents", "venv", ".venv"}


def include(path: Path) -> bool:
    if any(part in EXCLUDES or part.endswith(".pyc") for part in path.parts):
        return False
    return not (path.name.startswith("config") and path.suffix == ".yaml" and not path.name.endswith(".example.yaml"))


def main() -> int:
    files = sorted(path for path in ROOT.rglob("*") if path.is_file() and include(path.relative_to(ROOT)))
    with zipfile.ZipFile(OUTPUT, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in files:
            relative = Path(ROOT.name) / path.relative_to(ROOT)
            mode = 0o755 if path.suffix == ".sh" or path.name in {"config.py", "healthcheck.py", "build_archive.py"} else 0o644
            info = zipfile.ZipInfo(str(relative).replace("\\", "/"))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            data = path.read_bytes()
            archive.writestr(info, data)
    digest = hashlib.sha256(OUTPUT.read_bytes()).hexdigest()
    print(f"{OUTPUT}\nsha256={digest}\nfiles={len(files)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
