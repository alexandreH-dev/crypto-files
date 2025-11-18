from __future__ import annotations
import base64
import hashlib
from pathlib import Path
from datetime import datetime, timezone

B64 = base64.urlsafe_b64encode
B64D = base64.urlsafe_b64decode


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ensure_parent_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)