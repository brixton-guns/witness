"""File-based Ed25519 seed handling for development deployments (spec §13).

A seed file under the same user account as the observed workspace is a
development arrangement, not a strong trust boundary (spec §3). Production
keys belong outside the workspace, behind a real privilege boundary.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .errors import InputError

_SEED_HEX = re.compile(r"^[0-9a-fA-F]{64}$")

NON_PRODUCTION_WARNING = (
    "file-based seed: development arrangement only, keep it outside any observed "
    "workspace and out of source control (spec §3, §13)"
)


@dataclass(frozen=True)
class SigningKey:
    private_key: Ed25519PrivateKey
    key_id: str
    public_key_hex: str


def _key_from_seed(seed: bytes) -> SigningKey:
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    public = private_key.public_key().public_bytes_raw()
    return SigningKey(
        private_key=private_key,
        key_id="ed25519:" + hashlib.sha256(public).hexdigest(),
        public_key_hex=public.hex(),
    )


def generate_seed_file(path: Path) -> SigningKey:
    """Create a fresh owner-only seed file; refuse to overwrite anything."""
    seed = os.urandom(32)
    try:
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as exc:
        raise InputError(f"cannot create seed file {path}: {exc}") from exc
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(seed.hex() + "\n")
    return _key_from_seed(seed)


def load_seed_file(path: Path) -> SigningKey:
    """Load a seed file, refusing permissions that expose it beyond its owner."""
    try:
        mode = os.stat(path).st_mode
    except OSError as exc:
        raise InputError(f"cannot read seed file {path}: {exc}") from exc
    if not stat.S_ISREG(mode):
        raise InputError(f"seed file {path} is not a regular file")
    if stat.S_IMODE(mode) & 0o077:
        raise InputError(f"seed file {path} is readable by group or others; chmod 600 it")
    text = path.read_text(encoding="ascii").strip()
    if _SEED_HEX.fullmatch(text) is None:
        raise InputError("seed file must contain exactly 64 hexadecimal characters")
    return _key_from_seed(bytes.fromhex(text))
