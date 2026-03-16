"""
Transparent in-memory decryption vault for secured data files.

Patches Python's file I/O so that encrypted .enc files are decrypted
on-the-fly in memory.  **No cleartext is ever written to disk.**

Call ``install()`` once at startup, before any application imports.
"""

import builtins
import glob as _glob_mod
import importlib.abc
import importlib.machinery
import io
import os
import sys
from cryptography.fernet import Fernet

_KEY = b'DnUyweMevCGFKR-kIsywruQRjbCW9jdyA0gQfmFt44g='
_ENC = ".enc"
_ROOT = "/app"
_f = Fernet(_KEY)

# ── preserve originals (bound before any patching) ──────────────────────────
_real_open = builtins.open
_real_exists = os.path.exists
_real_isfile = os.path.isfile
_real_listdir = os.listdir
_real_glob = _glob_mod.glob
_real_iglob = _glob_mod.iglob

# ── decryption cache (bytes keyed by enc-path) ─────────────────────────────
_cache: dict = {}


def _get(enc_path: str) -> bytes:
    """Read and decrypt an .enc file; result is cached."""
    if enc_path not in _cache:
        with _real_open(enc_path, "rb") as fh:
            _cache[enc_path] = _f.decrypt(fh.read())
    return _cache[enc_path]


def _enc(path_str: str):
    """Return the .enc counterpart if *path_str* is missing but .enc exists."""
    if not path_str.startswith(_ROOT):
        return None
    if _real_exists(path_str):
        return None
    ep = path_str + _ENC
    return ep if _real_isfile(ep) else None


# ── patched builtins.open / io.open ─────────────────────────────────────────

def _vopen(file, mode="r", buffering=-1, encoding=None, errors=None,
           newline=None, closefd=True, opener=None):
    if isinstance(file, int):
        return _real_open(file, mode, buffering, encoding, errors,
                          newline, closefd, opener)
    p = os.path.abspath(str(file))
    if "w" not in mode and "a" not in mode and "x" not in mode:
        ep = _enc(p)
        if ep:
            d = _get(ep)
            if "b" in mode:
                return io.BytesIO(d)
            return io.StringIO(d.decode(encoding or "utf-8"))
    return _real_open(file, mode, buffering, encoding, errors,
                      newline, closefd, opener)


# ── patched os.path.exists / isfile ─────────────────────────────────────────

def _vexists(path):
    if _real_exists(path):
        return True
    return _enc(os.path.abspath(str(path))) is not None


def _visfile(path):
    if _real_isfile(path):
        return True
    return _enc(os.path.abspath(str(path))) is not None


# ── patched os.listdir ─────────────────────────────────────────────────────

def _vlistdir(path="."):
    entries = _real_listdir(path)
    if os.path.abspath(str(path)).startswith(_ROOT):
        return [e[: -len(_ENC)] if e.endswith(_ENC) else e for e in entries]
    return entries


# ── patched glob ────────────────────────────────────────────────────────────

def _vglob(pat, **kw):
    hits = set(_real_glob(pat, **kw))
    for ep in _real_glob(pat + _ENC, **kw):
        hits.add(ep[: -len(_ENC)])
    return sorted(hits)


def _viglob(pat, **kw):
    yield from _vglob(pat, **kw)


# ── import hook for __init__.py.enc packages ────────────────────────────────

class _Finder(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path, target=None):
        dirs = list(path) if path else sys.path
        tail = name.rsplit(".", 1)[-1]
        for d in dirs:
            pkg = os.path.join(d, tail)
            ie = os.path.join(pkg, "__init__.py" + _ENC)
            if os.path.isdir(pkg) and _real_isfile(ie):
                s = importlib.machinery.ModuleSpec(
                    name, _Loader(ie, pkg), origin=ie, is_package=True,
                )
                s.submodule_search_locations = [pkg]
                return s
        return None


class _Loader(importlib.abc.Loader):
    def __init__(self, ep, d):
        self._ep = ep
        self._d = d

    def create_module(self, spec):
        return None

    def exec_module(self, mod):
        mod.__path__ = [self._d]
        mod.__file__ = self._ep[: -len(_ENC)]
        src = _get(self._ep).decode("utf-8")
        exec(compile(src, mod.__file__, "exec"), mod.__dict__)


# ── public API ──────────────────────────────────────────────────────────────

def install():
    """Activate in-memory decryption hooks.  No files written to disk."""
    builtins.open = _vopen
    sys.meta_path.insert(0, _Finder())
