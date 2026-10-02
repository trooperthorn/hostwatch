"""Authentication primitives: password hashing, login lockout, API keys and session tokens.

These are building blocks. Nothing in the hub calls them yet, so no endpoint is
protected by this module until a later Phase 3 slice wires it in. What this
module provides once wired: passwords are stored only as argon2id hashes, a
user locks after repeated failures, and key and session secrets are stored only
as SHA-256 digests (the store does the digesting). Secrets are never logged.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from functools import lru_cache

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from .config import Config
from .store import Store

SCOPES = frozenset({"read:metrics", "read:events", "ingest", "admin"})


def make_hasher(cfg: Config) -> PasswordHasher:
    """Build an argon2id hasher whose cost comes from config, so tests can use a low cost."""
    return PasswordHasher(time_cost=cfg.argon2_time_cost, memory_cost=cfg.argon2_memory_kib,
                          parallelism=cfg.argon2_parallelism)


def hash_password(cfg: Config, password: str) -> str:
    return make_hasher(cfg).hash(password)


def verify_password(cfg: Config, stored_hash: str, password: str) -> bool:
    """Return True only for a matching password. A malformed stored hash counts as a mismatch."""
    try:
        return make_hasher(cfg).verify(stored_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(cfg: Config, stored_hash: str) -> bool:
    """True when the stored hash was made with weaker parameters than the configured ones."""
    return make_hasher(cfg).check_needs_rehash(stored_hash)


@lru_cache(maxsize=8)
def _dummy_hash(time_cost: int, memory_kib: int, parallelism: int) -> str:
    return PasswordHasher(time_cost=time_cost, memory_cost=memory_kib,
                          parallelism=parallelism).hash("hostwatch-dummy-password")


def _burn(cfg: Config, password: str) -> None:
    """Run one verification against a dummy hash so the failure path costs the same as a real check."""
    verify_password(cfg, _dummy_hash(cfg.argon2_time_cost, cfg.argon2_memory_kib, cfg.argon2_parallelism),
                    password)


@dataclass(frozen=True)
class LoginResult:
    ok: bool
    reason: str  # "ok", "bad_credentials", "locked" or "disabled"
    user: dict | None = None
    locked_until: float | None = None


def check_login(store: Store, cfg: Config, username: str, password: str,
                now: float | None = None) -> LoginResult:
    """Check credentials and apply the lockout policy.

    An unknown, locked or disabled user runs one argon2 verification against a
    dummy hash, so response time does not reveal whether the account exists. The
    caller must respond with one generic message for every failure reason. A
    correct password on a locked account is refused and does not unlock it; the
    lock ends when its window passes. A successful login clears the failure
    count and upgrades an outdated hash.
    """
    now = time.time() if now is None else now
    user = store.get_user(username)
    if user is None:
        _burn(cfg, password)
        return LoginResult(False, "bad_credentials")
    locked = user["locked_until"] is not None and user["locked_until"] > now
    if locked or user["disabled"]:
        _burn(cfg, password)
        if locked:
            return LoginResult(False, "locked", locked_until=user["locked_until"])
        return LoginResult(False, "disabled")
    if not verify_password(cfg, user["hash"], password):
        updated = store.record_login_failure(username, cfg.login_max_failures, cfg.login_lock_s, now=now)
        if updated is not None and updated["locked_until"] is not None and updated["locked_until"] > now:
            return LoginResult(False, "locked", locked_until=updated["locked_until"])
        return LoginResult(False, "bad_credentials")
    store.reset_failures(username)
    if needs_rehash(cfg, user["hash"]):
        store.set_password_hash(username, hash_password(cfg, password))
    return LoginResult(True, "ok", user=store.get_user(username))


def parse_scopes(raw: str | list[str]) -> list[str]:
    """Validate scopes given as a comma separated string or a list. Unknown or empty input raises ValueError."""
    items = raw.split(",") if isinstance(raw, str) else list(raw)
    items = [i.strip() for i in items if i.strip()]
    if not items:
        raise ValueError("at least one scope is required")
    unknown = sorted(set(items) - SCOPES)
    if unknown:
        raise ValueError(f"unknown scope(s): {', '.join(unknown)}; valid scopes are {', '.join(sorted(SCOPES))}")
    return sorted(set(items))


def generate_api_key(store: Store, scopes: str | list[str], owner: str,
                     now: float | None = None) -> tuple[str, dict]:
    """Create a scoped key. Returns (secret, row). The secret is `hw_<lookup prefix>_<random>`,
    is shown once, and only its SHA-256 digest and the lookup prefix are stored."""
    return store.create_api_key(parse_scopes(scopes), owner, now=now)


def generate_session_token(store: Store, user_id: int, ttl_s: float, now: float | None = None) -> str:
    """Create a session and return its random token. Only the token's digest is stored server side."""
    return store.create_session(user_id, ttl_s, now=now)


INTERNAL_AGENT_OWNER = "internal:local-agent"


def mint_internal_ingest_key(cfg: Config, store: Store) -> str:
    """For the all role: return the key the local agent should send.

    If HOSTWATCH_INGEST_KEY is set it is used unchanged. Otherwise a fresh key
    with the ingest and read:events scopes is created in memory for this process
    only. The store keeps its hash, never the key, and the key is never logged.
    Earlier internal keys are revoked first, so restarts do not accumulate
    active credentials nobody holds.
    """
    if cfg.ingest_key:
        return cfg.ingest_key
    store.revoke_api_keys_by_owner(INTERNAL_AGENT_OWNER)
    full, _ = store.create_api_key(["ingest", "read:events"], INTERNAL_AGENT_OWNER)
    return full
