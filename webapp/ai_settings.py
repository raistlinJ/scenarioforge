"""AI provider settings resolved from `.scenarioforge.env` (or the environment).

The Web UI keeps provider/model/base URL in browser state and the API key in the
encrypted per-user credential store, which leaves nothing for a headless caller
to read. These helpers give the CLI and the API route one shared place to pick up
that configuration, with explicit arguments always winning over the environment.

No Flask import here: the CLI resolves settings before it loads the web backend.
"""

from __future__ import annotations

import os
from typing import Any, Callable, Iterable


# Environment keys, documented in .scenarioforge.env.example.
AI_ENV_KEYS: dict[str, str] = {
    'provider': 'CORETG_AI_PROVIDER',
    'model': 'CORETG_AI_MODEL',
    'base_url': 'CORETG_AI_BASE_URL',
    'api_key': 'CORETG_AI_API_KEY',
    'credential_username': 'CORETG_AI_API_KEY_USER',
    'bridge_mode': 'CORETG_AI_BRIDGE_MODE',
    'mcp_server_path': 'CORETG_AI_MCP_SERVER_PATH',
    'timeout_seconds': 'CORETG_AI_TIMEOUT_S',
    'verify_ssl': 'CORETG_AI_VERIFY_SSL',
}

_SECRET_FIELDS = {'api_key'}
_FLOAT_FIELDS = {'timeout_seconds'}
_BOOL_FIELDS = {'verify_ssl'}


def _clean(value: Any) -> str:
    return str(value if value is not None else '').strip()


def _coerce_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    text = _clean(value).lower()
    if not text:
        return None
    if text in {'1', 'true', 't', 'yes', 'y', 'on'}:
        return True
    if text in {'0', 'false', 'f', 'no', 'n', 'off'}:
        return False
    return None


def _coerce_float(value: Any) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    text = _clean(value)
    if not text:
        return None
    try:
        return float(text)
    except Exception:
        return None


def _coerce_field(field: str, value: Any) -> Any:
    if field in _BOOL_FIELDS:
        return _coerce_bool(value)
    if field in _FLOAT_FIELDS:
        return _coerce_float(value)
    text = _clean(value)
    return text or None


def ai_settings_from_env(environ: dict[str, str] | None = None) -> dict[str, Any]:
    """Read AI provider settings from the environment, skipping unset keys."""
    source = environ if environ is not None else os.environ
    settings: dict[str, Any] = {}
    for field, env_key in AI_ENV_KEYS.items():
        coerced = _coerce_field(field, source.get(env_key))
        if coerced is not None:
            settings[field] = coerced
    return settings


def resolve_ai_settings(
    overrides: dict[str, Any] | None = None,
    *,
    environ: dict[str, str] | None = None,
    stored_api_key_loader: Callable[[str, str], str | None] | None = None,
) -> dict[str, Any]:
    """Merge explicit overrides over environment settings.

    Precedence is overrides > environment > stored credential. The stored
    credential only ever supplies the API key: it holds nothing else, and a key
    kept in the encrypted store is preferable to one written into a dotfile.
    """
    resolved = ai_settings_from_env(environ=environ)

    for field, value in (overrides or {}).items():
        if field not in AI_ENV_KEYS:
            continue
        coerced = _coerce_field(field, value)
        if coerced is not None:
            resolved[field] = coerced

    if not resolved.get('api_key') and callable(stored_api_key_loader):
        username = _clean(resolved.get('credential_username'))
        provider = _clean(resolved.get('provider'))
        if username and provider:
            try:
                stored_key = stored_api_key_loader(username, provider)
            except Exception:
                stored_key = None
            if _clean(stored_key):
                resolved['api_key'] = _clean(stored_key)
                resolved['api_key_source'] = 'stored_credential'

    if resolved.get('api_key') and 'api_key_source' not in resolved:
        resolved['api_key_source'] = 'environment'
    return resolved


def missing_ai_settings(settings: dict[str, Any], *, required: Iterable[str] = ('provider', 'model', 'base_url')) -> list[str]:
    """Names of required settings that are still unset, as env keys."""
    missing: list[str] = []
    for field in required:
        if not _clean((settings or {}).get(field)):
            missing.append(AI_ENV_KEYS.get(field, field))
    return missing


def redact_ai_settings(settings: dict[str, Any] | None) -> dict[str, Any]:
    """Copy safe to print or log: secrets become a presence marker."""
    safe: dict[str, Any] = {}
    for field, value in (settings or {}).items():
        if field in _SECRET_FIELDS:
            safe[field] = f'<set len={len(_clean(value))}>' if _clean(value) else ''
            continue
        safe[field] = value
    return safe


def ai_settings_as_payload(settings: dict[str, Any] | None) -> dict[str, Any]:
    """Shape resolved settings into the AI endpoint's payload field names."""
    source = settings or {}
    payload: dict[str, Any] = {}
    for field in ('provider', 'model', 'base_url', 'api_key', 'bridge_mode', 'mcp_server_path'):
        value = _clean(source.get(field))
        if value:
            payload[field] = value
    timeout_seconds = source.get('timeout_seconds')
    if isinstance(timeout_seconds, (int, float)) and not isinstance(timeout_seconds, bool):
        payload['timeout_seconds'] = float(timeout_seconds)
    verify_ssl = source.get('verify_ssl')
    if isinstance(verify_ssl, bool):
        payload['verify_ssl'] = verify_ssl
    return payload


__all__ = [
    'AI_ENV_KEYS',
    'ai_settings_as_payload',
    'ai_settings_from_env',
    'missing_ai_settings',
    'redact_ai_settings',
    'resolve_ai_settings',
]
