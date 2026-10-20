"""Persistence-boundary redaction for SENTINEL scan history.

The submitted input is still used unmodified for analysis inside the request
lifecycle.  The helpers in this module are applied only to values written to
scan history (the bounded content preview and the persisted structured result)
so common credentials are not retained in storage.

The transformation is deterministic and safe on malformed input.  It is also
idempotent for the outputs it produces, because every masked value
(``[MASKED]``) no longer matches a secret pattern.

No function in this module logs, so raw input never reaches log sinks here.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import unquote, unquote_plus

MAX_PREVIEW_CHARS = 100
MASK = "[MASKED]"

# Parameter names that are credential fields regardless of the value shape.
# Names are normalised (lower-case, separators collapsed to "_") before lookup.
_ALWAYS_SECRET_PARAMETERS = frozenset(
    {
        # bearer / token / assertion style
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "auth_token",
        "bearer_token",
        "bearer",
        "jwt",
        "assertion",
        # keys and secrets
        "api_key",
        "apikey",
        "api_token",
        "secret_key",
        "private_key",
        "signing_key",
        "secret",
        "client_secret",
        "clientsecret",
        # passwords
        "password",
        "passwd",
        "pwd",
        "passphrase",
        "pass",
        # authentication / session / cookies
        "authorization",
        "auth",
        "session",
        "sessionid",
        "session_id",
        "cookie",
        "cookies",
        "otp",
        "pin",
        # generic signatures and signed-URL fields
        "sig",
        "signature",
        "x_amz_signature",
        "x_amz_credential",
        "x_amz_security_token",
        "x_goog_signature",
        "x_goog_credential",
    }
)

# Generic names that are only treated as credentials when the value looks like
# a machine-issued credential.  ``?key=value`` must remain readable, while
# ``?key=a1b2c3d4e5`` and OAuth ``?code=...`` values are masked.
_CONDITIONAL_SECRET_PARAMETERS = frozenset(
    {"key", "code", "ticket", "credential", "cred"}
)

_PARAM_INDEX_RE = re.compile(r"(?:\[[^\]]*\])+$")
_JWT_LIKE_RE = re.compile(r"^eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.")

# URL-like spans inside free text (email bodies, signal descriptions, reports).
_URL_RE = re.compile(r"(?i)\b[a-z][a-z0-9+.\-]*://[^\s<>\"'`]+")

# Schemeless URLs are accepted by the analyzer (it prepends http://), so their
# query/fragment credentials must be redacted too.
_BARE_URL_RE = re.compile(
    r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}"
    r"(?::\d{1,5})?"
    r"(?:/[^\s<>\"'`]*)?(?:\?[^\s<>\"'`#]*)?(?:#[^\s<>\"'`]*)?"
)

# scheme://userinfo@host -- the userinfo part may contain ":" or be an email.
_SCHEMELESS_USERINFO_RE = re.compile(
    r"(?i)(?<!mailto:)(?<!tel:)\b[A-Za-z0-9._%+\-]+:[^\s/@]+@"
    r"(?=[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+)"
)

# Sensitive header lines (raw header blocks).  A value runs to the end of the
# line (or the next ``Name:``-shaped token, which keeps the transformation
# idempotent on an already-collapsed preview) and includes RFC 5322 folded
# continuation lines so a wrapped credential is not partially retained.
_HEADER_VALUE = (
    r"[^\r\n]*?(?=(?:[ \t]+[A-Za-z][A-Za-z0-9-]*[ \t]*:)|[\r\n]|$)"
    r"(?:\r?\n[ \t]+[^\r\n]*)*"
)
_AUTHORIZATION_HEADER_RE = re.compile(
    r"(?i)\b(?P<prefix>(?:proxy-)?authorization[ \t]*:[ \t]*)" + _HEADER_VALUE
)
_COOKIE_HEADER_RE = re.compile(
    r"(?im)(?P<prefix>^[ \t]*(?:set-)?cookie[ \t]*:[ \t]*)" + _HEADER_VALUE
)

# Credential assignments in free text (headers already handled above).
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)(?<![\w-])"
    r"(?P<key>api[_-]?key|apikey|authorization|access[_-]?token|refresh[_-]?token|"
    r"id[_-]?token|auth[_-]?token|client[_-]?secret|secret[_-]?key|private[_-]?key|"
    r"passphrase|password|passwd|pwd|bearer|cookie|token|secret|sessionid|"
    r"session_id|session|auth)"
    r"(?P<sep>\s*[:=]\s*)(?P<value>[^\s&;]+)"
)
_GENERIC_KEY_ASSIGNMENT_RE = re.compile(
    r"(?i)(?<![\w-])(?P<key>key)(?P<sep>\s*[:=]\s*)(?P<value>[^\s&;]+)"
)

# Well-known credential shapes.
_BEARER_TOKEN_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9_\-.~+/=]{8,}")
_JWT_RE = re.compile(
    r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-]{10,}"
)
_GOOGLE_API_KEY_RE = re.compile(r"AIzaSy[A-Za-z0-9_\-]{10,}")
_CARD_NUMBER_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")


def _normalize_param_name(raw_name: str) -> str:
    name = unquote_plus(raw_name).strip().lower()
    name = _PARAM_INDEX_RE.sub("", name)
    return re.sub(r"[\s.\-]+", "_", name)


def _looks_like_secret_value(value: str) -> bool:
    """Return True when a generically named value is credential-shaped."""
    candidate = unquote_plus(value).strip()
    if not candidate or candidate == MASK:
        return False
    if len(candidate) < 8:
        return False
    if _JWT_LIKE_RE.match(candidate):
        return True
    if len(candidate) >= 16:
        return True
    has_letter = bool(re.search(r"[A-Za-z]", candidate))
    has_digit = bool(re.search(r"\d", candidate))
    return has_letter and has_digit


def _is_secret_pair(name: str, value: Optional[str]) -> bool:
    normalized = _normalize_param_name(name)
    if normalized in _ALWAYS_SECRET_PARAMETERS:
        return True
    if normalized in _CONDITIONAL_SECRET_PARAMETERS:
        return _looks_like_secret_value(value or "")
    return False


def _redact_authority(authority: str) -> str:
    """Mask URL user-information while keeping the hostname visible."""
    if "@" not in authority:
        return authority
    _, _, host = authority.rpartition("@")
    return f"{MASK}@{host}"


def _redact_url_like_value(value: str) -> str:
    """Redact secrets inside a (possibly URL-encoded) nested URL value."""
    decoded = unquote(value)
    if "://" not in decoded:
        return value
    redacted = _URL_RE.sub(lambda match: _redact_url(match.group(0)), decoded)
    if redacted == decoded:
        return value
    return redacted


def _redact_pair(pair: str) -> str:
    if not pair:
        return pair

    name, separator, value = pair.partition("=")
    if separator:
        if _is_secret_pair(name, value):
            return f"{name}={MASK}"
        redacted_value = _redact_url_like_value(value)
        if redacted_value != value:
            return f"{name}={redacted_value}"
        return pair

    # Percent-encoded assignment such as ``password%3Dsecret``.
    decoded = unquote_plus(pair)
    if "=" in decoded:
        decoded_name, _, decoded_value = decoded.partition("=")
        if _is_secret_pair(decoded_name, decoded_value):
            return f"{decoded_name.strip()}={MASK}"

    return pair


def _redact_parameter_block(block: str) -> str:
    parts = re.split(r"([&;])", block)
    return "".join(
        separator if separator in ("&", ";") else _redact_pair(separator)
        for separator in parts
    )


def _redact_fragment(fragment: str) -> str:
    decoded = unquote_plus(fragment)
    if re.match(r"(?i)^\s*bearer\s+\S+", decoded):
        return MASK
    if "=" in decoded:
        # Parameter handling also covers percent-encoded assignments and
        # generic credential-shaped values (``#key=a1b2c3d4``).
        return _redact_parameter_block(fragment)
    if _JWT_LIKE_RE.match(decoded) or (
        len(decoded) >= 24 and re.search(r"[A-Za-z]", decoded) and re.search(r"\d", decoded)
    ):
        return MASK
    return fragment


def _redact_url(url: str) -> str:
    """Mask user-info, secret query values, and secret fragments in one URL."""
    scheme_end = url.find("://")
    if scheme_end < 0:
        prefix, remainder = "", url
    else:
        prefix = url[: scheme_end + 3]
        remainder = url[scheme_end + 3 :]

    fragment = None
    if "#" in remainder:
        remainder, fragment = remainder.split("#", 1)
    query = None
    if "?" in remainder:
        remainder, query = remainder.split("?", 1)

    authority, slash, path = remainder.partition("/")
    redacted = prefix + _redact_authority(authority)
    if slash:
        redacted += slash + path
    if query is not None:
        redacted += "?" + _redact_parameter_block(query)
    if fragment is not None:
        redacted += "#" + _redact_fragment(fragment)
    return redacted


def _replace_assignment(match: re.Match) -> str:
    return f"{match.group('key')}{match.group('sep')}{MASK}"


def _replace_generic_key_assignment(match: re.Match) -> str:
    if _looks_like_secret_value(match.group("value")):
        return f"{match.group('key')}{match.group('sep')}{MASK}"
    return match.group(0)


def redact_secrets_in_text(text: str) -> str:
    """Mask common embedded credentials in a free-text value.

    Covers URL user-information, secret-bearing query/fragment parameters,
    sensitive header values, bearer/JWT/API-key shapes, credential
    assignments, and card-number-like sequences.  Malformed URL parsing keeps
    the surrounding text intact.
    """
    if not text:
        return ""

    redacted = text
    redacted = _URL_RE.sub(lambda match: _redact_url(match.group(0)), redacted)
    redacted = _BARE_URL_RE.sub(lambda match: _redact_url(match.group(0)), redacted)
    redacted = _SCHEMELESS_USERINFO_RE.sub(f"{MASK}@", redacted)
    redacted = _AUTHORIZATION_HEADER_RE.sub(
        lambda match: match.group("prefix") + MASK, redacted
    )
    redacted = _COOKIE_HEADER_RE.sub(
        lambda match: match.group("prefix") + MASK, redacted
    )
    redacted = _SECRET_ASSIGNMENT_RE.sub(_replace_assignment, redacted)
    redacted = _GENERIC_KEY_ASSIGNMENT_RE.sub(_replace_generic_key_assignment, redacted)
    redacted = _BEARER_TOKEN_RE.sub("Bearer " + MASK, redacted)
    redacted = _JWT_RE.sub("[MASKED_JWT]", redacted)
    redacted = _GOOGLE_API_KEY_RE.sub("AIzaSy..." + MASK, redacted)
    redacted = _CARD_NUMBER_RE.sub("[MASKED_CARD]", redacted)
    return redacted


def sanitize_history_preview(
    content: str, max_chars: int = MAX_PREVIEW_CHARS
) -> str:
    """Build the bounded, sanitized preview persisted as scan history content.

    Preserves scheme, hostname, path, parameter names, and harmless query
    parameters for later investigation while masking credential values.
    """
    if not content:
        return ""

    sanitized = redact_secrets_in_text(content.strip())
    sanitized = re.sub(r"\s+", " ", sanitized).strip()

    if len(sanitized) > max_chars:
        return sanitized[:max_chars] + "..."
    return sanitized


def sanitize_persisted_details(details: Any) -> Any:
    """Return a redacted copy of the structured analysis ``details`` mapping.

    Diagnostics keep their shape and types; only string values are transformed.
    ``host``/``netloc`` values are authority strings without a scheme, so URL
    user-information is stripped explicitly there.
    """
    if isinstance(details, dict):
        return {
            key: _sanitize_details_value(value, key)
            for key, value in details.items()
        }
    return _sanitize_details_value(details, None)


def _sanitize_details_value(value: Any, key: Optional[str]) -> Any:
    if isinstance(value, dict):
        return {
            inner_key: _sanitize_details_value(inner_value, inner_key)
            for inner_key, inner_value in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_sanitize_details_value(item, key) for item in value]
    if isinstance(value, str):
        if key in ("host", "netloc"):
            return _redact_authority(value)
        return redact_secrets_in_text(value)
    return value


def sanitize_persisted_signals(signals: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """Return redacted copies of analysis signals without mutating the originals."""
    redacted_signals: List[Dict[str, Any]] = []
    for signal in signals or []:
        if isinstance(signal, dict):
            redacted_signals.append(
                {
                    key: (redact_secrets_in_text(value) if isinstance(value, str) else value)
                    for key, value in signal.items()
                }
            )
        else:
            redacted_signals.append(signal)
    return redacted_signals
