"""
Classifies request-log entries as security-model enumeration, per H294's
own named endpoints: /api/security/users, /api/security/groups,
/api/security/permissions, and federation/credential-set paths under
/access/api/v1/.
"""
from __future__ import annotations

import re

from .models import RequestLogEntry

_ENUMERATION_PATTERNS = [
    re.compile(r"(^|/)api/security/users(/|$|\?)"),
    re.compile(r"(^|/)api/security/groups(/|$|\?)"),
    re.compile(r"(^|/)api/security/permissions(/|$|\?)"),
    re.compile(r"(^|/)access/api/v1/federation(/|$|\?)"),
    re.compile(r"(^|/)access/api/v1/credential-sets?(/|$|\?)"),
]


def is_enumeration_request(entry: RequestLogEntry) -> bool:
    url = entry.url.lstrip("/")
    return any(pattern.search(url) for pattern in _ENUMERATION_PATTERNS)
