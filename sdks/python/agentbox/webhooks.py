from __future__ import annotations

import hmac
import hashlib


def verify_webhook_signature(secret: str, raw_body: bytes | str, signature_header: str) -> bool:
    """Verify the X-AgentBox-Signature (`sha256=<hex>`) header using constant-time comparison."""
    if not secret or not signature_header.startswith("sha256="):
        return False
    body_bytes = raw_body.encode("utf-8") if isinstance(raw_body, str) else raw_body
    expected = "sha256=" + hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)
