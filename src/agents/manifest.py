"""Spawn manifest construction, canonicalization and detached-JWS signing.

This is the Python side of the manifest signature scheme, whose Go
implementation lives in src/vending-service/internal/manifest and
internal/signature. A port, not a redesign: the wire shape and
the canonicalization rule are dictated by the Go verifier, which recomputes
the payload independently (see internal/manifest.CanonicalBytes's own
comment) rather than trusting the bytes it received — so this module's
canonical_bytes() must byte-for-byte match what Go's json.Marshal produces
for internal/manifest.canonicalForm, or every signature this harness produces
fails verification.

Two things Go's encoding/json does that Python's json module does not do by
default, both handled explicitly below:
  1. Compact output (no spaces) — separators=(",", ":").
  2. HTML-safe escaping of '<', '>', '&' to \\u003c/\\u003e/\\u0026, and of
     U+2028/U+2029, applied unconditionally by json.Marshal. Python's
     json.dumps does neither. Field values in this lab (SPIFFE IDs, scope
     names, short task descriptions) are unlikely to ever contain these
     characters, but the whole signature scheme is worthless if the
     canonicalization silently diverges on the day one does, so it is
     handled here rather than assumed away.

The struct field ORDER matters too: Go marshals struct fields in declaration
order (not sorted) and map keys in sorted order. canonical_bytes() below
mirrors both: the outer dict is built in internal/manifest.canonicalForm's
declared field order, and child_selectors' keys are sorted before insertion.
"""

from __future__ import annotations

import base64
import json
import time
import uuid
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding

# MaxTTLSeconds mirrors internal/manifest.MaxTTLSeconds (24h) — not enforced
# client-side (the vending service is the authority), only used as a sane
# demo default.
DEFAULT_TTL_SECONDS = 300


@dataclass
class SpawnManifest:
    parent_spiffe_id: str
    child_path_hint: str
    requested_scopes: list[str]
    task_context: str
    child_selectors: dict[str, str]
    ttl_seconds: int = DEFAULT_TTL_SECONDS
    nonce: str = field(default_factory=lambda: f"n_{time.time_ns()}")
    signature: str = ""

    def child_spiffe_id(self) -> str:
        # Exactly manifest.SpawnManifest.ChildSpiffeID()'s Go shape:
        # parent_spiffe_id + "/" + child_path_hint.
        return f"{self.parent_spiffe_id}/{self.child_path_hint}"

    def canonical_bytes(self) -> bytes:
        canonical = {
            "parent_spiffe_id": self.parent_spiffe_id,
            "child_path_hint": self.child_path_hint,
            "requested_scopes": self.requested_scopes,
            "task_context": self.task_context,
            "child_selectors": dict(sorted(self.child_selectors.items())),
            "ttl_seconds": self.ttl_seconds,
            "nonce": self.nonce,
        }
        s = json.dumps(canonical, separators=(",", ":"), ensure_ascii=False)
        s = (
            s.replace("&", "\\u0026")
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
            .replace("\u2028", "\\u2028")
            .replace("\u2029", "\\u2029")
        )
        return s.encode("utf-8")

    def to_wire(self) -> dict:
        return {
            "parent_spiffe_id": self.parent_spiffe_id,
            "child_path_hint": self.child_path_hint,
            "requested_scopes": self.requested_scopes,
            "task_context": self.task_context,
            "child_selectors": self.child_selectors,
            "ttl_seconds": self.ttl_seconds,
            "nonce": self.nonce,
            "signature": self.signature,
        }


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def sign_manifest(m: SpawnManifest, private_key, cert_chain) -> str:
    """Signs m.canonical_bytes() with private_key (the parent's own
    X.509-SVID key), carrying cert_chain (leaf first) in the x5c header —
    the Python side of internal/signature.Sign. Returns the detached-JWS
    compact serialization (RFC 7515 Appendix F: header..signature, empty
    payload segment).

    Unlike canonical_bytes(), the HEADER's exact byte encoding does not need
    to match Go's: internal/signature.Verify parses whatever protected
    header the compact string carries (json.Unmarshal, not a byte
    comparison) and only re-derives the PAYLOAD independently. Only the
    ECDSA signature's byte FORMAT matters here — JOSE ES256 requires the
    raw, fixed-width r||s concatenation (RFC 7515 A.3), not the DER
    encoding `cryptography`'s sign() returns by default.
    """
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise TypeError(
            f"unsupported private key type {type(private_key)!r}: this lab's "
            "SPIRE deployment issues EC P-256 keys (ES256); a differently "
            "configured trust domain would need PS256 support, not built here"
        )

    x5c = [base64.standard_b64encode(cert.public_bytes(Encoding.DER)).decode("ascii") for cert in cert_chain]
    header = {"alg": "ES256", "x5c": x5c}
    header_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64url(m.canonical_bytes())
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

    der_sig = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    # P-256: each coordinate is 32 bytes, big-endian, zero-padded.
    raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    sig_b64 = _b64url(raw_sig)

    # Detached: the middle (payload) segment is empty in the transmitted
    # compact string — the verifier is expected to supply the payload bytes
    # itself, which is exactly what internal/signature.Verify(compactJWS,
    # payload, ...) does.
    return f"{header_b64}..{sig_b64}"


def new_child_pod_name(prefix: str = "nhi-demo-child") -> str:
    # Chosen by the PARENT before the child pod is created — this is what
    # lets child_selectors name k8s:pod-name (manifest.Validate()'s
    # distinguishing-selector allow-list) even though the pod does not exist
    # yet at manifest-submission time: the
    # parent picks the name, submits it as a selector, and only creates the
    # pod (with this exact metadata.name) after the vending service has
    # already minted the matching SPIRE entry. See parent.py.
    return f"{prefix}-{uuid.uuid4().hex[:10]}"
