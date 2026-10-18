"""Shared helpers for parent.py and child.py: Workload API access, the
lab-wide audit event shape, and small HTTP conveniences.

Both agents fetch their own credentials from the SPIRE Workload API — no
pre-shared secret, no human action — exactly like cmd/parentsim. This module
exists so that shape is written once instead of twice.
"""

from __future__ import annotations

import datetime
import json
import os
import re
import select
import socket
import struct
import sys
import time
import warnings

import requests
import spiffetls
from cryptography import x509
from OpenSSL import SSL, crypto
from spiffe import JwtSvid, WorkloadApiClient, X509Svid
from spiffe.spiffe_id.spiffe_id import SpiffeId
from spiffe.workloadapi.x509_source import X509Source
from spiffetls.tlsconfig.authorize import authorize_id

DEFAULT_SOCKET_PATH = "unix:///run/spire/sockets/agent.sock"

# --- audit events ------------------------------------------------------------
#
# Mirrors src/vending-service/internal/audit.Event /
# src/resource/audit.go / src/policy-engine/audit.go exactly (the schema is
# shared lab-wide): timestamp, stage, chain_id, actor_spiffe_id, outcome,
# detail. Printed to stdout as one JSON object per line — this pod's
# container log is what `make demo` (src/deploy/scripts/demo.sh) gathers into
# the single, unified audit stream. When NHI_AUDIT_SINK names a path the
# line is appended there instead: a long-lived parent pod points it at the
# container's own stdout (/proc/1/fd/1), so events written by a process
# started with `kubectl exec` still reach `kubectl logs`.
#
# The vocabulary is spawn|attest|vend|operate|log|dispose. The harness emits
# "spawn" (parent.py, the one stage no other component can emit, since it is
# the parent's own decision to fork) and "operate" (the child's own resource
# call, and the parent's side of the mTLS result callback: result accepted or
# refused) — attest/vend/dispose belong to the vending service and policy
# engine, and the resource emits its own operate event; all of them are
# collected from their own pods by demo.sh.
STAGE_SPAWN = "spawn"
STAGE_OPERATE = "operate"

OUTCOME_ALLOW = "allow"
OUTCOME_DENY = "deny"
OUTCOME_ERROR = "error"


def emit_audit_event(
    *,
    stage: str,
    chain_id: str,
    actor_spiffe_id: str,
    outcome: str,
    detail: dict,
) -> None:
    event = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "stage": stage,
        "chain_id": chain_id,
        "actor_spiffe_id": actor_spiffe_id,
        "outcome": outcome,
        "detail": detail,
    }
    line = json.dumps(event, separators=(",", ":"))
    sink = os.environ.get("NHI_AUDIT_SINK")
    if sink:
        try:
            with open(sink, "a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()
            return
        except OSError as err:
            # Never lose an event: fall back to stderr (never stdout, which a
            # caller may be parsing) and say why.
            log(f"audit sink {sink!r} unwritable ({err!r}); event follows on stderr")
            print(line, file=sys.stderr, flush=True)
            return
    print(line, flush=True)


def log(msg: str) -> None:
    """Human-readable progress line, kept OFF stdout (which the audit
    collector treats as JSON-lines-or-ignore) and onto stderr instead, so
    `kubectl logs` stdout capture stays a clean audit stream."""
    print(f"[{datetime.datetime.now(datetime.timezone.utc).isoformat()}] {msg}", file=sys.stderr, flush=True)


# --- Workload API --------------------------------------------------------


def socket_path() -> str:
    return os.environ.get("SPIFFE_ENDPOINT_SOCKET", DEFAULT_SOCKET_PATH)


def new_workload_client() -> WorkloadApiClient:
    return WorkloadApiClient(socket_path())


def fetch_x509_svid_retrying(client: WorkloadApiClient, *, attempts: int = 30, delay_seconds: float = 2.0) -> X509Svid:
    """Fetches this workload's own X.509-SVID, retrying: the SPIRE agent
    needs a moment to notice a freshly created registration entry (the same
    window verify-vending.sh's exit-criterion-B check retries against), and for
    the CHILD in particular, this call may start racing the entry's very
    creation.
    """
    last_err: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            return client.fetch_x509_svid()
        except Exception as err:  # noqa: BLE001 - genuinely want to retry any Workload API failure here
            last_err = err
            log(f"fetch_x509_svid attempt {attempt}/{attempts} failed: {err!r}; retrying")
            time.sleep(delay_seconds)
    assert last_err is not None
    raise last_err


def fetch_jwt_svid_retrying(
    client: WorkloadApiClient, audience: str, *, attempts: int = 30, delay_seconds: float = 2.0
) -> JwtSvid:
    last_err: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            return client.fetch_jwt_svid(audience={audience})
        except Exception as err:  # noqa: BLE001
            last_err = err
            log(f"fetch_jwt_svid attempt {attempt}/{attempts} failed: {err!r}; retrying")
            time.sleep(delay_seconds)
    assert last_err is not None
    raise last_err


# --- HTTP ------------------------------------------------------------------


def bearer_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def http_session(timeout_seconds: float = 15.0) -> requests.Session:
    s = requests.Session()
    s.request = _with_default_timeout(s.request, timeout_seconds)  # type: ignore[method-assign]
    return s


def _with_default_timeout(request_fn, timeout_seconds: float):
    def wrapped(method, url, **kwargs):
        kwargs.setdefault("timeout", timeout_seconds)
        return request_fn(method, url, **kwargs)

    return wrapped


# --- mTLS result callback ------------------------------------------------
#
# A child hands its result straight back to its parent over mutual TLS, each
# side authenticated by its X.509-SVID (spiffe-tls). The parent listens on its
# pod IP before the child pod exists and authorizes exactly the vended child's
# SPIFFE ID; the child dials with authorize_id(<its own parent's ID>), derived
# from its own SPIFFE ID, never from configuration.

CALLBACK_MAX_BYTES = 1 << 20  # largest result line the parent will buffer
CALLBACK_IO_TIMEOUT_SECONDS = 10.0  # one connection's handshake + read, total
DIAL_ATTEMPTS = 5
DIAL_RETRY_DELAY_SECONDS = 1.0

_CHILD_ID_RE = re.compile(r"^(spiffe://[^/]+/.+)/child/[^/]+$")


def parent_id_from_child_id(child_spiffe_id: str) -> str | None:
    """Strips the trailing /child/<single segment> a vended child ID carries
    (manifest.SpawnManifest.child_spiffe_id(): <parent_id>/child/<pod-name>).
    None if the ID does not have that shape."""
    m = _CHILD_ID_RE.match(child_spiffe_id)
    return m.group(1) if m else None


def spiffe_id_from_x509(cert: crypto.X509) -> str | None:
    """The single URI SAN of a pyOpenSSL certificate, if it is a valid
    SPIFFE ID; None otherwise."""
    try:
        san = cert.to_cryptography().extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        uris = san.get_values_for_type(x509.UniformResourceIdentifier)
        if len(uris) != 1:
            return None
        return str(SpiffeId(uris[0]))
    except Exception:  # noqa: BLE001 - any malformed cert simply has no usable ID
        return None


def _wait_fd(conn: SSL.Connection, want_write: bool, deadline: float) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("connection I/O deadline exceeded")
    r, w, _ = select.select([] if want_write else [conn], [conn] if want_write else [], [], remaining)
    if not (r or w):
        raise TimeoutError("connection I/O deadline exceeded")


def _drive(conn: SSL.Connection, op, deadline: float):
    """Runs a pyOpenSSL operation on a non-blocking connection to completion,
    waiting on the socket as it asks, bounded by an absolute deadline."""
    while True:
        try:
            return op()
        except SSL.WantReadError:
            _wait_fd(conn, False, deadline)
        except SSL.WantWriteError:
            _wait_fd(conn, True, deadline)


class CallbackListener:
    """mTLS listener the parent opens for one child's result.

    Built from spiffetls.create_ssl_context (the same context spiffetls.listen
    builds) over our own socket rather than from listen() itself, because the
    listening socket needs SO_REUSEADDR: the parent closes each connection
    first, and a long-lived parent pod serves a new cycle on the same port
    within TIME_WAIT of the last one.
    """

    def __init__(self, address: str, expected_peer_id: str) -> None:
        self.expected_peer_id = expected_peer_id
        self._seen_peer: str | None = None
        self._authorized = False
        authorize = authorize_id(SpiffeId(expected_peer_id))

        def _authorize(cert: crypto.X509) -> bool:
            # Record who knocked (for the audit event) before deciding.
            self._seen_peer = spiffe_id_from_x509(cert)
            try:
                self._authorized = bool(authorize(cert))
            except Exception:  # noqa: BLE001 - any failure to authorize is a refusal
                self._authorized = False
            return self._authorized

        host, port = address.rsplit(":", 1)
        self._source = X509Source(socket_path=socket_path(), timeout_in_seconds=30)
        sock = None
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                ctx = spiffetls.create_ssl_context(
                    SSL.TLS_SERVER_METHOD,
                    self._source,
                    _authorize,
                    SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
                    False,
                )
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, int(port)))
            sock.listen(8)
            self._listener = SSL.Connection(ctx, sock)
            self._listener.set_accept_state()
        except Exception:
            if sock is not None:
                sock.close()
            self._source.close()
            raise

    def close(self) -> None:
        try:
            self._listener.close()
        finally:
            self._source.close()

    def accept_one(self, timeout_seconds: float, *, max_bytes: int = CALLBACK_MAX_BYTES) -> dict:
        """Waits up to timeout_seconds for one connection and handles it.

        Returns {"kind": "idle"} if nothing connected; {"kind": "refused",
        "peer": <presented SPIFFE ID or None>, "reason": str} if the
        connection failed the handshake, was not the authorized peer, or sent
        no usable line; {"kind": "line", "peer": <authenticated peer>, "line":
        bytes} when the authorized peer delivered one newline-terminated line.
        Never raises for a bad peer, and one connection costs at most
        CALLBACK_IO_TIMEOUT_SECONDS.
        """
        ready, _, _ = select.select([self._listener], [], [], max(timeout_seconds, 0))
        if not ready:
            return {"kind": "idle"}
        self._seen_peer, self._authorized = None, False
        try:
            conn, addr = self._listener.accept()
        except OSError as err:
            return {"kind": "refused", "peer": None, "reason": f"accept failed: {err!r}"}
        origin = f"{addr[0]}:{addr[1]}"
        deadline = time.monotonic() + CALLBACK_IO_TIMEOUT_SECONDS
        try:
            conn.setblocking(False)
            try:
                _drive(conn, conn.do_handshake, deadline)
            except (SSL.Error, OSError, TimeoutError) as err:
                why = _err_text(err)
                if self._seen_peer is not None and not self._authorized:
                    why += f"; presented SPIFFE ID {self._seen_peer} is not the delegated child"
                return {"kind": "refused", "peer": self._seen_peer, "reason": f"handshake from {origin} failed: {why}"}
            peer = self._seen_peer
            if not self._authorized or peer != self.expected_peer_id:
                return {"kind": "refused", "peer": peer, "reason": f"peer from {origin} is not the delegated child"}
            buf = b""
            try:
                while b"\n" not in buf:
                    if len(buf) > max_bytes:
                        return {"kind": "refused", "peer": peer, "reason": f"payload from {origin} exceeds {max_bytes} bytes"}
                    chunk = _drive(conn, lambda: conn.recv(65536), deadline)
                    if not chunk:
                        break
                    buf += chunk
            except (SSL.ZeroReturnError, SSL.SysCallError):
                pass  # peer closed; judged below on what arrived
            except (SSL.Error, OSError, TimeoutError) as err:
                return {"kind": "refused", "peer": peer, "reason": f"read from {origin} failed: {_err_text(err)}"}
            line, nl, rest = buf.partition(b"\n")
            if not nl:
                return {"kind": "refused", "peer": peer, "reason": f"payload from {origin} not newline-terminated"}
            if len(line) > max_bytes or rest.strip():
                return {"kind": "refused", "peer": peer, "reason": f"payload from {origin} oversized or has trailing data"}
            # Close politely so the child sees a clean end of stream (its
            # delivery acknowledgement).
            try:
                _drive(conn, conn.shutdown, deadline)
            except (SSL.Error, OSError, TimeoutError):
                pass
            return {"kind": "line", "peer": peer, "line": line}
        finally:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass


def _err_text(err: BaseException) -> str:
    text = str(err) or type(err).__name__
    return text if len(text) <= 300 else text[:300] + "..."


def send_to_parent(address: str, parent_spiffe_id: str, payload: dict) -> None:
    """Child side: dial the parent's callback listener, authorizing exactly
    parent_spiffe_id, send one JSON line, and wait for the parent's clean
    close. Raises on failure. Only the dial is retried (the listener is up
    before this pod exists, but the network may blip); once a payload has been
    sent the outcome is final."""
    source = X509Source(socket_path=socket_path(), timeout_in_seconds=30)
    try:
        authorize = authorize_id(SpiffeId(parent_spiffe_id))
        conn = None
        for attempt in range(1, DIAL_ATTEMPTS + 1):
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", DeprecationWarning)
                    conn = spiffetls.dial(address, source, spiffetls.ClientTlsMode.TLS, authorize)
                break
            except Exception as err:  # noqa: BLE001 - spiffetls raises several types; all are dial failures
                log(f"child: dial {address} attempt {attempt}/{DIAL_ATTEMPTS} failed: {_err_text(err)}")
                if attempt == DIAL_ATTEMPTS:
                    raise
                time.sleep(DIAL_RETRY_DELAY_SECONDS)
        assert conn is not None
        try:
            # Bound the blocking send/recv below (SO_*TIMEO surface as
            # WantRead/WantWrite, which fall through to the except clauses).
            tv = struct.pack("ll", int(CALLBACK_IO_TIMEOUT_SECONDS), 0)
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, tv)
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO, tv)
            conn.sendall(json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n")
            try:
                extra = conn.recv(1)
            except SSL.ZeroReturnError:
                return  # the parent read the line and closed cleanly
            raise ConnectionError(f"parent did not close cleanly after the result (got {extra!r})")
        finally:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass
    finally:
        source.close()
