"""Offline certificate-chain coverage checking.

Core ideas
----------
* Chains are built by matching issuer/subject names and verifying each link's
  signature; every issuer (intermediate or root) must carry BasicConstraints
  CA=TRUE.  A chain is only usable for a cluster when it terminates at one of
  that cluster's trusted roots.
* A chain's usable interval is the intersection of the validity periods of all
  certificates in it (clipped to the requested check window).
* Coverage of the window is computed with an interval sweep over chain
  boundaries -- the window is only ever split at points where some chain
  starts or stops being valid, never sampled second by second.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Sequence

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed25519,
    ed448,
    padding,
    rsa,
)

# Safety bound so a pathological pool of intermediates cannot loop forever.
MAX_CHAIN_DEPTH = 10


class PemParseError(ValueError):
    """Raised when a submitted PEM block cannot be parsed as a certificate."""


@dataclass(frozen=True)
class CertWrap:
    """A parsed certificate plus the metadata the checker needs."""

    cert: x509.Certificate
    name: Optional[str]
    fingerprint: str  # SHA-256 over DER, hex
    subject: str
    issuer: str
    not_before: datetime  # tz-aware UTC
    not_after: datetime  # tz-aware UTC
    is_ca: bool


@dataclass(frozen=True)
class Chain:
    """A verified chain (leaf .. root) and its usable interval."""

    certs: tuple  # tuple[CertWrap, ...], leaf first, root last
    valid_from: datetime
    valid_until: datetime


@dataclass(frozen=True)
class Segment:
    """A maximal window slice during which the same set of chains is usable."""

    start: datetime
    end: datetime
    chain_ids: tuple  # tuple[int, ...] indices into the cluster's chain list


def _validity_utc(cert: x509.Certificate) -> tuple[datetime, datetime]:
    try:
        return cert.not_valid_before_utc, cert.not_valid_after_utc
    except AttributeError:  # cryptography < 42
        return (
            cert.not_valid_before.replace(tzinfo=timezone.utc),
            cert.not_valid_after.replace(tzinfo=timezone.utc),
        )


def parse_cert(pem: str, name: Optional[str], role: str) -> CertWrap:
    label = name or "<unnamed>"
    try:
        cert = x509.load_pem_x509_certificate(pem.encode("utf-8"))
    except Exception as exc:
        raise PemParseError(f"{role} '{label}': not a valid PEM certificate ({exc})")
    not_before, not_after = _validity_utc(cert)
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        is_ca = bool(bc.ca)
    except x509.ExtensionNotFound:
        is_ca = False
    return CertWrap(
        cert=cert,
        name=name,
        fingerprint=cert.fingerprint(hashes.SHA256()).hex(),
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        not_before=not_before,
        not_after=not_after,
        is_ca=is_ca,
    )


def verify_child_signature(child: x509.Certificate, issuer: x509.Certificate) -> bool:
    """Verify ``child``'s signature with ``issuer``'s public key."""
    pub = issuer.public_key()
    try:
        params = child.signature_algorithm_parameters
    except Exception:
        params = None
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            pad = params if params is not None else padding.PKCS1v15()
            pub.verify(
                child.signature,
                child.tbs_certificate_bytes,
                pad,
                child.signature_hash_algorithm,
            )
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            algo = params if params is not None else ec.ECDSA(child.signature_hash_algorithm)
            pub.verify(child.signature, child.tbs_certificate_bytes, algo)
        elif isinstance(pub, dsa.DSAPublicKey):
            pub.verify(
                child.signature,
                child.tbs_certificate_bytes,
                child.signature_hash_algorithm,
            )
        elif isinstance(pub, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            pub.verify(child.signature, child.tbs_certificate_bytes)
        else:
            return False
    except InvalidSignature:
        return False
    except Exception:
        return False
    return True


def _extend_paths(
    leaf: CertWrap,
    intermediates: Sequence[CertWrap],
    roots: Sequence[CertWrap],
) -> list[tuple[CertWrap, ...]]:
    """All verified paths from ``leaf`` to any of ``roots`` (leaf .. root)."""
    results: list[tuple[CertWrap, ...]] = []

    def dfs(path: list[CertWrap], in_path: frozenset) -> None:
        current = path[-1]
        if len(path) > MAX_CHAIN_DEPTH:
            return
        for root in roots:
            if (
                root.cert.subject == current.cert.issuer
                and root.is_ca
                and verify_child_signature(current.cert, root.cert)
            ):
                results.append(tuple(path + [root]))
        for inter in intermediates:
            if inter.fingerprint in in_path:
                continue
            if (
                inter.cert.subject == current.cert.issuer
                and inter.is_ca
                and verify_child_signature(current.cert, inter.cert)
            ):
                dfs(path + [inter], in_path | {inter.fingerprint})

    dfs([leaf], frozenset({leaf.fingerprint}))
    return results


def build_chains(
    leaves: Sequence[CertWrap],
    intermediates: Sequence[CertWrap],
    roots: Sequence[CertWrap],
    window_start: datetime,
    window_end: datetime,
) -> list[Chain]:
    """Verified, de-duplicated chains for one cluster, clipped to the window."""
    chains: list[Chain] = []
    seen: set[tuple[str, ...]] = set()
    for leaf in leaves:
        for path in _extend_paths(leaf, intermediates, roots):
            key = tuple(c.fingerprint for c in path)
            if key in seen:
                continue
            seen.add(key)
            start = max(max(c.not_before for c in path), window_start)
            end = min(min(c.not_after for c in path), window_end)
            if start < end:
                chains.append(Chain(certs=path, valid_from=start, valid_until=end))
    chains.sort(key=lambda ch: (ch.valid_from, ch.valid_until, ch.certs[0].fingerprint))
    return chains


def coverage_segments(
    chains: Sequence[Chain],
    window_start: datetime,
    window_end: datetime,
) -> list[Segment]:
    """Partition the window into maximal segments with a constant chain set.

    Only chain boundary instants are used as split points, so the number of
    segments is bounded by 2 * len(chains) + 1 regardless of window length.
    """
    points = {window_start, window_end}
    for ch in chains:
        points.add(ch.valid_from)
        points.add(ch.valid_until)
    ordered = sorted(points)

    segments: list[Segment] = []
    for a, b in zip(ordered, ordered[1:]):
        active = tuple(
            i for i, ch in enumerate(chains) if ch.valid_from <= a and ch.valid_until >= b
        )
        if segments and segments[-1].chain_ids == active and segments[-1].end == a:
            prev = segments[-1]
            segments[-1] = Segment(start=prev.start, end=b, chain_ids=prev.chain_ids)
        else:
            segments.append(Segment(start=a, end=b, chain_ids=active))
    return segments
