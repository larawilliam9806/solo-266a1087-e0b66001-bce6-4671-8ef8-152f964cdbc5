"""Tests for the offline chain-coverage checker.

Builds small throwaway PKIs in memory (Ed25519, so it is fast) and exercises
both the service layer and the HTTP API.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from app.main import app
from app.service import build_chains, coverage_segments, parse_cert

UTC = timezone.utc


def dt(month: int, day: int, year: int = 2026) -> datetime:
    return datetime(year, month, day, tzinfo=UTC)


def _cn(value: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, value)])


def _key() -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.generate()


def _cert(subject_cn, issuer, issuer_key, subject_key, nb, na, ca) -> x509.Certificate:
    return (
        x509.CertificateBuilder()
        .subject_name(_cn(subject_cn))
        .issuer_name(issuer)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb)
        .not_valid_after(na)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .sign(issuer_key, algorithm=None)
    )


def make_root(cn: str, nb: datetime, na: datetime):
    key = _key()
    return key, _cert(cn, _cn(cn), key, key, nb, na, ca=True)


def make_child(cn, issuer_cert, issuer_key, nb, na, ca, key=None):
    key = key or _key()
    return key, _cert(cn, issuer_cert.subject, issuer_key, key, nb, na, ca)


def pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def wrap(cert, name="c"):
    return parse_cert(pem(cert), name, "test")


@pytest.fixture()
def pki():
    """root -> ica -> {leaf1, leaf2}; leaf2 takes over when leaf1 expires."""
    root_key, root = make_root("root-a", dt(1, 1, 2020), dt(1, 1, 2030))
    ica_key, ica = make_child("ica-a", root, root_key, dt(1, 1, 2025), dt(1, 6, 2028), ca=True)
    _, leaf1 = make_child("gw-1", ica, ica_key, dt(1, 1), dt(6, 1), ca=False)
    _, leaf2 = make_child("gw-2", ica, ica_key, dt(5, 1), dt(12, 1), ca=False)
    return {
        "root": (root_key, root),
        "ica": (ica_key, ica),
        "leaf1": leaf1,
        "leaf2": leaf2,
    }


WINDOW = (dt(1, 1), dt(12, 1))


def _chains(pki, leaves, roots=None, window=WINDOW):
    roots = roots if roots is not None else [wrap(pki["root"][1], "root-a")]
    return build_chains(
        [wrap(c, "leaf") for c in leaves],
        [wrap(pki["ica"][1], "ica-a")],
        roots,
        window[0],
        window[1],
    )


def test_chain_interval_is_intersection_of_validities(pki):
    chains = _chains(pki, [pki["leaf1"]])
    assert len(chains) == 1
    ch = chains[0]
    assert [c.subject for c in ch.certs] == ["CN=gw-1", "CN=ica-a", "CN=root-a"]
    assert ch.valid_from == dt(1, 1)  # max of notBefore, clipped to window
    assert ch.valid_until == dt(6, 1)  # leaf expires first


def test_handover_between_chains_covers_window(pki):
    chains = _chains(pki, [pki["leaf1"], pki["leaf2"]])
    segments = coverage_segments(chains, *WINDOW)
    assert [(s.start, s.end, s.chain_ids) for s in segments] == [
        (dt(1, 1), dt(5, 1), (0,)),
        (dt(5, 1), dt(6, 1), (0, 1)),
        (dt(6, 1), dt(12, 1), (1,)),
    ]


def test_gap_is_reported_with_exact_bounds(pki):
    ica_key, ica = pki["ica"]
    _, leaf3 = make_child("gw-3", ica, ica_key, dt(8, 1), dt(12, 1), ca=False)
    chains = _chains(pki, [pki["leaf1"], leaf3])
    segments = coverage_segments(chains, *WINDOW)
    gaps = [(s.start, s.end) for s in segments if not s.chain_ids]
    assert gaps == [(dt(6, 1), dt(8, 1))]


def test_non_ca_intermediate_is_rejected(pki):
    root_key, root = pki["root"]
    bad_key, bad_ica = make_child("ica-bad", root, root_key, dt(1, 1, 2025), dt(1, 1, 2029), ca=False)
    _, leaf = make_child("gw-x", bad_ica, bad_key, dt(1, 1), dt(12, 1), ca=False)
    chains = build_chains([wrap(leaf)], [wrap(bad_ica)], [wrap(root)], *WINDOW)
    assert chains == []


def test_issuer_name_match_without_valid_signature_is_rejected(pki):
    # ica claims issuer "root-a" but was actually signed by an impostor key.
    impostor_key, _ = make_root("root-a", dt(1, 1, 2020), dt(1, 1, 2030))
    ica_key, forged = make_child("ica-a", pki["root"][1], impostor_key, dt(1, 1, 2025), dt(1, 1, 2029), ca=True)
    _, leaf = make_child("gw-y", forged, ica_key, dt(1, 1), dt(12, 1), ca=False)
    chains = build_chains([wrap(leaf)], [wrap(forged)], [wrap(pki["root"][1])], *WINDOW)
    assert chains == []


def test_chain_must_end_at_the_clusters_own_root(pki):
    other_key, other_root = make_root("root-b", dt(1, 1, 2020), dt(1, 1, 2030))
    chains = _chains(pki, [pki["leaf1"]], roots=[wrap(other_root, "root-b")])
    assert chains == []


def test_expiring_root_truncates_chain(pki):
    root_key, short_root = make_root("root-s", dt(1, 1, 2020), dt(3, 1))
    ica_key, ica = make_child("ica-s", short_root, root_key, dt(1, 1, 2025), dt(1, 1, 2029), ca=True)
    _, leaf = make_child("gw-s", ica, ica_key, dt(1, 1), dt(12, 1), ca=False)
    chains = build_chains([wrap(leaf)], [wrap(ica)], [wrap(short_root)], *WINDOW)
    assert len(chains) == 1
    assert chains[0].valid_until == dt(3, 1)
    segments = coverage_segments(chains, *WINDOW)
    gaps = [(s.start, s.end) for s in segments if not s.chain_ids]
    assert gaps == [(dt(3, 1), dt(12, 1))]


def test_abutting_chains_leave_no_gap(pki):
    ica_key, ica = pki["ica"]
    _, leaf_a = make_child("gw-a", ica, ica_key, dt(1, 1), dt(6, 1), ca=False)
    _, leaf_b = make_child("gw-b", ica, ica_key, dt(6, 1), dt(12, 1), ca=False)
    chains = _chains(pki, [leaf_a, leaf_b])
    segments = coverage_segments(chains, *WINDOW)
    assert all(s.chain_ids for s in segments)


# ---------------------------------------------------------------------------
# API level
# ---------------------------------------------------------------------------


def _request(pki, window=None, roots=None, clusters=None):
    roots = roots if roots is not None else [pki["root"][1]]
    window = window or {"start": "2026-01-01T00:00:00Z", "end": "2026-12-01T00:00:00Z"}
    if clusters is None:
        clusters = [
            {
                "name": "cluster-east",
                "trusted_roots": [{"name": "root-a", "pem": pem(r)} for r in roots],
            }
        ]
    return {
        "window": window,
        "leaf_certificates": [
            {"name": "gw-1", "pem": pem(pki["leaf1"])},
            {"name": "gw-2", "pem": pem(pki["leaf2"])},
        ],
        "intermediate_certificates": [{"name": "ica-a", "pem": pem(pki["ica"][1])}],
        "clusters": clusters,
    }


def test_api_full_coverage_with_handover(pki):
    client = TestClient(app)
    resp = client.post("/check", json=_request(pki))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    cluster = body["clusters"][0]
    assert cluster["name"] == "cluster-east"
    assert cluster["full_coverage"] is True
    assert cluster["gaps"] == []
    assert [(s["start"], s["end"], [c["id"] for c in s["chains"]]) for s in cluster["timeline"]] == [
        ("2026-01-01T00:00:00Z", "2026-05-01T00:00:00Z", ["chain-1"]),
        ("2026-05-01T00:00:00Z", "2026-06-01T00:00:00Z", ["chain-1", "chain-2"]),
        ("2026-06-01T00:00:00Z", "2026-12-01T00:00:00Z", ["chain-2"]),
    ]
    chain1 = cluster["chains"][0]
    assert chain1["names"] == ["gw-1", "ica-a", "root-a"]
    assert len(chain1["fingerprints"]) == 3
    assert chain1["valid_from"] == "2026-01-01T00:00:00Z"
    assert chain1["valid_until"] == "2026-06-01T00:00:00Z"


def test_api_per_cluster_results(pki):
    _, other_root = make_root("root-b", dt(1, 1, 2020), dt(1, 1, 2030))
    clusters = [
        {"name": "east", "trusted_roots": [{"pem": pem(pki["root"][1])}]},
        {"name": "west", "trusted_roots": [{"pem": pem(other_root)}]},
    ]
    client = TestClient(app)
    resp = client.post("/check", json=_request(pki, clusters=clusters))
    assert resp.status_code == 200
    east, west = resp.json()["clusters"]
    assert east["full_coverage"] is True
    assert west["full_coverage"] is False
    assert west["chains"] == []
    assert west["gaps"] == [{"start": "2026-01-01T00:00:00Z", "end": "2026-12-01T00:00:00Z"}]


def test_api_rejects_bad_pem(pki):
    payload = _request(pki)
    payload["leaf_certificates"][0]["pem"] = "-----BEGIN CERTIFICATE-----\\nbm90\\n-----END CERTIFICATE-----"
    client = TestClient(app)
    resp = client.post("/check", json=payload)
    assert resp.status_code == 422


def test_api_rejects_inverted_window(pki):
    client = TestClient(app)
    resp = client.post(
        "/check",
        json=_request(pki, window={"start": "2026-12-01T00:00:00Z", "end": "2026-01-01T00:00:00Z"}),
    )
    assert resp.status_code == 422


def test_api_window_with_offset_is_normalized(pki):
    client = TestClient(app)
    resp = client.post(
        "/check",
        json=_request(
            pki,
            window={"start": "2026-01-01T08:00:00+08:00", "end": "2026-12-01T08:00:00+08:00"},
        ),
    )
    assert resp.status_code == 200
    assert resp.json()["window"] == {
        "start": "2026-01-01T00:00:00Z",
        "end": "2026-12-01T00:00:00Z",
    }
