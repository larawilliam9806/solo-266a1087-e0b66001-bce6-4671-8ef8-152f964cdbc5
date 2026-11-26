#!/usr/bin/env python3
"""Generate a demo PKI and a ready-to-post request body for /check.

Usage:
    python scripts/gen_sample.py [output_dir]

Writes <output_dir>/request.json (default: ./sample).  Post it with:

    curl -s http://localhost:8000/check -H 'Content-Type: application/json' \
        --data @sample/request.json | jq
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

UTC = timezone.utc
NOW = datetime.now(UTC).replace(microsecond=0)


def cn(value: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, value)])


def make_cert(subject, issuer, issuer_key, subject_key, days, ca):
    key = ed25519.Ed25519PrivateKey.generate() if subject_key is None else subject_key
    signer = issuer_key if issuer_key is not None else key  # None => self-signed
    cert = (
        x509.CertificateBuilder()
        .subject_name(cn(subject))
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=days[0]))
        .not_valid_after(NOW + timedelta(days=days[1]))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .sign(signer, algorithm=None)
    )
    return key, cert


def pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def main() -> None:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "sample")
    out.mkdir(parents=True, exist_ok=True)

    # Cluster "east" root; the old leaf expires mid-window, the new one
    # takes over -- the pair covers the whole window.
    root_e_key, root_e = make_cert("root-east", cn("root-east"), None, None, (3650, 3650), True)
    ica_key, ica = make_cert("ica-east", root_e.subject, root_e_key, None, (400, 700), True)
    _, leaf_old = make_cert("gw-old", ica.subject, ica_key, None, (200, 5), False)
    _, leaf_new = make_cert("gw-new", ica.subject, ica_key, None, (2, 360), False)

    # Cluster "west" has its own root and no chain from these leaves.
    _, root_w = make_cert("root-west", cn("root-west"), None, None, (3650, 3650), True)

    request = {
        "window": {
            "start": NOW.isoformat().replace("+00:00", "Z"),
            "end": (NOW + timedelta(days=30)).isoformat().replace("+00:00", "Z"),
        },
        "leaf_certificates": [
            {"name": "gw-old", "pem": pem(leaf_old)},
            {"name": "gw-new", "pem": pem(leaf_new)},
        ],
        "intermediate_certificates": [{"name": "ica-east", "pem": pem(ica)}],
        "clusters": [
            {"name": "east", "trusted_roots": [{"name": "root-east", "pem": pem(root_e)}]},
            {"name": "west", "trusted_roots": [{"name": "root-west", "pem": pem(root_w)}]},
        ],
    }
    path = out / "request.json"
    path.write_text(json.dumps(request, indent=2), encoding="utf-8")
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
