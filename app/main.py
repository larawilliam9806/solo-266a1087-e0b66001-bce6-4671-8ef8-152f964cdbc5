"""FastAPI entrypoint for the offline certificate-chain coverage checker."""

from __future__ import annotations

from fastapi import FastAPI, HTTPException

from .models import (
    ChainOut,
    ChainRef,
    CheckRequest,
    CheckResponse,
    ClusterResult,
    GapOut,
    SegmentOut,
    WindowOut,
    iso_z,
)
from .service import (
    PemParseError,
    build_chains,
    coverage_segments,
    parse_cert,
)

app = FastAPI(
    title="Gateway certificate chain coverage checker",
    version="1.0.0",
    description=(
        "Offline check of whether each cluster's certificate chain covers a "
        "maintenance window. Verifies signatures, CA flags and validity "
        "periods only; every chain must terminate at the cluster's own "
        "trusted root. Coverage is computed by interval arithmetic, not by "
        "per-second probing."
    ),
)


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@app.post("/check", response_model=CheckResponse)
def check(req: CheckRequest) -> CheckResponse:
    try:
        leaves = [parse_cert(c.pem, c.name, "leaf") for c in req.leaf_certificates]
        intermediates = [
            parse_cert(c.pem, c.name, "intermediate") for c in req.intermediate_certificates
        ]
        roots_by_cluster = {
            cluster.name: [
                parse_cert(r.pem, r.name, f"root of cluster '{cluster.name}'")
                for r in cluster.trusted_roots
            ]
            for cluster in req.clusters
        }
    except PemParseError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    win_start, win_end = req.window.start, req.window.end
    results: list[ClusterResult] = []

    for cluster in req.clusters:
        roots = roots_by_cluster[cluster.name]
        chains = build_chains(leaves, intermediates, roots, win_start, win_end)
        segments = coverage_segments(chains, win_start, win_end)

        chain_outs = [
            ChainOut(
                id=f"chain-{i + 1}",
                names=[c.name for c in ch.certs],
                subjects=[c.subject for c in ch.certs],
                fingerprints=[c.fingerprint for c in ch.certs],
                valid_from=iso_z(ch.valid_from),
                valid_until=iso_z(ch.valid_until),
            )
            for i, ch in enumerate(chains)
        ]

        timeline: list[SegmentOut] = []
        gaps: list[GapOut] = []
        for seg in segments:
            refs = [
                ChainRef(
                    id=chain_outs[i].id,
                    fingerprints=chain_outs[i].fingerprints,
                )
                for i in seg.chain_ids
            ]
            timeline.append(
                SegmentOut(start=iso_z(seg.start), end=iso_z(seg.end), chains=refs)
            )
            if not refs:
                gaps.append(GapOut(start=iso_z(seg.start), end=iso_z(seg.end)))

        results.append(
            ClusterResult(
                name=cluster.name,
                full_coverage=not gaps,
                chains=chain_outs,
                timeline=timeline,
                gaps=gaps,
            )
        )

    return CheckResponse(
        window=WindowOut(start=iso_z(win_start), end=iso_z(win_end)),
        clusters=results,
    )
