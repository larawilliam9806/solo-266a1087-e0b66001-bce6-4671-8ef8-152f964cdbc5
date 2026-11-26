"""Request/response schemas for the chain-coverage checker."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


def to_utc(value: datetime) -> datetime:
    """Normalize to tz-aware UTC; naive values are assumed to be UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def iso_z(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class PemCertificate(BaseModel):
    name: Optional[str] = Field(default=None, description="Optional label echoed back in results")
    pem: str = Field(description="PEM-encoded X.509 certificate")


class Window(BaseModel):
    start: datetime = Field(description="Window start, UTC (ISO 8601)")
    end: datetime = Field(description="Window end, UTC (ISO 8601)")

    @field_validator("start", "end")
    @classmethod
    def _normalize(cls, v: datetime) -> datetime:
        return to_utc(v)

    @model_validator(mode="after")
    def _ordered(self) -> "Window":
        if not self.start < self.end:
            raise ValueError("window.start must be earlier than window.end")
        return self


class Cluster(BaseModel):
    name: str
    trusted_roots: List[PemCertificate] = Field(
        min_length=1, description="Trusted root certificates for this cluster"
    )


class CheckRequest(BaseModel):
    window: Window
    leaf_certificates: List[PemCertificate] = Field(
        min_length=1, description="Gateway leaf certificates (PEM)"
    )
    intermediate_certificates: List[PemCertificate] = Field(
        default_factory=list, description="Issuing intermediate certificates (PEM)"
    )
    clusters: List[Cluster] = Field(min_length=1)

    @model_validator(mode="after")
    def _unique_cluster_names(self) -> "CheckRequest":
        names = [c.name for c in self.clusters]
        if len(names) != len(set(names)):
            raise ValueError("cluster names must be unique")
        return self


class ChainOut(BaseModel):
    id: str
    names: List[Optional[str]]
    subjects: List[str]
    fingerprints: List[str]  # SHA-256, leaf first, root last
    valid_from: str
    valid_until: str


class ChainRef(BaseModel):
    id: str
    fingerprints: List[str]


class SegmentOut(BaseModel):
    start: str
    end: str
    chains: List[ChainRef]  # empty => coverage gap


class GapOut(BaseModel):
    start: str
    end: str


class ClusterResult(BaseModel):
    name: str
    full_coverage: bool
    chains: List[ChainOut]
    timeline: List[SegmentOut]
    gaps: List[GapOut]


class WindowOut(BaseModel):
    start: str
    end: str


class CheckResponse(BaseModel):
    window: WindowOut
    clusters: List[ClusterResult]
