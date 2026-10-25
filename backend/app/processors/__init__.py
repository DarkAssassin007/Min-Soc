"""Preprocessing layer: parse -> validate -> normalise -> dedupe -> features."""

from __future__ import annotations

from .deduplicator import Deduplicator
from .feature_engineering import FEATURE_ORDER, FeatureExtractor
from .models import FeatureVector, NormalizedEvent, PipelineResult, RawRecord
from .normalizer import dedupe_hash, normalise, normalise_direction
from .parser import parse_record
from .validator import ValidationError, validate

__all__ = [
    "FEATURE_ORDER",
    "Deduplicator",
    "FeatureExtractor",
    "FeatureVector",
    "NormalizedEvent",
    "PipelineResult",
    "RawRecord",
    "ValidationError",
    "dedupe_hash",
    "normalise",
    "normalise_direction",
    "parse_record",
    "validate",
]
