"""
SafeX Core Package
"""

from safex.core.models import (
    DetectionSignal,
    HeaderAnalysis,
    BodyAnalysis,
    LinkAnalysis,
    AttachmentInventory,
    SafeGuidance,
    EmailAnalysisResult,
)
from safex.core.analyzer import analyze_email
from safex.core.test_samples import get_test_samples

__all__ = [
    "DetectionSignal",
    "HeaderAnalysis",
    "BodyAnalysis",
    "LinkAnalysis",
    "AttachmentInventory",
    "SafeGuidance",
    "EmailAnalysisResult",
    "analyze_email",
    "get_test_samples",
]
