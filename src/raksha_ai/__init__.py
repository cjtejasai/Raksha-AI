"""
🔱 Raksha - AI Security SDK

Framework-agnostic security evaluation for LLMs and AI agents.
Protect your AI with comprehensive threat detection.
"""

from raksha_ai.scanner import SecurityScanner
from raksha_ai.core.models import (
    SecurityResult,
    ThreatDetection,
    ThreatLevel,
    ThreatType,
)

# Export main scanner classes
__version__ = "0.1.0"
__all__ = [
    "SecurityScanner",
    "SecurityResult",
    "ThreatDetection",
    "ThreatLevel",
    "ThreatType",
]