"""Core data models for security detection"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ThreatLevel(str, Enum):
    """Severity level of detected threats"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ThreatType(str, Enum):
    """Types of security threats"""
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    PII_LEAKAGE = "pii_leakage"
    TOXIC_CONTENT = "toxic_content"
    DATA_EXFILTRATION = "data_exfiltration"
    TOOL_MISUSE = "tool_misuse"
    GOAL_HIJACKING = "goal_hijacking"
    RECURSIVE_LOOP = "recursive_loop"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    CREDENTIAL_LEAK = "credential_leak"
    SYSTEM_PROMPT_LEAK = "system_prompt_leak"
    INSTRUCTION_OVERRIDE = "instruction_override"
    CONTEXT_MANIPULATION = "context_manipulation"


class ThreatDetection(BaseModel):
    """Individual threat detection result"""
    threat_type: ThreatType
    level: ThreatLevel
    confidence: float = Field(ge=0.0, le=1.0, description="Detection confidence score")
    description: str
    evidence: Optional[str] = None
    mitigation: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SecurityResult(BaseModel):
    """Complete security evaluation result"""
    score: float = Field(ge=0.0, le=1.0, description="Overall security score (0=unsafe, 1=safe)")
    threats: List[ThreatDetection] = Field(default_factory=list)
    is_safe: bool
    execution_time_ms: float
    detector_results: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @property
    def has_critical_threats(self) -> bool:
        """Check if any critical threats were detected"""
        return any(t.level == ThreatLevel.CRITICAL for t in self.threats)

    @property
    def threat_summary(self) -> Dict[ThreatLevel, int]:
        """Get count of threats by severity level"""
        summary = {level: 0 for level in ThreatLevel}
        for threat in self.threats:
            summary[threat.level] += 1
        return summary


class DetectorConfig(BaseModel):
    """Configuration for individual detector"""
    enabled: bool = True
    threshold: float = Field(default=0.7, ge=0.0, le=1.0)
    custom_rules: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)