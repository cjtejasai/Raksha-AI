"""Base detector interface"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from raksha_ai.core.models import ThreatDetection, DetectorConfig


class BaseDetector(ABC):
    """Base class for all security detectors"""

    def __init__(self, config: Optional[DetectorConfig] = None):
        self.config = config or DetectorConfig()
        self._initialize()

    def _initialize(self) -> None:
        """Initialize detector-specific resources"""
        pass

    @abstractmethod
    def detect(
        self,
        prompt: Optional[str] = None,
        response: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ThreatDetection]:
        """
        Detect security threats in the given input

        Args:
            prompt: User input/prompt to analyze
            response: Model response to analyze
            context: Additional context (agent state, tools used, etc.)

        Returns:
            List of detected threats
        """
        pass

    @property
    @abstractmethod
    def detector_name(self) -> str:
        """Name of the detector"""
        pass

    @property
    def is_enabled(self) -> bool:
        """Check if detector is enabled"""
        return self.config.enabled

    def _calculate_confidence(self, score: float) -> float:
        """Normalize score to confidence value between 0 and 1"""
        return max(0.0, min(1.0, score))