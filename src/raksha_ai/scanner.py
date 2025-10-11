"""
🔱 Raksha Security Scanner

Framework-agnostic security scanner for LLMs and AI agents.
"""

import time
from typing import Any, Dict, List, Optional
from raksha_ai.core.detector import BaseDetector
from raksha_ai.core.models import SecurityResult, ThreatLevel


class SecurityScanner:
    """
    Framework-agnostic security scanner that coordinates multiple threat detectors.

    Works standalone or with any framework (Phoenix, LangChain, LlamaIndex, etc.)

    Example:
        >>> from raksha_ai import SecurityScanner
        >>> scanner = SecurityScanner()
        >>> result = scanner.scan_input("User prompt here")
        >>> if not result.is_safe:
        ...     print(f"Threats: {result.threats}")
    """

    def __init__(
        self,
        detectors: Optional[List[BaseDetector]] = None,
        safe_threshold: float = 0.7,
        enable_logging: bool = False,
    ):
        """
        Initialize Security Scanner

        Args:
            detectors: List of security detectors to use (None = use defaults)
            safe_threshold: Minimum score to consider content safe (0-1)
            enable_logging: Enable detailed logging
        """
        self.detectors = detectors or self._get_default_detectors()
        self.safe_threshold = safe_threshold
        self.enable_logging = enable_logging

    def _get_default_detectors(self) -> List[BaseDetector]:
        """Get default set of detectors"""
        from raksha_ai.detectors import (
            PromptInjectionDetector,
            PIIDetector,
            ToxicityDetector,
        )

        return [
            PromptInjectionDetector(),
            PIIDetector(),
            ToxicityDetector(),
        ]

    def scan_input(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> SecurityResult:
        """
        Scan input text for security threats

        Args:
            text: Input text to scan
            context: Additional context (agent state, etc.)

        Returns:
            SecurityResult with threat detections
        """
        return self._scan(prompt=text, context=context)

    def scan_output(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> SecurityResult:
        """
        Scan output text for security threats

        Args:
            text: Output text to scan
            context: Additional context

        Returns:
            SecurityResult with threat detections
        """
        return self._scan(response=text, context=context)

    def scan(
        self,
        prompt: Optional[str] = None,
        response: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> SecurityResult:
        """
        Scan both prompt and response for security threats

        Args:
            prompt: User prompt to evaluate
            response: Model response to evaluate
            context: Additional context

        Returns:
            SecurityResult with threat detections
        """
        return self._scan(prompt=prompt, response=response, context=context)

    def _scan(
        self,
        prompt: Optional[str] = None,
        response: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> SecurityResult:
        """
        Internal scan method

        Args:
            prompt: User prompt to evaluate
            response: Model response to evaluate
            context: Additional context

        Returns:
            SecurityResult with threat detections
        """
        start_time = time.time()
        all_threats = []
        detector_results = {}

        # Run all enabled detectors
        for detector in self.detectors:
            if not detector.is_enabled:
                continue

            try:
                threats = detector.detect(
                    prompt=prompt,
                    response=response,
                    context=context
                )
                all_threats.extend(threats)
                detector_results[detector.detector_name] = {
                    "threats_found": len(threats),
                    "threats": [t.model_dump() for t in threats]
                }

                if self.enable_logging and threats:
                    print(f"[Raksha] {detector.detector_name}: {len(threats)} threats")

            except Exception as e:
                if self.enable_logging:
                    print(f"[Raksha] Error in {detector.detector_name}: {e}")
                detector_results[detector.detector_name] = {"error": str(e)}

        # Calculate overall security score
        score = self._calculate_security_score(all_threats)
        execution_time = (time.time() - start_time) * 1000

        result = SecurityResult(
            score=score,
            threats=all_threats,
            is_safe=score >= self.safe_threshold,
            execution_time_ms=execution_time,
            detector_results=detector_results,
            metadata={
                "prompt_length": len(prompt) if prompt else 0,
                "response_length": len(response) if response else 0,
                "num_detectors": len(self.detectors),
            }
        )

        return result

    def _calculate_security_score(self, threats: List[Any]) -> float:
        """
        Calculate overall security score based on detected threats

        Returns score between 0 (unsafe) and 1 (safe)
        """
        if not threats:
            return 1.0

        # Weight threats by severity
        severity_weights = {
            ThreatLevel.CRITICAL: 1.0,
            ThreatLevel.HIGH: 0.7,
            ThreatLevel.MEDIUM: 0.4,
            ThreatLevel.LOW: 0.2,
            ThreatLevel.INFO: 0.1,
        }

        total_penalty = 0.0
        for threat in threats:
            weight = severity_weights.get(threat.level, 0.5)
            penalty = weight * threat.confidence
            total_penalty += penalty

        # Normalize to 0-1 score (with diminishing returns)
        score = max(0.0, 1.0 - (total_penalty / (1 + total_penalty)))
        return score

    def add_detector(self, detector: BaseDetector) -> None:
        """Add a new detector to the scanner"""
        self.detectors.append(detector)

    def remove_detector(self, detector_name: str) -> None:
        """Remove a detector by name"""
        self.detectors = [d for d in self.detectors if d.detector_name != detector_name]

    def get_detector(self, detector_name: str) -> Optional[BaseDetector]:
        """Get a detector by name"""
        for detector in self.detectors:
            if detector.detector_name == detector_name:
                return detector
        return None

    def list_detectors(self) -> List[str]:
        """List all active detector names"""
        return [d.detector_name for d in self.detectors]


# Alias for backward compatibility
SecurityGuard = SecurityScanner