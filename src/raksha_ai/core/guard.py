"""Main SecurityGuard class for coordinating threat detection"""

import time
from typing import Any, Dict, List, Optional
from raksha_ai.core.detector import BaseDetector
from raksha_ai.core.models import SecurityResult, ThreatLevel


class SecurityGuard:
    """
    Main security guard that coordinates multiple detectors
    and provides unified threat detection
    """

    def __init__(
        self,
        detectors: Optional[List[BaseDetector]] = None,
        phoenix_enabled: bool = False,
        phoenix_project: Optional[str] = None,
        safe_threshold: float = 0.7,
    ):
        """
        Initialize SecurityGuard

        Args:
            detectors: List of security detectors to use
            phoenix_enabled: Enable Phoenix telemetry integration
            phoenix_project: Phoenix project name for logging
            safe_threshold: Minimum score to consider content safe (0-1)
        """
        self.detectors = detectors or []
        self.phoenix_enabled = phoenix_enabled
        self.phoenix_project = phoenix_project
        self.safe_threshold = safe_threshold

        if self.phoenix_enabled:
            self._initialize_phoenix()

    def _initialize_phoenix(self) -> None:
        """Initialize Phoenix telemetry"""
        try:
            import phoenix as px
            from opentelemetry import trace

            self.tracer = trace.get_tracer(__name__)
            print(f"Phoenix telemetry initialized for project: {self.phoenix_project}")
        except ImportError:
            print("Warning: Phoenix not installed. Install with: pip install arize-phoenix")
            self.phoenix_enabled = False

    def evaluate(
        self,
        prompt: Optional[str] = None,
        response: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> SecurityResult:
        """
        Evaluate security threats in prompt/response

        Args:
            prompt: User prompt to evaluate
            response: Model response to evaluate
            context: Additional context (agent state, tools, etc.)

        Returns:
            SecurityResult with threat detections and safety score
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
            except Exception as e:
                print(f"Error in {detector.detector_name}: {e}")
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

        # Log to Phoenix if enabled
        if self.phoenix_enabled:
            self._log_to_phoenix(prompt, response, result, context)

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

        # Normalize to 0-1 score (with diminishing returns for multiple threats)
        score = max(0.0, 1.0 - (total_penalty / (1 + total_penalty)))
        return score

    def _log_to_phoenix(
        self,
        prompt: Optional[str],
        response: Optional[str],
        result: SecurityResult,
        context: Optional[Dict[str, Any]],
    ) -> None:
        """Log security evaluation to Phoenix"""
        try:
            with self.tracer.start_as_current_span("security_evaluation") as span:
                span.set_attribute("security.score", result.score)
                span.set_attribute("security.is_safe", result.is_safe)
                span.set_attribute("security.threats_count", len(result.threats))
                span.set_attribute("security.has_critical", result.has_critical_threats)

                for level, count in result.threat_summary.items():
                    span.set_attribute(f"security.threats.{level.value}", count)

                if result.threats:
                    threat_types = [t.threat_type.value for t in result.threats]
                    span.set_attribute("security.threat_types", ",".join(threat_types))
        except Exception as e:
            print(f"Failed to log to Phoenix: {e}")

    def add_detector(self, detector: BaseDetector) -> None:
        """Add a new detector"""
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