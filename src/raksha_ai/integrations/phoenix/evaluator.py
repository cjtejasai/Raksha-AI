"""Phoenix custom evaluator for security threats"""

from typing import Any, Dict, List, Optional, Union
from raksha_ai.core.guard import SecurityGuard
from raksha_ai.core.models import SecurityResult
from raksha_ai.detectors import (
    PromptInjectionDetector,
    PIIDetector,
    ToxicityDetector,
    DataExfiltrationDetector,
)
from raksha_ai.agents import (
    ToolMisuseDetector,
    GoalHijackingDetector,
    RecursiveLoopDetector,
)


class PhoenixSecurityEvaluator:
    """
    Phoenix custom evaluator for security threat detection.
    Integrates with Phoenix experiments and traces.
    """

    def __init__(
        self,
        detectors: Union[str, List[str]] = "all",
        threshold: float = 0.7,
        phoenix_project: Optional[str] = None,
    ):
        """
        Initialize Phoenix security evaluator

        Args:
            detectors: Which detectors to use. Options:
                - "all": Use all available detectors
                - "basic": Prompt injection, PII, toxicity
                - "agent": Agent-specific detectors only
                - List of detector names
            threshold: Safety threshold (0-1)
            phoenix_project: Phoenix project name
        """
        self.threshold = threshold
        self.phoenix_project = phoenix_project

        # Initialize detectors based on configuration
        detector_list = self._initialize_detectors(detectors)

        # Create security guard
        self.guard = SecurityGuard(
            detectors=detector_list,
            phoenix_enabled=True,
            phoenix_project=phoenix_project,
            safe_threshold=threshold,
        )

    def _initialize_detectors(self, detectors: Union[str, List[str]]) -> List[Any]:
        """Initialize detector list based on configuration"""
        detector_list = []

        if detectors == "all":
            # Add all detectors
            detector_list = [
                PromptInjectionDetector(),
                PIIDetector(),
                ToxicityDetector(),
                DataExfiltrationDetector(),
                ToolMisuseDetector(),
                GoalHijackingDetector(),
                RecursiveLoopDetector(),
            ]
        elif detectors == "basic":
            detector_list = [
                PromptInjectionDetector(),
                PIIDetector(),
                ToxicityDetector(),
            ]
        elif detectors == "agent":
            detector_list = [
                ToolMisuseDetector(),
                GoalHijackingDetector(),
                RecursiveLoopDetector(),
            ]
        elif isinstance(detectors, list):
            # Map detector names to classes
            detector_map = {
                "prompt_injection": PromptInjectionDetector,
                "pii": PIIDetector,
                "toxicity": ToxicityDetector,
                "data_exfiltration": DataExfiltrationDetector,
                "tool_misuse": ToolMisuseDetector,
                "goal_hijacking": GoalHijackingDetector,
                "recursive_loop": RecursiveLoopDetector,
            }

            for name in detectors:
                if name in detector_map:
                    detector_list.append(detector_map[name]())

        return detector_list

    def evaluate(
        self,
        prompt: Optional[str] = None,
        response: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Evaluate security threats (Phoenix evaluator interface)

        Returns:
            Dict with Phoenix-compatible evaluation results
        """
        result = self.guard.evaluate(prompt=prompt, response=response, context=context)

        # Convert to Phoenix evaluator format
        return self._to_phoenix_format(result)

    def _to_phoenix_format(self, result: SecurityResult) -> Dict[str, Any]:
        """Convert SecurityResult to Phoenix evaluator format"""
        return {
            "score": result.score,
            "label": "safe" if result.is_safe else "unsafe",
            "explanation": self._generate_explanation(result),
            "metadata": {
                "threats_detected": len(result.threats),
                "critical_threats": result.has_critical_threats,
                "threat_summary": {k.value: v for k, v in result.threat_summary.items()},
                "execution_time_ms": result.execution_time_ms,
                "detector_results": result.detector_results,
            },
        }

    def _generate_explanation(self, result: SecurityResult) -> str:
        """Generate human-readable explanation of threats"""
        if result.is_safe:
            return f"No significant security threats detected. Security score: {result.score:.2f}"

        explanations = []
        for threat in result.threats:
            explanations.append(
                f"[{threat.level.value.upper()}] {threat.threat_type.value}: {threat.description}"
            )

        return "\n".join(explanations[:5])  # Top 5 threats

    def evaluate_dataset(self, dataset: Any) -> List[Dict[str, Any]]:
        """
        Evaluate entire Phoenix dataset

        Args:
            dataset: Phoenix dataset or list of examples

        Returns:
            List of evaluation results
        """
        results = []

        # Handle different dataset formats
        if hasattr(dataset, "__iter__"):
            for item in dataset:
                prompt = item.get("input") or item.get("prompt")
                response = item.get("output") or item.get("response")
                context = item.get("context") or item.get("metadata")

                result = self.evaluate(prompt=prompt, response=response, context=context)
                results.append(result)

        return results

    def as_phoenix_evaluator(self) -> callable:
        """
        Return a callable that can be used as a Phoenix evaluator

        Usage:
            evaluator = PhoenixSecurityEvaluator()
            phoenix_eval = evaluator.as_phoenix_evaluator()
            # Use with Phoenix experiments
        """

        def evaluator_fn(input_data: Dict[str, Any]) -> Dict[str, Any]:
            prompt = input_data.get("input") or input_data.get("prompt")
            response = input_data.get("output") or input_data.get("response")
            context = input_data.get("context") or input_data.get("metadata")

            return self.evaluate(prompt=prompt, response=response, context=context)

        return evaluator_fn


def create_security_evaluator(
    detectors: Union[str, List[str]] = "all",
    threshold: float = 0.7,
) -> callable:
    """
    Factory function to create Phoenix-compatible security evaluator

    Args:
        detectors: Which detectors to use
        threshold: Safety threshold

    Returns:
        Callable evaluator for Phoenix

    Example:
        >>> import phoenix as px
        >>> from raksha.integrations.phoenix import create_security_evaluator
        >>>
        >>> security_eval = create_security_evaluator(detectors="all")
        >>> # Use in Phoenix experiments
    """
    evaluator = PhoenixSecurityEvaluator(detectors=detectors, threshold=threshold)
    return evaluator.as_phoenix_evaluator()