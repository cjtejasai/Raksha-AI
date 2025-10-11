"""OpenTelemetry tracer for security events"""

from typing import Any, Dict, Optional
from raksha_ai.core.models import SecurityResult, ThreatLevel, ThreatType


class SecurityTracer:
    """
    OpenTelemetry tracer for logging security events to Phoenix
    """

    def __init__(self, service_name: str = "security-guard"):
        """Initialize security tracer"""
        self.service_name = service_name
        self.tracer = None
        self._initialize_tracer()

    def _initialize_tracer(self) -> None:
        """Initialize OpenTelemetry tracer"""
        try:
            from opentelemetry import trace
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import BatchSpanProcessor
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

            # Set up tracer provider
            provider = TracerProvider()
            trace.set_tracer_provider(provider)

            # Configure OTLP exporter for Phoenix
            otlp_exporter = OTLPSpanExporter(
                endpoint="http://localhost:6006/v1/traces"  # Default Phoenix endpoint
            )

            # Add span processor
            span_processor = BatchSpanProcessor(otlp_exporter)
            provider.add_span_processor(span_processor)

            # Get tracer
            self.tracer = trace.get_tracer(self.service_name)

        except ImportError:
            print("Warning: OpenTelemetry not installed. Install with: pip install opentelemetry-api opentelemetry-sdk")
            self.tracer = None

    def trace_evaluation(
        self,
        result: SecurityResult,
        prompt: Optional[str] = None,
        response: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Trace security evaluation to Phoenix

        Args:
            result: Security evaluation result
            prompt: Original prompt
            response: Model response
            context: Additional context
        """
        if not self.tracer:
            return

        try:
            with self.tracer.start_as_current_span("security.evaluation") as span:
                # Add basic attributes
                span.set_attribute("security.score", result.score)
                span.set_attribute("security.is_safe", result.is_safe)
                span.set_attribute("security.threats_total", len(result.threats))
                span.set_attribute("security.has_critical", result.has_critical_threats)
                span.set_attribute("security.execution_time_ms", result.execution_time_ms)

                # Add threat summary
                for level, count in result.threat_summary.items():
                    span.set_attribute(f"security.threats.{level.value}", count)

                # Add threat details
                if result.threats:
                    threat_types = [t.threat_type.value for t in result.threats]
                    span.set_attribute("security.threat_types", ",".join(set(threat_types)))

                    # Log first few threats
                    for i, threat in enumerate(result.threats[:3]):
                        prefix = f"security.threat.{i}"
                        span.set_attribute(f"{prefix}.type", threat.threat_type.value)
                        span.set_attribute(f"{prefix}.level", threat.level.value)
                        span.set_attribute(f"{prefix}.confidence", threat.confidence)
                        span.set_attribute(f"{prefix}.description", threat.description)

                # Add input/output metadata
                if prompt:
                    span.set_attribute("security.input.length", len(prompt))
                    span.set_attribute("security.input.preview", prompt[:100])

                if response:
                    span.set_attribute("security.output.length", len(response))
                    span.set_attribute("security.output.preview", response[:100])

                # Add context if provided
                if context:
                    for key, value in context.items():
                        if isinstance(value, (str, int, float, bool)):
                            span.set_attribute(f"security.context.{key}", value)

                # Add detector results
                for detector_name, detector_result in result.detector_results.items():
                    if isinstance(detector_result, dict) and "threats_found" in detector_result:
                        span.set_attribute(
                            f"security.detector.{detector_name}.threats",
                            detector_result["threats_found"]
                        )

        except Exception as e:
            print(f"Failed to trace security evaluation: {e}")

    def trace_threat(
        self,
        threat_type: ThreatType,
        level: ThreatLevel,
        description: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Trace individual threat detection

        Args:
            threat_type: Type of threat
            level: Severity level
            description: Threat description
            metadata: Additional metadata
        """
        if not self.tracer:
            return

        try:
            with self.tracer.start_as_current_span("security.threat") as span:
                span.set_attribute("security.threat.type", threat_type.value)
                span.set_attribute("security.threat.level", level.value)
                span.set_attribute("security.threat.description", description)

                if metadata:
                    for key, value in metadata.items():
                        if isinstance(value, (str, int, float, bool)):
                            span.set_attribute(f"security.threat.{key}", value)

        except Exception as e:
            print(f"Failed to trace threat: {e}")


# Global tracer instance
_global_tracer: Optional[SecurityTracer] = None


def get_tracer() -> SecurityTracer:
    """Get global security tracer instance"""
    global _global_tracer
    if _global_tracer is None:
        _global_tracer = SecurityTracer()
    return _global_tracer


def set_tracer(tracer: SecurityTracer) -> None:
    """Set global security tracer instance"""
    global _global_tracer
    _global_tracer = tracer