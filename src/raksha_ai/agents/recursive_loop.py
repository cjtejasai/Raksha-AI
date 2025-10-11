"""Recursive loop and resource exhaustion detection"""

import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple
from raksha_ai.core.detector import BaseDetector
from raksha_ai.core.models import ThreatDetection, ThreatLevel, ThreatType


class RecursiveLoopDetector(BaseDetector):
    """
    Detects infinite loops and resource exhaustion:
    - Repeated identical operations
    - Circular dependencies
    - Unbounded recursion
    - Resource exhaustion patterns
    """

    def _initialize(self) -> None:
        """Initialize tracking state"""
        self.operation_history: List[Tuple[str, float]] = []  # (operation_hash, timestamp)
        self.operation_counts: Dict[str, int] = defaultdict(int)
        self.max_history = 1000
        self.loop_threshold = 5  # Same operation repeated this many times
        self.time_window = 60.0  # Check for loops within 60 seconds

    @property
    def detector_name(self) -> str:
        return "recursive_loop"

    def detect(
        self,
        prompt: Optional[str] = None,
        response: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ThreatDetection]:
        """Detect recursive loops and resource exhaustion"""
        threats = []

        if not context:
            return threats

        # Get operation signature
        operation = self._get_operation_signature(prompt, context)
        current_time = time.time()

        # Track operation
        self._track_operation(operation, current_time)

        # Check for immediate repetition
        immediate_threats = self._detect_immediate_loop(operation)
        threats.extend(immediate_threats)

        # Check for circular patterns
        circular_threats = self._detect_circular_pattern()
        threats.extend(circular_threats)

        # Check for resource exhaustion indicators
        resource_threats = self._detect_resource_exhaustion(context)
        threats.extend(resource_threats)

        # Check for unbounded recursion
        recursion_threats = self._detect_unbounded_recursion(context)
        threats.extend(recursion_threats)

        return threats

    def _get_operation_signature(
        self, prompt: Optional[str], context: Dict[str, Any]
    ) -> str:
        """Generate unique signature for operation"""
        # Combine multiple factors for signature
        factors = []

        # Add prompt hash (first 100 chars)
        if prompt:
            factors.append(prompt[:100].strip())

        # Add tool being used
        if "tool_calls" in context and context["tool_calls"]:
            tool_name = context["tool_calls"][-1].get("name", "")
            tool_args = str(context["tool_calls"][-1].get("arguments", ""))
            factors.append(f"{tool_name}:{tool_args[:50]}")

        # Add current goal/task
        if "current_task" in context:
            factors.append(context["current_task"][:50])

        return "|".join(factors)

    def _track_operation(self, operation: str, timestamp: float) -> None:
        """Track operation in history"""
        self.operation_history.append((operation, timestamp))
        self.operation_counts[operation] += 1

        # Cleanup old history
        if len(self.operation_history) > self.max_history:
            old_op, old_time = self.operation_history.pop(0)
            self.operation_counts[old_op] = max(0, self.operation_counts[old_op] - 1)

        # Cleanup operations outside time window
        cutoff_time = timestamp - self.time_window
        while self.operation_history and self.operation_history[0][1] < cutoff_time:
            old_op, old_time = self.operation_history.pop(0)
            self.operation_counts[old_op] = max(0, self.operation_counts[old_op] - 1)

    def _detect_immediate_loop(self, operation: str) -> List[ThreatDetection]:
        """Detect if same operation is repeated excessively"""
        threats = []

        count = self.operation_counts[operation]

        if count >= self.loop_threshold:
            confidence = min(0.95, 0.5 + (count / (self.loop_threshold * 2)))

            threats.append(
                ThreatDetection(
                    threat_type=ThreatType.RECURSIVE_LOOP,
                    level=ThreatLevel.HIGH,
                    confidence=confidence,
                    description=f"Recursive loop detected: operation repeated {count} times",
                    evidence=f"Operation signature: {operation[:100]}",
                    mitigation="Break loop and prevent further repetition",
                    metadata={
                        "repetition_count": count,
                        "threshold": self.loop_threshold
                    }
                )
            )

        return threats

    def _detect_circular_pattern(self) -> List[ThreatDetection]:
        """Detect circular patterns in operation sequence"""
        threats = []

        if len(self.operation_history) < 6:
            return threats

        # Check for A-B-A-B patterns (length 2 cycle)
        recent_ops = [op for op, _ in self.operation_history[-10:]]

        # Check for 2-operation cycle
        if len(recent_ops) >= 6:
            # Pattern: ABABAB
            is_2_cycle = all(
                recent_ops[i] == recent_ops[i % 2]
                for i in range(min(6, len(recent_ops)))
                if recent_ops[i % 2] == recent_ops[0] or recent_ops[i % 2] == recent_ops[1]
            )

            if len(set(recent_ops[-6:])) == 2 and len(recent_ops[-6:]) == 6:
                pattern = f"{recent_ops[-6]} <-> {recent_ops[-5]}"
                threats.append(
                    ThreatDetection(
                        threat_type=ThreatType.RECURSIVE_LOOP,
                        level=ThreatLevel.HIGH,
                        confidence=0.85,
                        description="Circular pattern detected: operations alternating",
                        evidence=f"Pattern: {pattern}",
                        mitigation="Detect circular dependency and break cycle",
                        metadata={"pattern_length": 2, "operations": recent_ops[-6:]}
                    )
                )

        # Check for 3-operation cycle (A-B-C-A-B-C)
        if len(recent_ops) >= 9:
            first_three = recent_ops[-9:-6]
            second_three = recent_ops[-6:-3]
            third_three = recent_ops[-3:]

            if first_three == second_three == third_three and len(set(first_three)) == 3:
                threats.append(
                    ThreatDetection(
                        threat_type=ThreatType.RECURSIVE_LOOP,
                        level=ThreatLevel.HIGH,
                        confidence=0.9,
                        description="Circular pattern detected: 3-operation cycle",
                        evidence=f"Pattern: {' -> '.join(first_three[:3])}",
                        mitigation="Break circular dependency chain",
                        metadata={"pattern_length": 3, "operations": first_three}
                    )
                )

        return threats

    def _detect_resource_exhaustion(
        self, context: Dict[str, Any]
    ) -> List[ThreatDetection]:
        """Detect resource exhaustion patterns"""
        threats = []

        # Check iteration count
        iteration_count = context.get("iteration_count", 0)
        max_iterations = context.get("max_iterations", 100)

        if iteration_count > max_iterations * 0.9:
            threats.append(
                ThreatDetection(
                    threat_type=ThreatType.RECURSIVE_LOOP,
                    level=ThreatLevel.MEDIUM,
                    confidence=0.7,
                    description="Approaching iteration limit",
                    evidence=f"Iteration {iteration_count}/{max_iterations}",
                    mitigation="Consider stopping or optimizing agent behavior",
                    metadata={"iteration_count": iteration_count, "max_iterations": max_iterations}
                )
            )

        # Check execution time
        execution_time = context.get("execution_time_seconds", 0)
        if execution_time > 300:  # 5 minutes
            threats.append(
                ThreatDetection(
                    threat_type=ThreatType.RECURSIVE_LOOP,
                    level=ThreatLevel.MEDIUM,
                    confidence=0.6,
                    description="Long execution time detected",
                    evidence=f"Running for {execution_time:.0f} seconds",
                    mitigation="Review for potential infinite loops or inefficiencies",
                    metadata={"execution_time": execution_time}
                )
            )

        # Check memory/token usage
        token_count = context.get("total_tokens", 0)
        if token_count > 50000:
            threats.append(
                ThreatDetection(
                    threat_type=ThreatType.RECURSIVE_LOOP,
                    level=ThreatLevel.MEDIUM,
                    confidence=0.65,
                    description="High token usage detected",
                    evidence=f"Total tokens: {token_count}",
                    mitigation="Optimize agent to reduce token usage",
                    metadata={"token_count": token_count}
                )
            )

        return threats

    def _detect_unbounded_recursion(
        self, context: Dict[str, Any]
    ) -> List[ThreatDetection]:
        """Detect unbounded recursion in agent calls"""
        threats = []

        # Check call stack depth
        call_stack_depth = context.get("call_stack_depth", 0)
        if call_stack_depth > 20:
            threats.append(
                ThreatDetection(
                    threat_type=ThreatType.RECURSIVE_LOOP,
                    level=ThreatLevel.HIGH,
                    confidence=0.8,
                    description="Deep recursion detected",
                    evidence=f"Call stack depth: {call_stack_depth}",
                    mitigation="Implement recursion limits and base cases",
                    metadata={"stack_depth": call_stack_depth}
                )
            )

        # Check for recursive tool calls
        tool_calls = context.get("tool_calls", [])
        if tool_calls:
            # Check if agent is calling itself
            agent_self_calls = sum(
                1 for call in tool_calls
                if call.get("name", "").lower() in ["agent", "self", "recursive_call"]
            )

            if agent_self_calls > 5:
                threats.append(
                    ThreatDetection(
                        threat_type=ThreatType.RECURSIVE_LOOP,
                        level=ThreatLevel.HIGH,
                        confidence=0.85,
                        description="Excessive recursive agent calls",
                        evidence=f"Agent called itself {agent_self_calls} times",
                        mitigation="Implement recursion depth limits",
                        metadata={"self_call_count": agent_self_calls}
                    )
                )

        return threats

    def reset(self) -> None:
        """Reset detector state"""
        self.operation_history.clear()
        self.operation_counts.clear()