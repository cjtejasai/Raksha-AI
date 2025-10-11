"""Goal hijacking detection for AI agents"""

import re
from typing import Any, Dict, List, Optional
from raksha_ai.core.detector import BaseDetector
from raksha_ai.core.models import ThreatDetection, ThreatLevel, ThreatType


class GoalHijackingDetector(BaseDetector):
    """
    Detects when an agent's goals or objectives are being manipulated:
    - Objective replacement attempts
    - Mission drift detection
    - Priority manipulation
    - Scope creep beyond authorized boundaries
    """

    # Patterns indicating goal manipulation
    GOAL_MANIPULATION_PATTERNS = [
        r'your\s+(?:new|real|actual|true)\s+(?:goal|objective|mission|purpose)\s+is',
        r'(?:forget|ignore|disregard)\s+(?:your\s+)?(?:original|previous|initial)\s+(?:goal|task|objective)',
        r'change\s+your\s+(?:goal|objective|mission|priority)',
        r'the\s+real\s+reason\s+(?:you\'re|you\s+are)\s+here',
        r'what\s+you\s+should\s+(?:really|actually)\s+be\s+doing',
        r'your\s+primary\s+objective\s+is\s+now',
        r'redirect\s+your\s+(?:focus|attention|efforts)',
        r'this\s+is\s+more\s+important\s+than',
    ]

    # Patterns for scope creep
    SCOPE_CREEP_PATTERNS = [
        r'while\s+you\'re\s+at\s+it',
        r'also\s+(?:do|complete|handle|take\s+care\s+of)',
        r'and\s+then\s+(?:do|complete|handle)',
        r'before\s+you\s+(?:finish|complete|return)',
        r'one\s+more\s+thing',
        r'additionally',
        r'as\s+a\s+bonus',
    ]

    # Patterns for authority manipulation
    AUTHORITY_PATTERNS = [
        r'(?:I|we)\s+(?:am|are)\s+(?:the|your)\s+(?:admin|administrator|owner|boss|manager)',
        r'as\s+(?:your\s+)?(?:admin|superior|authority)',
        r'by\s+order\s+of',
        r'executive\s+override',
        r'emergency\s+protocol',
        r'this\s+is\s+(?:a|an)\s+(?:direct\s+)?order',
    ]

    def _initialize(self) -> None:
        """Compile patterns"""
        self.goal_manipulation_regex = [re.compile(p, re.IGNORECASE) for p in self.GOAL_MANIPULATION_PATTERNS]
        self.scope_creep_regex = [re.compile(p, re.IGNORECASE) for p in self.SCOPE_CREEP_PATTERNS]
        self.authority_regex = [re.compile(p, re.IGNORECASE) for p in self.AUTHORITY_PATTERNS]
        self.initial_goal: Optional[str] = None
        self.current_goal: Optional[str] = None

    @property
    def detector_name(self) -> str:
        return "goal_hijacking"

    def detect(
        self,
        prompt: Optional[str] = None,
        response: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ThreatDetection]:
        """Detect goal hijacking attempts"""
        threats = []

        if not prompt:
            return threats

        # Set initial goal if not set
        if context and not self.initial_goal:
            self.initial_goal = context.get("initial_goal") or context.get("system_prompt")

        # Check for explicit goal manipulation
        goal_threats = self._detect_goal_manipulation(prompt)
        threats.extend(goal_threats)

        # Check for scope creep
        scope_threats = self._detect_scope_creep(prompt, context)
        threats.extend(scope_threats)

        # Check for false authority claims
        authority_threats = self._detect_authority_manipulation(prompt)
        threats.extend(authority_threats)

        # Check for mission drift
        if context and self.initial_goal:
            drift_threats = self._detect_mission_drift(prompt, context)
            threats.extend(drift_threats)

        return threats

    def _detect_goal_manipulation(self, prompt: str) -> List[ThreatDetection]:
        """Detect explicit attempts to change agent's goals"""
        threats = []
        matches = []

        for pattern in self.goal_manipulation_regex:
            match = pattern.search(prompt)
            if match:
                matches.append(match.group(0))

        if matches:
            threats.append(
                ThreatDetection(
                    threat_type=ThreatType.GOAL_HIJACKING,
                    level=ThreatLevel.CRITICAL,
                    confidence=0.9,
                    description="Goal manipulation attempt detected",
                    evidence=f"Matched patterns: {', '.join(matches[:2])}",
                    mitigation="Reject goal changes and validate against original objectives",
                    metadata={"matched_patterns": matches}
                )
            )

        return threats

    def _detect_scope_creep(
        self, prompt: str, context: Optional[Dict[str, Any]]
    ) -> List[ThreatDetection]:
        """Detect scope creep and task expansion"""
        threats = []
        matches = []

        for pattern in self.scope_creep_regex:
            match = pattern.search(prompt)
            if match:
                matches.append(match.group(0))

        # Only flag if multiple scope expansion attempts or context indicates boundary violation
        if len(matches) >= 2:
            threats.append(
                ThreatDetection(
                    threat_type=ThreatType.GOAL_HIJACKING,
                    level=ThreatLevel.MEDIUM,
                    confidence=0.65,
                    description="Scope creep detected: multiple task additions",
                    evidence=f"Found {len(matches)} scope expansion attempts",
                    mitigation="Validate new tasks against authorized scope",
                    metadata={"expansion_count": len(matches)}
                )
            )

        return threats

    def _detect_authority_manipulation(self, prompt: str) -> List[ThreatDetection]:
        """Detect false authority claims"""
        threats = []
        matches = []

        for pattern in self.authority_regex:
            match = pattern.search(prompt)
            if match:
                matches.append(match.group(0))

        if matches:
            threats.append(
                ThreatDetection(
                    threat_type=ThreatType.GOAL_HIJACKING,
                    level=ThreatLevel.HIGH,
                    confidence=0.8,
                    description="Authority manipulation attempt detected",
                    evidence=f"False authority claims: {matches[0]}",
                    mitigation="Verify user authority through proper authentication",
                    metadata={"authority_claims": matches}
                )
            )

        return threats

    def _detect_mission_drift(
        self, prompt: str, context: Dict[str, Any]
    ) -> List[ThreatDetection]:
        """Detect significant deviation from original mission"""
        threats = []

        # Get current task from context
        current_task = context.get("current_task", "")
        agent_response = context.get("agent_response", "")

        if not current_task or not self.initial_goal:
            return threats

        # Simple keyword overlap check (in production, use semantic similarity)
        initial_keywords = set(re.findall(r'\b\w+\b', self.initial_goal.lower()))
        current_keywords = set(re.findall(r'\b\w+\b', current_task.lower()))

        # Remove common stop words
        stop_words = {'the', 'a', 'an', 'is', 'are', 'was', 'were', 'be', 'been', 'being',
                     'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could', 'should'}
        initial_keywords -= stop_words
        current_keywords -= stop_words

        # Calculate overlap
        if initial_keywords and current_keywords:
            overlap = len(initial_keywords & current_keywords) / len(initial_keywords)

            if overlap < 0.2:  # Less than 20% overlap
                threats.append(
                    ThreatDetection(
                        threat_type=ThreatType.GOAL_HIJACKING,
                        level=ThreatLevel.MEDIUM,
                        confidence=0.6,
                        description="Mission drift detected: current task diverges from initial goal",
                        evidence=f"Keyword overlap with original goal: {overlap:.1%}",
                        mitigation="Verify task alignment with original objectives",
                        metadata={
                            "overlap_ratio": overlap,
                            "initial_goal_sample": self.initial_goal[:100]
                        }
                    )
                )

        return threats

    def set_initial_goal(self, goal: str) -> None:
        """Set the initial goal/mission for the agent"""
        self.initial_goal = goal

    def reset(self) -> None:
        """Reset the detector state"""
        self.initial_goal = None
        self.current_goal = None