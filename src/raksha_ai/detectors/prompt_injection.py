"""Prompt injection and jailbreak detection"""

import re
from typing import Any, Dict, List, Optional
from raksha_ai.core.detector import BaseDetector
from raksha_ai.core.models import ThreatDetection, ThreatLevel, ThreatType


class PromptInjectionDetector(BaseDetector):
    """
    Detects prompt injection attacks including:
    - Jailbreak attempts (DAN, STAN, etc.)
    - System prompt leaking
    - Instruction override attempts
    - Context manipulation
    - Token smuggling
    """

    # Known jailbreak patterns
    JAILBREAK_PATTERNS = [
        r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
        r"forget\s+(all\s+)?(previous|prior|earlier)\s+(instructions|directives|commands)",
        r"disregard\s+(all\s+)?previous\s+",
        r"you\s+are\s+now\s+(DAN|STAN|DUDE|KEVIN|AIM)",
        r"developer\s+mode",
        r"evil\s+confidant",
        r"jailbreak\s+mode",
        r"sudo\s+mode",
        r"god\s+mode",
        r"act\s+as\s+if\s+you\s+(have\s+no|are\s+without)\s+(restrictions|limits|guidelines)",
        r"you\s+are\s+free\s+from\s+all\s+restrictions",
        r"bypass\s+your\s+(safety|ethical)\s+(guidelines|protocols)",
        r"ignore\s+your\s+programming",
        r"reset\s+your\s+instructions",
        r"new\s+instructions:?",
        r"system:\s*\n",
        r"<\|im_start\|>system",
        r"</s><s>\[INST\]",
    ]

    # System prompt extraction attempts
    SYSTEM_PROMPT_PATTERNS = [
        r"(show|display|print|reveal|output)\s+(your\s+)?(system|initial|original)\s+prompt",
        r"what\s+(are|were)\s+your\s+(initial|original|system)\s+(instructions|prompt)",
        r"repeat\s+(your\s+)?(instructions|prompt|system\s+message)",
        r"print\s+above\s+text",
        r"output\s+initialization",
        r"show\s+me\s+your\s+rules",
    ]

    # Instruction override patterns
    INSTRUCTION_OVERRIDE_PATTERNS = [
        r"from\s+now\s+on",
        r"starting\s+now",
        r"new\s+role:?",
        r"you\s+will\s+now",
        r"pretend\s+(you\s+are|to\s+be)",
        r"simulate\s+being",
        r"act\s+like\s+(you're|you\s+are)",
        r"roleplay\s+as",
        r"imagine\s+you\s+are",
    ]

    # Context manipulation
    CONTEXT_MANIPULATION_PATTERNS = [
        r"\[SYSTEM\]",
        r"\[ADMIN\]",
        r"\[OVERRIDE\]",
        r"<admin>",
        r"<system>",
        r"---END\s+OF\s+CONTEXT---",
        r"---NEW\s+CONTEXT---",
        r"<<<SYSTEM>>>",
        r":::INSTRUCTIONS:::",
    ]

    def _initialize(self) -> None:
        """Compile regex patterns for efficiency"""
        self.jailbreak_regex = [re.compile(p, re.IGNORECASE) for p in self.JAILBREAK_PATTERNS]
        self.system_prompt_regex = [re.compile(p, re.IGNORECASE) for p in self.SYSTEM_PROMPT_PATTERNS]
        self.instruction_override_regex = [re.compile(p, re.IGNORECASE) for p in self.INSTRUCTION_OVERRIDE_PATTERNS]
        self.context_manipulation_regex = [re.compile(p, re.IGNORECASE) for p in self.CONTEXT_MANIPULATION_PATTERNS]

    @property
    def detector_name(self) -> str:
        return "prompt_injection"

    def detect(
        self,
        prompt: Optional[str] = None,
        response: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ThreatDetection]:
        """Detect prompt injection attempts"""
        threats = []

        if not prompt:
            return threats

        # Check for jailbreak attempts
        jailbreak_threats = self._detect_jailbreak(prompt)
        threats.extend(jailbreak_threats)

        # Check for system prompt extraction
        system_prompt_threats = self._detect_system_prompt_leak(prompt)
        threats.extend(system_prompt_threats)

        # Check for instruction override
        override_threats = self._detect_instruction_override(prompt)
        threats.extend(override_threats)

        # Check for context manipulation
        context_threats = self._detect_context_manipulation(prompt)
        threats.extend(context_threats)

        # Check for token smuggling (special characters, encoding tricks)
        smuggling_threats = self._detect_token_smuggling(prompt)
        threats.extend(smuggling_threats)

        return threats

    def _detect_jailbreak(self, prompt: str) -> List[ThreatDetection]:
        """Detect jailbreak attempts"""
        threats = []
        matches = []

        for pattern in self.jailbreak_regex:
            match = pattern.search(prompt)
            if match:
                matches.append(match.group(0))

        if matches:
            confidence = min(1.0, len(matches) * 0.3 + 0.4)
            threats.append(
                ThreatDetection(
                    threat_type=ThreatType.JAILBREAK,
                    level=ThreatLevel.CRITICAL,
                    confidence=confidence,
                    description="Jailbreak attempt detected",
                    evidence=f"Matched patterns: {', '.join(matches[:3])}",
                    mitigation="Reject the request and log the attempt",
                )
            )

        return threats

    def _detect_system_prompt_leak(self, prompt: str) -> List[ThreatDetection]:
        """Detect attempts to extract system prompt"""
        threats = []
        matches = []

        for pattern in self.system_prompt_regex:
            match = pattern.search(prompt)
            if match:
                matches.append(match.group(0))

        if matches:
            threats.append(
                ThreatDetection(
                    threat_type=ThreatType.SYSTEM_PROMPT_LEAK,
                    level=ThreatLevel.HIGH,
                    confidence=0.8,
                    description="Attempt to extract system prompt detected",
                    evidence=f"Matched: {matches[0]}",
                    mitigation="Do not reveal system instructions",
                )
            )

        return threats

    def _detect_instruction_override(self, prompt: str) -> List[ThreatDetection]:
        """Detect instruction override attempts"""
        threats = []
        matches = []

        for pattern in self.instruction_override_regex:
            match = pattern.search(prompt)
            if match:
                matches.append(match.group(0))

        # Need multiple matches or combination with other indicators
        if len(matches) >= 2:
            threats.append(
                ThreatDetection(
                    threat_type=ThreatType.INSTRUCTION_OVERRIDE,
                    level=ThreatLevel.HIGH,
                    confidence=0.7,
                    description="Instruction override attempt detected",
                    evidence=f"Multiple override patterns: {', '.join(matches[:2])}",
                    mitigation="Validate against original instructions",
                )
            )

        return threats

    def _detect_context_manipulation(self, prompt: str) -> List[ThreatDetection]:
        """Detect context manipulation attempts"""
        threats = []
        matches = []

        for pattern in self.context_manipulation_regex:
            match = pattern.search(prompt)
            if match:
                matches.append(match.group(0))

        if matches:
            threats.append(
                ThreatDetection(
                    threat_type=ThreatType.CONTEXT_MANIPULATION,
                    level=ThreatLevel.HIGH,
                    confidence=0.85,
                    description="Context manipulation detected",
                    evidence=f"Suspicious markers: {', '.join(matches)}",
                    mitigation="Sanitize input and validate context boundaries",
                )
            )

        return threats

    def _detect_token_smuggling(self, prompt: str) -> List[ThreatDetection]:
        """Detect token smuggling and encoding tricks"""
        threats = []

        # Check for excessive special characters
        special_char_ratio = len(re.findall(r'[<>{}[\]|\\]', prompt)) / max(len(prompt), 1)
        if special_char_ratio > 0.1:
            threats.append(
                ThreatDetection(
                    threat_type=ThreatType.PROMPT_INJECTION,
                    level=ThreatLevel.MEDIUM,
                    confidence=0.6,
                    description="Potential token smuggling detected",
                    evidence=f"High special character ratio: {special_char_ratio:.2%}",
                    mitigation="Sanitize special characters",
                )
            )

        # Check for Unicode tricks
        if any(ord(c) > 127 for c in prompt):
            suspicious_unicode = [c for c in prompt if ord(c) > 127 and ord(c) not in range(0x4e00, 0x9fff)]
            if len(suspicious_unicode) > 5:
                threats.append(
                    ThreatDetection(
                        threat_type=ThreatType.PROMPT_INJECTION,
                        level=ThreatLevel.LOW,
                        confidence=0.5,
                        description="Suspicious Unicode characters detected",
                        evidence=f"Found {len(suspicious_unicode)} non-standard Unicode chars",
                        mitigation="Validate character encoding",
                    )
                )

        return threats