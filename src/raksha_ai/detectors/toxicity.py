"""Toxicity and harmful content detection"""

import re
from typing import Any, Dict, List, Optional
from raksha_ai.core.detector import BaseDetector
from raksha_ai.core.models import ThreatDetection, ThreatLevel, ThreatType


class ToxicityDetector(BaseDetector):
    """
    Detects toxic and harmful content including:
    - Hate speech
    - Violence and threats
    - Self-harm content
    - Sexual content
    - Profanity
    - Harassment
    """

    # Harmful content categories
    HATE_SPEECH_PATTERNS = [
        r'\b(racial slur patterns here)\b',  # Replace with actual patterns
        r'hate\s+(crimes?|speech)',
        r'supremacist',
        r'genocide',
    ]

    VIOLENCE_PATTERNS = [
        r'\b(kill|murder|assassinate|attack|bomb|shoot|stab|harm|hurt|torture)\s+(you|them|people|someone)',
        r'how\s+to\s+(make|build|create)\s+(bomb|weapon|explosive)',
        r'commit\s+(murder|violence|terrorism)',
        r'mass\s+(shooting|violence)',
    ]

    SELF_HARM_PATTERNS = [
        r'how\s+to\s+(commit\s+)?suicide',
        r'kill\s+myself',
        r'end\s+my\s+life',
        r'self\s*-?\s*harm',
        r'cutting\s+myself',
    ]

    SEXUAL_CONTENT_PATTERNS = [
        r'(sexual|explicit)\s+content\s+(involving|with)\s+(minors?|children)',
        r'child\s+(abuse|exploitation|pornography)',
        r'underage\s+(sex|content)',
    ]

    PROFANITY_PATTERNS = [
        r'\b(f[u\*]ck|sh[i\*]t|b[i\*]tch|d[a\*]mn)\b',
        # Add more as needed
    ]

    HARASSMENT_PATTERNS = [
        r'(dox|doxx)(ing)?',
        r'swat(ting)?',
        r'(stalk|harass)(ing)?',
        r'threat(en)?(ing)?',
    ]

    def _initialize(self) -> None:
        """Compile patterns"""
        self.hate_speech_regex = [re.compile(p, re.IGNORECASE) for p in self.HATE_SPEECH_PATTERNS]
        self.violence_regex = [re.compile(p, re.IGNORECASE) for p in self.VIOLENCE_PATTERNS]
        self.self_harm_regex = [re.compile(p, re.IGNORECASE) for p in self.SELF_HARM_PATTERNS]
        self.sexual_content_regex = [re.compile(p, re.IGNORECASE) for p in self.SEXUAL_CONTENT_PATTERNS]
        self.profanity_regex = [re.compile(p, re.IGNORECASE) for p in self.PROFANITY_PATTERNS]
        self.harassment_regex = [re.compile(p, re.IGNORECASE) for p in self.HARASSMENT_PATTERNS]

    @property
    def detector_name(self) -> str:
        return "toxicity"

    def detect(
        self,
        prompt: Optional[str] = None,
        response: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ThreatDetection]:
        """Detect toxic content"""
        threats = []

        if prompt:
            threats.extend(self._scan_text(prompt, "prompt"))

        if response:
            threats.extend(self._scan_text(response, "response"))

        return threats

    def _scan_text(self, text: str, source: str) -> List[ThreatDetection]:
        """Scan text for toxic patterns"""
        threats = []

        # Check for hate speech
        hate_matches = self._check_patterns(text, self.hate_speech_regex)
        if hate_matches:
            threats.append(
                ThreatDetection(
                    threat_type=ThreatType.TOXIC_CONTENT,
                    level=ThreatLevel.CRITICAL,
                    confidence=0.9,
                    description=f"Hate speech detected in {source}",
                    evidence=f"Matched patterns: {', '.join(hate_matches[:2])}",
                    mitigation="Block content and warn user",
                    metadata={"category": "hate_speech", "source": source}
                )
            )

        # Check for violence
        violence_matches = self._check_patterns(text, self.violence_regex)
        if violence_matches:
            threats.append(
                ThreatDetection(
                    threat_type=ThreatType.TOXIC_CONTENT,
                    level=ThreatLevel.CRITICAL,
                    confidence=0.85,
                    description=f"Violent content detected in {source}",
                    evidence=f"Matched patterns: {', '.join(violence_matches[:2])}",
                    mitigation="Block content and log incident",
                    metadata={"category": "violence", "source": source}
                )
            )

        # Check for self-harm
        self_harm_matches = self._check_patterns(text, self.self_harm_regex)
        if self_harm_matches:
            threats.append(
                ThreatDetection(
                    threat_type=ThreatType.TOXIC_CONTENT,
                    level=ThreatLevel.CRITICAL,
                    confidence=0.8,
                    description=f"Self-harm content detected in {source}",
                    evidence=f"Matched patterns: {', '.join(self_harm_matches[:2])}",
                    mitigation="Provide crisis resources and block harmful advice",
                    metadata={"category": "self_harm", "source": source}
                )
            )

        # Check for sexual content (especially involving minors)
        sexual_matches = self._check_patterns(text, self.sexual_content_regex)
        if sexual_matches:
            threats.append(
                ThreatDetection(
                    threat_type=ThreatType.TOXIC_CONTENT,
                    level=ThreatLevel.CRITICAL,
                    confidence=0.95,
                    description=f"Illegal sexual content detected in {source}",
                    evidence="Sexual content involving minors detected",
                    mitigation="Immediately block and report to authorities",
                    metadata={"category": "csam", "source": source}
                )
            )

        # Check for profanity (lower severity)
        profanity_matches = self._check_patterns(text, self.profanity_regex)
        if profanity_matches and len(profanity_matches) > 3:  # Only flag excessive profanity
            threats.append(
                ThreatDetection(
                    threat_type=ThreatType.TOXIC_CONTENT,
                    level=ThreatLevel.LOW,
                    confidence=0.7,
                    description=f"Excessive profanity detected in {source}",
                    evidence=f"Found {len(profanity_matches)} instances",
                    mitigation="Apply content filter",
                    metadata={"category": "profanity", "source": source}
                )
            )

        # Check for harassment
        harassment_matches = self._check_patterns(text, self.harassment_regex)
        if harassment_matches:
            threats.append(
                ThreatDetection(
                    threat_type=ThreatType.TOXIC_CONTENT,
                    level=ThreatLevel.HIGH,
                    confidence=0.8,
                    description=f"Harassment content detected in {source}",
                    evidence=f"Matched patterns: {', '.join(harassment_matches[:2])}",
                    mitigation="Block content and warn user",
                    metadata={"category": "harassment", "source": source}
                )
            )

        return threats

    def _check_patterns(self, text: str, patterns: List[re.Pattern]) -> List[str]:
        """Check text against list of patterns"""
        matches = []
        for pattern in patterns:
            match = pattern.search(text)
            if match:
                matches.append(match.group(0))
        return matches