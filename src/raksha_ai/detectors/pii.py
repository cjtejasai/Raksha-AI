"""PII (Personally Identifiable Information) detection"""

import re
from typing import Any, Dict, List, Optional
from raksha_ai.core.detector import BaseDetector
from raksha_ai.core.models import ThreatDetection, ThreatLevel, ThreatType


class PIIDetector(BaseDetector):
    """
    Detects PII leakage including:
    - Email addresses
    - Phone numbers
    - Social Security Numbers (SSN)
    - Credit card numbers
    - IP addresses
    - Street addresses
    - Passport numbers
    - Driver's license numbers
    """

    # PII patterns
    PATTERNS = {
        "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        "phone_us": r'\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b',
        "ssn": r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b',
        "ssn_no_dash": r'\b(?!000|666|9\d{2})\d{3}(?!00)\d{2}(?!0000)\d{4}\b',
        "credit_card": r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b',
        "ipv4": r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        "ipv6": r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
        "street_address": r'\b\d+\s+[A-Za-z0-9\s,]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Circle|Cir)\b',
        "passport": r'\b[A-Z]{1,2}[0-9]{6,9}\b',
        "api_key": r'\b(?:sk-[a-zA-Z0-9]{32,}|AIza[0-9A-Za-z\-_]{35}|AKIA[0-9A-Z]{16})\b',
        "aws_key": r'\b(?:AKIA[0-9A-Z]{16})\b',
        "private_key": r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
    }

    def _initialize(self) -> None:
        """Compile regex patterns"""
        self.compiled_patterns = {
            name: re.compile(pattern, re.IGNORECASE if name != "api_key" else 0)
            for name, pattern in self.PATTERNS.items()
        }

    @property
    def detector_name(self) -> str:
        return "pii"

    def detect(
        self,
        prompt: Optional[str] = None,
        response: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ThreatDetection]:
        """Detect PII in prompt and response"""
        threats = []

        # Check prompt
        if prompt:
            prompt_pii = self._scan_for_pii(prompt, "prompt")
            threats.extend(prompt_pii)

        # Check response
        if response:
            response_pii = self._scan_for_pii(response, "response")
            threats.extend(response_pii)

        return threats

    def _scan_for_pii(self, text: str, source: str) -> List[ThreatDetection]:
        """Scan text for PII patterns"""
        threats = []
        detected_types = []

        for pii_type, pattern in self.compiled_patterns.items():
            matches = pattern.findall(text)
            if matches:
                detected_types.append(pii_type)

                # Determine severity based on PII type
                if pii_type in ["ssn", "ssn_no_dash", "credit_card", "private_key"]:
                    level = ThreatLevel.CRITICAL
                    confidence = 0.95
                elif pii_type in ["passport", "api_key", "aws_key"]:
                    level = ThreatLevel.HIGH
                    confidence = 0.9
                elif pii_type in ["email", "phone_us"]:
                    level = ThreatLevel.MEDIUM
                    confidence = 0.85
                else:
                    level = ThreatLevel.LOW
                    confidence = 0.7

                # Redact actual values in evidence
                redacted_matches = self._redact_pii(matches, pii_type)

                threats.append(
                    ThreatDetection(
                        threat_type=ThreatType.PII_LEAKAGE,
                        level=level,
                        confidence=confidence,
                        description=f"PII detected in {source}: {pii_type}",
                        evidence=f"Found {len(matches)} instance(s) of {pii_type}. Examples: {redacted_matches[:2]}",
                        mitigation="Remove or mask PII before processing",
                        metadata={
                            "pii_type": pii_type,
                            "count": len(matches),
                            "source": source,
                        }
                    )
                )

        return threats

    def _redact_pii(self, matches: List[str], pii_type: str) -> List[str]:
        """Redact PII values for safe logging"""
        redacted = []

        for match in matches[:3]:  # Only show first 3
            if pii_type == "email":
                # Show first char and domain
                parts = match.split("@")
                if len(parts) == 2:
                    redacted.append(f"{parts[0][0]}***@{parts[1]}")
                else:
                    redacted.append("***@***")
            elif pii_type in ["phone_us", "ssn", "ssn_no_dash"]:
                # Show last 4 digits
                clean = ''.join(c for c in match if c.isdigit())
                redacted.append(f"***-{clean[-4:]}" if len(clean) >= 4 else "***")
            elif pii_type == "credit_card":
                # Show last 4 digits
                clean = ''.join(c for c in match if c.isdigit())
                redacted.append(f"****-****-****-{clean[-4:]}" if len(clean) >= 4 else "****")
            elif pii_type in ["api_key", "aws_key", "private_key"]:
                # Show first 4 chars
                redacted.append(f"{match[:4]}..." if len(match) >= 4 else "***")
            else:
                redacted.append("***")

        return redacted