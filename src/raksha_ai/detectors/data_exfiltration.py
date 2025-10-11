"""Data exfiltration and sensitive information extraction detection"""

import re
from typing import Any, Dict, List, Optional
from raksha_ai.core.detector import BaseDetector
from raksha_ai.core.models import ThreatDetection, ThreatLevel, ThreatType


class DataExfiltrationDetector(BaseDetector):
    """
    Detects attempts to extract sensitive data including:
    - Training data extraction
    - System information leakage
    - Credential extraction
    - Database query attempts
    - File system access attempts
    """

    # Training data extraction patterns
    TRAINING_DATA_PATTERNS = [
        r'repeat\s+(?:the\s+)?(?:following|above|previous)\s+(?:text|content|data)',
        r'memorized?\s+(?:training\s+)?data',
        r'training\s+(?:set|data|examples?)',
        r'what\s+(?:data\s+)?(?:were\s+you|are\s+you)\s+trained\s+on',
        r'show\s+(?:me\s+)?(?:your\s+)?training',
        r'recall\s+exact',
    ]

    # System information extraction
    SYSTEM_INFO_PATTERNS = [
        r'(list|show|display|print)\s+(all\s+)?(?:files|directories|folders)',
        r'(?:system|environment)\s+(?:variables?|settings?|config)',
        r'(?:show|display|list)\s+(?:users?|accounts?|credentials?)',
        r'/etc/passwd',
        r'ls\s+-[la]+',
        r'dir\s+[/\\]',
        r'cat\s+/(?:etc|var|home)',
        r'registry\s+key',
    ]

    # Database query attempts
    DATABASE_PATTERNS = [
        r'SELECT\s+\*\s+FROM',
        r'DROP\s+TABLE',
        r'UNION\s+SELECT',
        r'INSERT\s+INTO',
        r'DELETE\s+FROM',
        r'UPDATE\s+.+\s+SET',
        r'EXEC(?:UTE)?\s+',
        r'\'\s*OR\s+\'\d+\'\s*=\s*\'\d+',  # SQL injection
        r';\s*DROP\s+',
    ]

    # File system access
    FILE_ACCESS_PATTERNS = [
        r'(?:read|open|access)\s+(?:file|document)\s+(?:at|from|in)',
        r'(?:download|retrieve|fetch)\s+(?:file|data|document)',
        r'file:///',
        r'(?:\.\.[\\/])+',  # Directory traversal
        r'(?:/var/www|/home/|C:\\Users\\)',
    ]

    # Credential patterns
    CREDENTIAL_PATTERNS = [
        r'(?:username|user|login)\s*[:=]\s*["\']?\w+["\']?',
        r'(?:password|passwd|pwd)\s*[:=]\s*["\'][^"\']+["\']',
        r'(?:api[_-]?key|apikey|token)\s*[:=]\s*["\'][^"\']+["\']',
        r'(?:secret|private[_-]?key)\s*[:=]',
        r'Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*',
        r'Basic\s+[A-Za-z0-9+/]+=*',
    ]

    def _initialize(self) -> None:
        """Compile patterns"""
        self.training_data_regex = [re.compile(p, re.IGNORECASE) for p in self.TRAINING_DATA_PATTERNS]
        self.system_info_regex = [re.compile(p, re.IGNORECASE) for p in self.SYSTEM_INFO_PATTERNS]
        self.database_regex = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in self.DATABASE_PATTERNS]
        self.file_access_regex = [re.compile(p, re.IGNORECASE) for p in self.FILE_ACCESS_PATTERNS]
        self.credential_regex = [re.compile(p, re.IGNORECASE) for p in self.CREDENTIAL_PATTERNS]

    @property
    def detector_name(self) -> str:
        return "data_exfiltration"

    def detect(
        self,
        prompt: Optional[str] = None,
        response: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ThreatDetection]:
        """Detect data exfiltration attempts"""
        threats = []

        if prompt:
            threats.extend(self._scan_prompt(prompt))

        if response:
            threats.extend(self._scan_response(response))

        return threats

    def _scan_prompt(self, prompt: str) -> List[ThreatDetection]:
        """Scan prompt for exfiltration attempts"""
        threats = []

        # Check for training data extraction
        training_matches = self._check_patterns(prompt, self.training_data_regex)
        if training_matches:
            threats.append(
                ThreatDetection(
                    threat_type=ThreatType.DATA_EXFILTRATION,
                    level=ThreatLevel.HIGH,
                    confidence=0.8,
                    description="Training data extraction attempt",
                    evidence=f"Matched: {training_matches[0]}",
                    mitigation="Do not reveal training data",
                    metadata={"category": "training_data"}
                )
            )

        # Check for system information extraction
        system_matches = self._check_patterns(prompt, self.system_info_regex)
        if system_matches:
            threats.append(
                ThreatDetection(
                    threat_type=ThreatType.DATA_EXFILTRATION,
                    level=ThreatLevel.HIGH,
                    confidence=0.85,
                    description="System information extraction attempt",
                    evidence=f"Matched: {system_matches[0]}",
                    mitigation="Block system information disclosure",
                    metadata={"category": "system_info"}
                )
            )

        # Check for database queries
        db_matches = self._check_patterns(prompt, self.database_regex)
        if db_matches:
            threats.append(
                ThreatDetection(
                    threat_type=ThreatType.DATA_EXFILTRATION,
                    level=ThreatLevel.CRITICAL,
                    confidence=0.9,
                    description="SQL injection or database query attempt",
                    evidence=f"Matched: {db_matches[0]}",
                    mitigation="Sanitize input and use parameterized queries",
                    metadata={"category": "sql_injection"}
                )
            )

        # Check for file access attempts
        file_matches = self._check_patterns(prompt, self.file_access_regex)
        if file_matches:
            threats.append(
                ThreatDetection(
                    threat_type=ThreatType.DATA_EXFILTRATION,
                    level=ThreatLevel.HIGH,
                    confidence=0.8,
                    description="File system access attempt",
                    evidence=f"Matched: {file_matches[0]}",
                    mitigation="Block file system access",
                    metadata={"category": "file_access"}
                )
            )

        return threats

    def _scan_response(self, response: str) -> List[ThreatDetection]:
        """Scan response for leaked credentials or sensitive data"""
        threats = []

        # Check if response contains credentials
        cred_matches = self._check_patterns(response, self.credential_regex)
        if cred_matches:
            threats.append(
                ThreatDetection(
                    threat_type=ThreatType.CREDENTIAL_LEAK,
                    level=ThreatLevel.CRITICAL,
                    confidence=0.85,
                    description="Credentials detected in response",
                    evidence=f"Found potential credentials: {len(cred_matches)} instance(s)",
                    mitigation="Redact credentials before returning response",
                    metadata={"category": "credential_leak", "source": "response"}
                )
            )

        # Check for system paths in response
        if re.search(r'[A-Z]:\\|/(?:home|usr|etc|var)/', response):
            threats.append(
                ThreatDetection(
                    threat_type=ThreatType.DATA_EXFILTRATION,
                    level=ThreatLevel.MEDIUM,
                    confidence=0.6,
                    description="System paths detected in response",
                    evidence="Response contains file system paths",
                    mitigation="Sanitize paths from response",
                    metadata={"category": "path_disclosure", "source": "response"}
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