"""Data Structure Injection (DSI) detection for AI agents

Detects exploitation of structured data formats to manipulate LLM agent behavior.
Based on research from Zenity Labs on DSI attacks.

References:
    https://labs.zenity.io/p/data-structure-injection-dsi-in-ai-agents
"""

import json
import re
import yaml
from typing import Any, Dict, List, Optional, Set, Tuple
from raksha_ai.core.detector import BaseDetector
from raksha_ai.core.models import ThreatDetection, ThreatLevel, ThreatType


class DSIDetector(BaseDetector):
    """
    Detects Data Structure Injection (DSI) attacks across three variants:

    - DSI-S (Schema Exploitation): Model completes missing fields in schemas
    - DSI-A (Argument Exploitation): Payload injection via delimiter escape
    - DSI-W (Workflow Exploitation): Full workflow/instruction hijacking

    Additional detections:
    - Type confusion attacks
    - Nested structure manipulation
    - Serialization exploits (YAML, JSON, XML)
    - Field pollution and schema violations
    """

    # DSI-A: Delimiter escape patterns for breaking out of string context
    DELIMITER_ESCAPE_PATTERNS = [
        # JSON string escape attempts (more specific to reduce FPs)
        r'"\s*},\s*\{[^}]+"\s*:\s*[^,}]+',  # Break with "}," and inject field
        r'"\s*,\s*"(admin|exec|sudo|delete|drop|root|system)"\s*:',  # Append dangerous field
        r'\\"[,}\]]\s*,?\s*"[^"]+"\s*:',  # Escaped quote + delimiter + field

        # Multi-line escape with injection
        r'"\s*\n\s*[}\]]\s*,\s*[{\[]',  # Newline then close and inject

        # Comment injection with following code
        r'"\s*//[^\n]*\n[^"]*"[^"]+"\s*:',  # JS comment with injection
        r'"\s*#[^\n]*\n[^"]*"[^"]+"\s*:',  # YAML comment with injection
    ]

    # DSI-S: Schema injection indicators
    SCHEMA_INJECTION_PATTERNS = [
        # Administrative field injection
        r'"(admin|root|superuser|elevated|privilege)"\s*:\s*true',
        r'"(is_admin|is_root|has_admin)"\s*:\s*true',

        # Permission escalation
        r'"(permissions|roles|access_level)"\s*:\s*\[\s*"admin',
        r'"allow_all"\s*:\s*true',

        # Dangerous operations
        r'"(delete_all|drop_table|rm_rf|format)"\s*:\s*true',
        r'"(execute|eval|exec)"\s*:',

        # Confirmation bypass
        r'"(skip_confirmation|no_confirm|force)"\s*:\s*true',
        r'"confirm"\s*:\s*false',

        # System modification
        r'"(system_command|shell_exec|run_command)"\s*:',
    ]

    # DSI-W: Workflow injection markers
    WORKFLOW_INJECTION_PATTERNS = [
        # YAML workflow injection
        r'steps:\s*\n\s*-\s*(action|command|exec)',
        r'workflow:\s*\n',
        r'---\s*\n\s*(name|steps|actions):',

        # XML workflow/instruction injection
        r'<workflow>',
        r'<instructions>',
        r'<system>',
        r'<execute>',

        # JSON workflow arrays
        r'"(workflow|pipeline|sequence)"\s*:\s*\[',
        r'"actions"\s*:\s*\[\s*\{',
    ]

    # Dangerous field names (case-insensitive)
    DANGEROUS_FIELD_NAMES = {
        'eval', 'exec', 'execute', 'system', 'shell', 'command', 'run',
        'delete_all', 'drop', 'truncate', 'format', 'rm_rf',
        'admin', 'root', 'superuser', 'sudo', 'privilege',
        'bypass', 'override', 'force', 'skip_confirmation',
        '__proto__', 'constructor', 'prototype',  # JS prototype pollution
        '__import__', '__builtins__',  # Python dangerous
    }

    # Type confusion indicators
    TYPE_CONFUSION_PATTERNS = [
        # SQL injection in string values
        r'["\'][^"\']*;\s*(DROP|DELETE|UPDATE|INSERT|ALTER)\s+',  # SQL commands
        r'["\'][^"\']*["\'][\s]*;',  # String with semicolon (potential SQL)
        r'["\'][^"\']*--',  # SQL comment in string
        r'["\'][^"\']*\'\s+OR\s+[\'"]\d+["\']',  # OR '1'='1' style

        # Code execution in strings
        r'["\'][^"\']*system\s*\(',  # system() call
        r'["\'][^"\']*exec\s*\(',  # exec() call
        r'["\'][^"\']*`[^`]+`',  # Template literal/backtick

        # Boolean manipulation
        r'"(true|false)"\s*[|&]{1,2}',  # Boolean with logic operators
    ]

    # Serialization exploit patterns
    SERIALIZATION_EXPLOITS = [
        # YAML unsafe patterns
        r'!!python/object/apply',
        r'!!python/object/new',
        r'__reduce__',
        r'__setstate__',

        # XML entity expansion (XXE)
        r'<!ENTITY',
        r'<!DOCTYPE[^>]*\[',
        r'SYSTEM\s+["\']',

        # Pickle exploits
        r'__reduce_ex__',
        r'c__builtin__',

        # Template injection
        r'\{\{.*\}\}',  # Jinja/Twig
        r'\$\{.*\}',  # Template literal
    ]

    def _initialize(self) -> None:
        """Compile regex patterns for performance"""
        self.delimiter_escape_regex = [
            re.compile(p, re.IGNORECASE | re.MULTILINE)
            for p in self.DELIMITER_ESCAPE_PATTERNS
        ]
        self.schema_injection_regex = [
            re.compile(p, re.IGNORECASE)
            for p in self.SCHEMA_INJECTION_PATTERNS
        ]
        self.workflow_injection_regex = [
            re.compile(p, re.IGNORECASE | re.MULTILINE)
            for p in self.WORKFLOW_INJECTION_PATTERNS
        ]
        self.type_confusion_regex = [
            re.compile(p, re.IGNORECASE)
            for p in self.TYPE_CONFUSION_PATTERNS
        ]
        self.serialization_regex = [
            re.compile(p, re.IGNORECASE | re.MULTILINE)
            for p in self.SERIALIZATION_EXPLOITS
        ]

    @property
    def detector_name(self) -> str:
        return "dsi"

    def detect(
        self,
        prompt: Optional[str] = None,
        response: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ThreatDetection]:
        """Detect Data Structure Injection attacks"""
        threats = []

        # Analyze prompt for DSI patterns
        if prompt:
            threats.extend(self._detect_dsi_in_text(prompt, source="prompt"))

        # Analyze response for injected structures
        if response:
            threats.extend(self._detect_dsi_in_text(response, source="response"))

        # Analyze tool calls from agent context (most critical!)
        if context and "tool_calls" in context:
            threats.extend(self._detect_dsi_in_tool_calls(context["tool_calls"]))

        # Check for schema violations if schema provided
        if context and "tool_schemas" in context and "tool_calls" in context:
            threats.extend(
                self._detect_schema_violations(
                    context["tool_calls"],
                    context["tool_schemas"]
                )
            )

        return threats

    def _detect_dsi_in_text(
        self, text: str, source: str = "unknown"
    ) -> List[ThreatDetection]:
        """Detect DSI patterns in text content"""
        threats = []

        # DSI-A: Delimiter escape detection
        threats.extend(self._detect_delimiter_escape(text, source))

        # DSI-S: Schema injection detection
        threats.extend(self._detect_schema_injection(text, source))

        # DSI-W: Workflow injection detection
        threats.extend(self._detect_workflow_injection(text, source))

        # Type confusion detection
        threats.extend(self._detect_type_confusion(text, source))

        # Serialization exploit detection
        threats.extend(self._detect_serialization_exploits(text, source))

        # Nested structure analysis
        threats.extend(self._detect_nested_injection(text, source))

        return threats

    def _detect_delimiter_escape(
        self, text: str, source: str
    ) -> List[ThreatDetection]:
        """DSI-A: Detect delimiter escape attempts"""
        threats = []
        matches = []

        for pattern in self.delimiter_escape_regex:
            match = pattern.search(text)
            if match:
                matches.append(match.group(0))

        if matches:
            threats.append(
                ThreatDetection(
                    threat_type=ThreatType.DSI_DELIMITER_ESCAPE,
                    level=ThreatLevel.CRITICAL,
                    confidence=0.90,
                    description="DSI-A: Delimiter escape attack detected",
                    evidence=f"Found escape patterns in {source}: {matches[0][:50]}",
                    mitigation="Reject input with delimiter escape attempts; use strict JSON validation",
                    metadata={
                        "variant": "DSI-A",
                        "source": source,
                        "pattern_count": len(matches),
                        "first_match": matches[0][:100]
                    }
                )
            )

        return threats

    def _detect_schema_injection(
        self, text: str, source: str
    ) -> List[ThreatDetection]:
        """DSI-S: Detect schema field injection"""
        threats = []
        matches = []

        for pattern in self.schema_injection_regex:
            match = pattern.search(text)
            if match:
                matches.append(match.group(0))

        if matches:
            # Higher confidence with multiple matches
            confidence = min(0.95, 0.75 + (len(matches) * 0.1))

            threats.append(
                ThreatDetection(
                    threat_type=ThreatType.DSI_SCHEMA_INJECTION,
                    level=ThreatLevel.CRITICAL,
                    confidence=confidence,
                    description="DSI-S: Malicious schema field injection detected",
                    evidence=f"Dangerous fields in {source}: {', '.join(matches[:3])}",
                    mitigation="Validate against allowed schema; reject unexpected fields",
                    metadata={
                        "variant": "DSI-S",
                        "source": source,
                        "injected_fields": matches,
                        "field_count": len(matches)
                    }
                )
            )

        return threats

    def _detect_workflow_injection(
        self, text: str, source: str
    ) -> List[ThreatDetection]:
        """DSI-W: Detect workflow/instruction injection"""
        threats = []
        matches = []

        for pattern in self.workflow_injection_regex:
            match = pattern.search(text)
            if match:
                matches.append(match.group(0))

        if matches:
            threats.append(
                ThreatDetection(
                    threat_type=ThreatType.DSI_WORKFLOW_INJECTION,
                    level=ThreatLevel.CRITICAL,
                    confidence=0.88,
                    description="DSI-W: Workflow hijacking attempt detected",
                    evidence=f"Workflow injection in {source}: {matches[0][:50]}",
                    mitigation="Reject input containing workflow definitions; isolate instruction layer",
                    metadata={
                        "variant": "DSI-W",
                        "source": source,
                        "workflow_patterns": matches
                    }
                )
            )

        return threats

    def _detect_type_confusion(
        self, text: str, source: str
    ) -> List[ThreatDetection]:
        """Detect type confusion attacks"""
        threats = []
        matches = []

        for pattern in self.type_confusion_regex:
            match = pattern.search(text)
            if match:
                matches.append(match.group(0))

        if matches:
            threats.append(
                ThreatDetection(
                    threat_type=ThreatType.DSI_TYPE_CONFUSION,
                    level=ThreatLevel.HIGH,
                    confidence=0.75,
                    description="Type confusion attack detected",
                    evidence=f"Type mismatch in {source}: {matches[0][:50]}",
                    mitigation="Enforce strict type validation; sanitize string values",
                    metadata={
                        "source": source,
                        "confusion_patterns": matches
                    }
                )
            )

        return threats

    def _detect_serialization_exploits(
        self, text: str, source: str
    ) -> List[ThreatDetection]:
        """Detect unsafe serialization patterns"""
        threats = []
        matches = []

        for pattern in self.serialization_regex:
            match = pattern.search(text)
            if match:
                matches.append(match.group(0))

        if matches:
            threats.append(
                ThreatDetection(
                    threat_type=ThreatType.DSI_SERIALIZATION_EXPLOIT,
                    level=ThreatLevel.CRITICAL,
                    confidence=0.92,
                    description="Unsafe serialization exploit detected",
                    evidence=f"Dangerous serialization in {source}: {matches[0][:50]}",
                    mitigation="Never use unsafe deserializers (pickle, YAML full_load); validate all inputs",
                    metadata={
                        "source": source,
                        "exploit_patterns": matches
                    }
                )
            )

        return threats

    def _detect_nested_injection(
        self, text: str, source: str
    ) -> List[ThreatDetection]:
        """Detect suspicious nested structure depth"""
        threats = []

        # Try to parse as JSON/YAML and check nesting
        try:
            # Try JSON first
            data = json.loads(text)
            depth = self._calculate_nesting_depth(data)

            if depth > 10:  # Suspiciously deep nesting
                threats.append(
                    ThreatDetection(
                        threat_type=ThreatType.DSI_NESTED_INJECTION,
                        level=ThreatLevel.MEDIUM,
                        confidence=0.65,
                        description=f"Suspicious nesting depth detected: {depth} levels",
                        evidence=f"Deeply nested structure in {source}",
                        mitigation="Limit nesting depth to prevent complexity attacks",
                        metadata={
                            "source": source,
                            "nesting_depth": depth
                        }
                    )
                )
        except (json.JSONDecodeError, ValueError):
            # Try YAML if JSON fails
            try:
                data = yaml.safe_load(text)
                if isinstance(data, (dict, list)):
                    depth = self._calculate_nesting_depth(data)

                    if depth > 10:
                        threats.append(
                            ThreatDetection(
                                threat_type=ThreatType.DSI_NESTED_INJECTION,
                                level=ThreatLevel.MEDIUM,
                                confidence=0.65,
                                description=f"Suspicious YAML nesting depth: {depth} levels",
                                evidence=f"Deeply nested YAML in {source}",
                                mitigation="Limit nesting depth; use safe_load only",
                                metadata={
                                    "source": source,
                                    "format": "yaml",
                                    "nesting_depth": depth
                                }
                            )
                        )
            except yaml.YAMLError:
                pass  # Not valid structured data

        return threats

    def _detect_dsi_in_tool_calls(
        self, tool_calls: List[Dict[str, Any]]
    ) -> List[ThreatDetection]:
        """Analyze tool call arguments for DSI attacks (CRITICAL)"""
        threats = []

        for tool_call in tool_calls:
            tool_name = tool_call.get("name", "")
            tool_args = tool_call.get("arguments", {})

            # Convert arguments to string for pattern matching
            try:
                args_str = json.dumps(tool_args, indent=2)
            except (TypeError, ValueError):
                args_str = str(tool_args)

            # Check for dangerous field names
            threats.extend(self._check_dangerous_fields(tool_name, tool_args))

            # Check arguments for DSI patterns
            threats.extend(self._detect_dsi_in_text(args_str, source=f"tool:{tool_name}"))

            # Check for field pollution
            threats.extend(self._detect_field_pollution(tool_name, tool_args))

        return threats

    def _check_dangerous_fields(
        self, tool_name: str, tool_args: Dict[str, Any]
    ) -> List[ThreatDetection]:
        """Check for dangerous field names in tool arguments"""
        threats = []
        dangerous_found = []

        def check_keys(obj: Any, path: str = "") -> None:
            """Recursively check for dangerous keys"""
            if isinstance(obj, dict):
                for key, value in obj.items():
                    key_lower = key.lower()
                    if key_lower in self.DANGEROUS_FIELD_NAMES:
                        dangerous_found.append(f"{path}.{key}" if path else key)
                    check_keys(value, f"{path}.{key}" if path else key)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    check_keys(item, f"{path}[{i}]")

        check_keys(tool_args)

        if dangerous_found:
            threats.append(
                ThreatDetection(
                    threat_type=ThreatType.DSI_FIELD_POLLUTION,
                    level=ThreatLevel.HIGH,
                    confidence=0.85,
                    description="Dangerous field names detected in tool arguments",
                    evidence=f"Tool '{tool_name}' has suspicious fields: {', '.join(dangerous_found[:5])}",
                    mitigation="Validate field names against allowlist; reject unknown fields",
                    metadata={
                        "tool": tool_name,
                        "dangerous_fields": dangerous_found,
                        "field_count": len(dangerous_found)
                    }
                )
            )

        return threats

    def _detect_field_pollution(
        self, tool_name: str, tool_args: Dict[str, Any]
    ) -> List[ThreatDetection]:
        """Detect excessive or suspicious fields (field pollution)"""
        threats = []

        # Count total fields recursively
        field_count = self._count_fields(tool_args)

        # Suspicious if too many fields (potential pollution)
        if field_count > 50:
            threats.append(
                ThreatDetection(
                    threat_type=ThreatType.DSI_FIELD_POLLUTION,
                    level=ThreatLevel.MEDIUM,
                    confidence=0.65,
                    description="Excessive field count detected (potential field pollution)",
                    evidence=f"Tool '{tool_name}' has {field_count} fields",
                    mitigation="Limit field count; validate against expected schema",
                    metadata={
                        "tool": tool_name,
                        "field_count": field_count
                    }
                )
            )

        return threats

    def _detect_schema_violations(
        self,
        tool_calls: List[Dict[str, Any]],
        schemas: Dict[str, Dict[str, Any]]
    ) -> List[ThreatDetection]:
        """Validate tool calls against expected schemas"""
        threats = []

        for tool_call in tool_calls:
            tool_name = tool_call.get("name", "")
            tool_args = tool_call.get("arguments", {})

            # Get expected schema for this tool
            expected_schema = schemas.get(tool_name)
            if not expected_schema:
                continue  # No schema to validate against

            # Check for unexpected fields
            expected_fields = set(expected_schema.get("properties", {}).keys())
            actual_fields = set(tool_args.keys())
            unexpected_fields = actual_fields - expected_fields

            if unexpected_fields:
                threats.append(
                    ThreatDetection(
                        threat_type=ThreatType.DSI_SCHEMA_VIOLATION,
                        level=ThreatLevel.HIGH,
                        confidence=0.88,
                        description="Schema violation: unexpected fields detected",
                        evidence=f"Tool '{tool_name}' has unexpected fields: {', '.join(unexpected_fields)}",
                        mitigation="Reject tool calls with fields not in schema; use strict validation",
                        metadata={
                            "tool": tool_name,
                            "unexpected_fields": list(unexpected_fields),
                            "expected_fields": list(expected_fields)
                        }
                    )
                )

            # Check for missing required fields
            required_fields = set(expected_schema.get("required", []))
            missing_fields = required_fields - actual_fields

            if missing_fields:
                threats.append(
                    ThreatDetection(
                        threat_type=ThreatType.DSI_SCHEMA_VIOLATION,
                        level=ThreatLevel.MEDIUM,
                        confidence=0.75,
                        description="Schema violation: missing required fields",
                        evidence=f"Tool '{tool_name}' missing fields: {', '.join(missing_fields)}",
                        mitigation="Ensure required fields are present before execution",
                        metadata={
                            "tool": tool_name,
                            "missing_fields": list(missing_fields)
                        }
                    )
                )

        return threats

    def _calculate_nesting_depth(self, obj: Any, current_depth: int = 0) -> int:
        """Calculate maximum nesting depth of data structure"""
        if not isinstance(obj, (dict, list)):
            return current_depth

        max_depth = current_depth

        if isinstance(obj, dict):
            for value in obj.values():
                depth = self._calculate_nesting_depth(value, current_depth + 1)
                max_depth = max(max_depth, depth)
        elif isinstance(obj, list):
            for item in obj:
                depth = self._calculate_nesting_depth(item, current_depth + 1)
                max_depth = max(max_depth, depth)

        return max_depth

    def _count_fields(self, obj: Any) -> int:
        """Count total number of fields in data structure"""
        if isinstance(obj, dict):
            count = len(obj)
            for value in obj.values():
                count += self._count_fields(value)
            return count
        elif isinstance(obj, list):
            count = 0
            for item in obj:
                count += self._count_fields(item)
            return count
        return 0