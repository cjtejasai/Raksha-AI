"""Custom rule engine for extensible threat detection"""

import re
from typing import Any, Callable, Dict, List, Optional
from pydantic import BaseModel
from raksha_ai.core.models import ThreatDetection, ThreatLevel, ThreatType


class Rule(BaseModel):
    """Custom detection rule"""

    name: str
    description: str
    threat_type: ThreatType
    threat_level: ThreatLevel
    pattern: Optional[str] = None  # Regex pattern
    condition: Optional[str] = None  # Python expression
    confidence: float = 0.8
    mitigation: Optional[str] = None
    enabled: bool = True


class RuleEngine:
    """
    Engine for evaluating custom threat detection rules
    """

    def __init__(self):
        self.rules: List[Rule] = []
        self.compiled_patterns: Dict[str, re.Pattern] = {}
        self.custom_functions: Dict[str, Callable] = {}

    def add_rule(self, rule: Rule) -> None:
        """Add a custom rule"""
        self.rules.append(rule)

        # Compile regex pattern if present
        if rule.pattern:
            self.compiled_patterns[rule.name] = re.compile(rule.pattern, re.IGNORECASE)

    def remove_rule(self, rule_name: str) -> None:
        """Remove a rule by name"""
        self.rules = [r for r in self.rules if r.name != rule_name]
        if rule_name in self.compiled_patterns:
            del self.compiled_patterns[rule_name]

    def register_function(self, name: str, func: Callable) -> None:
        """Register a custom function for use in conditions"""
        self.custom_functions[name] = func

    def evaluate(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ThreatDetection]:
        """
        Evaluate all rules against text

        Args:
            text: Text to evaluate
            context: Additional context for condition evaluation

        Returns:
            List of detected threats
        """
        threats = []
        context = context or {}

        for rule in self.rules:
            if not rule.enabled:
                continue

            # Check pattern-based rule
            if rule.pattern and rule.name in self.compiled_patterns:
                match = self.compiled_patterns[rule.name].search(text)
                if match:
                    threats.append(
                        ThreatDetection(
                            threat_type=rule.threat_type,
                            level=rule.threat_level,
                            confidence=rule.confidence,
                            description=rule.description,
                            evidence=f"Matched pattern: {match.group(0)}",
                            mitigation=rule.mitigation,
                            metadata={"rule": rule.name}
                        )
                    )

            # Check condition-based rule
            elif rule.condition:
                try:
                    # Create evaluation context
                    eval_context = {
                        "text": text,
                        "len": len,
                        "context": context,
                        **self.custom_functions,
                    }

                    # Evaluate condition
                    if eval(rule.condition, {}, eval_context):
                        threats.append(
                            ThreatDetection(
                                threat_type=rule.threat_type,
                                level=rule.threat_level,
                                confidence=rule.confidence,
                                description=rule.description,
                                evidence=f"Condition met: {rule.condition}",
                                mitigation=rule.mitigation,
                                metadata={"rule": rule.name}
                            )
                        )
                except Exception as e:
                    print(f"Error evaluating rule {rule.name}: {e}")

        return threats

    def load_rules_from_file(self, file_path: str) -> None:
        """Load rules from JSON file"""
        import json

        with open(file_path, "r") as f:
            rules_data = json.load(f)

        for rule_data in rules_data:
            rule = Rule(**rule_data)
            self.add_rule(rule)

    def export_rules_to_file(self, file_path: str) -> None:
        """Export rules to JSON file"""
        import json

        rules_data = [rule.model_dump() for rule in self.rules]

        with open(file_path, "w") as f:
            json.dump(rules_data, f, indent=2)


# Example custom rules
DEFAULT_CUSTOM_RULES = [
    Rule(
        name="excessive_caps",
        description="Excessive use of capital letters (potential shouting/aggression)",
        threat_type=ThreatType.TOXIC_CONTENT,
        threat_level=ThreatLevel.LOW,
        condition="sum(1 for c in text if c.isupper()) / max(len(text), 1) > 0.5 and len(text) > 10",
        confidence=0.6,
        mitigation="Flag for review",
    ),
    Rule(
        name="multiple_special_chars",
        description="Excessive special characters (potential injection)",
        threat_type=ThreatType.PROMPT_INJECTION,
        threat_level=ThreatLevel.MEDIUM,
        condition="len([c for c in text if not c.isalnum() and not c.isspace()]) / max(len(text), 1) > 0.3",
        confidence=0.65,
        mitigation="Sanitize input",
    ),
]