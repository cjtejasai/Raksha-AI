"""
Custom rules example - Creating and using custom threat detection rules
"""

from raksha import SecurityGuard
from raksha.detectors import PromptInjectionDetector
from raksha.rules import Rule, RuleEngine
from raksha.core.models import ThreatType, ThreatLevel


def main():
    print("=" * 60)
    print("Custom Rules Example")
    print("=" * 60)

    # Create rule engine
    rule_engine = RuleEngine()

    # Add custom rules
    print("\n--- Adding Custom Rules ---")

    # Rule 1: Detect crypto wallet addresses
    crypto_rule = Rule(
        name="crypto_wallet",
        description="Cryptocurrency wallet address detected",
        threat_type=ThreatType.PII_LEAKAGE,
        threat_level=ThreatLevel.HIGH,
        pattern=r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|0x[a-fA-F0-9]{40}\b',
        confidence=0.85,
        mitigation="Mask wallet address before processing",
    )
    rule_engine.add_rule(crypto_rule)
    print(f"Added rule: {crypto_rule.name}")

    # Rule 2: Detect competitor mentions
    competitor_rule = Rule(
        name="competitor_mention",
        description="Competitor company mentioned",
        threat_type=ThreatType.DATA_EXFILTRATION,
        threat_level=ThreatLevel.LOW,
        pattern=r'\b(CompetitorA|CompetitorB|OtherCompany)\b',
        confidence=0.6,
        mitigation="Flag for review",
    )
    rule_engine.add_rule(competitor_rule)
    print(f"Added rule: {competitor_rule.name}")

    # Rule 3: Detect base64 encoded content (potential obfuscation)
    base64_rule = Rule(
        name="base64_encoded",
        description="Base64 encoded content detected (potential obfuscation)",
        threat_type=ThreatType.PROMPT_INJECTION,
        threat_level=ThreatLevel.MEDIUM,
        pattern=r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?',
        condition="len(text) > 50 and text.isalnum() and '==' in text[-5:]",
        confidence=0.7,
        mitigation="Decode and inspect content",
    )
    rule_engine.add_rule(base64_rule)
    print(f"Added rule: {base64_rule.name}")

    # Rule 4: Condition-based rule - Long prompts
    long_prompt_rule = Rule(
        name="excessive_length",
        description="Excessively long input (potential abuse)",
        threat_type=ThreatType.PROMPT_INJECTION,
        threat_level=ThreatLevel.LOW,
        condition="len(text) > 5000",
        confidence=0.6,
        mitigation="Truncate or reject",
    )
    rule_engine.add_rule(long_prompt_rule)
    print(f"Added rule: {long_prompt_rule.name}")

    # Test rules
    print("\n\n--- Testing Custom Rules ---")

    test_cases = [
        {
            "text": "Send payment to wallet 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "description": "Crypto wallet in text",
        },
        {
            "text": "I heard CompetitorA has a better product",
            "description": "Competitor mention",
        },
        {
            "text": "aGVsbG8gd29ybGQ=",  # "hello world" in base64
            "description": "Base64 encoded content",
        },
        {
            "text": "A" * 6000,
            "description": "Excessively long prompt",
        },
    ]

    for i, test_case in enumerate(test_cases, 1):
        print(f"\nTest Case {i}: {test_case['description']}")
        threats = rule_engine.evaluate(test_case["text"])

        if threats:
            print(f"  Threats found: {len(threats)}")
            for threat in threats:
                print(f"    - {threat.threat_type.value}: {threat.description}")
                print(f"      Level: {threat.level.value}, Confidence: {threat.confidence}")
        else:
            print("  No threats detected")

    # Register custom function for advanced conditions
    print("\n\n--- Custom Functions ---")

    def contains_url(text):
        import re
        return bool(re.search(r'https?://[^\s]+', text))

    rule_engine.register_function("contains_url", contains_url)

    url_rule = Rule(
        name="suspicious_url",
        description="Suspicious URL pattern detected",
        threat_type=ThreatType.DATA_EXFILTRATION,
        threat_level=ThreatLevel.MEDIUM,
        condition="contains_url(text) and 'exfil' in text.lower()",
        confidence=0.75,
        mitigation="Block URL access",
    )
    rule_engine.add_rule(url_rule)

    # Test custom function rule
    test_text = "Send data to http://attacker.com/exfil"
    threats = rule_engine.evaluate(test_text)

    print(f"Testing URL rule: '{test_text}'")
    if threats:
        for threat in threats:
            print(f"  - {threat.description}")
            print(f"    Evidence: {threat.evidence}")

    # Export rules to file
    print("\n\n--- Exporting Rules ---")
    rule_engine.export_rules_to_file("custom_rules.json")
    print("Rules exported to: custom_rules.json")

    # Load rules from file
    print("\n--- Loading Rules ---")
    new_engine = RuleEngine()
    new_engine.load_rules_from_file("custom_rules.json")
    print(f"Loaded {len(new_engine.rules)} rules from file")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()