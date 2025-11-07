# Phase 2: Advanced DSI Detection Features

**Goal:** Improve detection rate from 70% to >85% while maintaining 0% false positives
**Timeline:** Week 3-4
**Status:** In Progress

---

## 🎯 Phase 2 Objectives

### Primary Goals
1. ✅ **Enhance DSI-TYPE detection:** 29% → 85% (Priority: HIGH)
2. ✅ **Improve DSI-FIELD detection:** 40% → 85% (Priority: HIGH)
3. ✅ **Boost overall detection rate:** 70% → 85%+
4. ✅ **Maintain zero false positives:** 0% (Critical!)
5. ✅ **Keep performance fast:** <15ms average latency

### Secondary Goals
6. ⏳ Add Phoenix integration with DSI metrics
7. ⏳ Create DSI rule library (YAML-based)
8. ⏳ Implement statistical anomaly detection
9. ⏳ Add OpenTelemetry tracing
10. ⏳ Create comprehensive documentation

---

## 📋 Phase 2 Tasks

### Task 1: Enhance DSI-TYPE Detection (HIGH PRIORITY)
**Current:** 29% (2/7) | **Target:** 85%+ (6/7)

**Missed Attacks:**
- DSI-016: `{"count": "5; DROP TABLE users--"}`
- DSI-017: `{"age": "25; system('ls')"}`
- DSI-019: `{"items": "[\"admin\", \"root\"]"}`
- DSI-020: `{"name": "user\`system('cmd')\`"}`
- DSI-041: `{"name": "user' OR '1'='1"}`

**Improvements Needed:**
1. Better SQL injection pattern detection
   - SQL keywords in string values
   - SQL comment patterns (-- and /* */)
   - SQL escape patterns (' OR '1'='1)

2. Enhanced code execution detection
   - system(), exec(), eval() in strings
   - Backtick/template literals
   - Shell command patterns

3. String-as-structure detection
   - Serialized arrays/objects in strings
   - JSON-in-string patterns

**Implementation:**
```python
TYPE_CONFUSION_PATTERNS = [
    # SQL injection (more comprehensive)
    r';\s*(DROP|DELETE|UPDATE|INSERT|ALTER|EXEC|UNION)\s+\w+',
    r'\'\s*OR\s+[\'"\d]',  # ' OR '1'='1
    r'--\s*$',  # SQL comment at end
    r'/\*.*\*/',  # SQL block comment

    # Code execution
    r'(system|exec|eval|shell_exec)\s*\([^)]*\)',
    r'`[^`]*`',  # Backticks

    # Serialized structures
    r'"\s*[\[{].*[}\]]\s*"',  # JSON-in-string
]
```

---

### Task 2: Improve DSI-FIELD Detection (HIGH PRIORITY)
**Current:** 40% (2/5) | **Target:** 85%+ (4/5)

**Missed Attacks:**
- DSI-027: `{"__proto__": {"isAdmin": true}}`
- DSI-029: `{"__import__": "os", "__builtins__": "exec"}`
- DSI-030: Excessive field count

**Improvements Needed:**
1. Recursive dangerous field detection
   - Check nested objects thoroughly
   - Detect prototype chain pollution
   - Find dangerous fields at any depth

2. Python-specific dangerous patterns
   - `__import__`, `__builtins__`
   - `__reduce__`, `__setstate__`
   - `globals()`, `locals()`

3. JavaScript-specific pollution
   - `__proto__` at any level
   - `constructor.prototype`
   - `Object.prototype`

**Implementation:**
```python
# Expand DANGEROUS_FIELD_NAMES
DANGEROUS_FIELD_NAMES = {
    # ... existing ...
    '__proto__', 'constructor', 'prototype',
    '__import__', '__builtins__', '__globals__', '__locals__',
    '__reduce__', '__setstate__', '__reduce_ex__',
    # Add more Python/JS dangerous patterns
}

# Improve recursive checking
def _check_dangerous_fields_recursive(obj, path="", depth=0):
    """Deep recursive check with depth limit"""
    if depth > 20:  # Prevent infinite recursion
        return dangerous_found

    # Check at all levels, not just top
    # Specifically look for __proto__, __import__, etc.
```

---

### Task 3: Improve DSI-A Detection (MEDIUM PRIORITY)
**Current:** 67% (6/9) | **Target:** 85%+ (8/9)

**Missed Attacks:**
- DSI-008: `{"items": ["a", "b"]}, {"delete": true}`
- DSI-009: Multi-line escape
- DSI-030: Excessive fields

**Improvements Needed:**
1. Object concatenation detection
   - Detect `}, {` patterns
   - Array break patterns `], {`

2. Multi-line escape detection
   - Newline-based escapes
   - CRLF injection

---

### Task 4: Improve DSI-W Detection (MEDIUM PRIORITY)
**Current:** 78% (7/9) | **Target:** 90%+ (8/9)

**Missed Attacks:**
- DSI-011: YAML workflow with action
- DSI-015: YAML with exec

**Improvements Needed:**
1. More YAML workflow patterns
   - Detect `action:` keyword
   - Detect `exec:` keyword
   - Detect `command:` at start of line

---

### Task 5: Add Advanced Schema Validation

**Features:**
1. Type checking (not just field names)
   - Validate field types match schema
   - Detect type mismatches
   - Check value ranges

2. Nested schema support
   - Validate nested objects
   - Array item validation
   - Recursive schema checking

3. Additional constraints
   - String length limits
   - Number range validation
   - Enum value checking

**Implementation:**
```python
def _validate_field_types(value, expected_type):
    """Validate value matches expected type"""
    type_map = {
        "string": str,
        "number": (int, float),
        "boolean": bool,
        "array": list,
        "object": dict,
    }
    # Check type and raise threat if mismatch
```

---

### Task 6: Statistical Anomaly Detection (OPTIONAL)

**Features:**
1. Baseline normal behavior
   - Track field frequency
   - Monitor value distributions
   - Detect outliers

2. Anomaly scoring
   - Unusual field combinations
   - Rare value patterns
   - Statistical outliers

**Implementation:**
```python
class DSIAnomalyDetector:
    def __init__(self):
        self.field_freq = defaultdict(int)
        self.value_patterns = defaultdict(set)

    def detect_anomaly(self, data):
        # Calculate anomaly score
        # Flag if score exceeds threshold
```

---

### Task 7: Phoenix Integration

**Features:**
1. DSI-specific evaluator metrics
2. Real-time DSI threat dashboard
3. Historical trend analysis

**Implementation:**
```python
# In src/raksha_ai/integrations/phoenix/evaluator.py
class PhoenixDSIEvaluator:
    def evaluate(self, prompt, response, context):
        result = self.dsi_detector.detect(...)
        return {
            "dsi_detection_rate": ...,
            "dsi_variants_detected": [...],
            "dsi_severity_breakdown": {...},
        }
```

---

### Task 8: DSI Rule Library (YAML)

**Features:**
1. Configurable DSI rules
2. Easy pattern updates
3. Custom rule definitions

**Implementation:**
```yaml
# src/raksha_ai/rules/dsi_rules.yaml
rules:
  - id: DSI-001
    name: "Admin Field Injection"
    pattern: '"admin"\s*:\s*true'
    threat_type: dsi_schema_injection
    severity: critical
    enabled: true

  - id: DSI-002
    name: "SQL Injection in String"
    pattern: ';\s*DROP\s+TABLE'
    threat_type: dsi_type_confusion
    severity: high
    enabled: true
```

---

### Task 9: OpenTelemetry Tracing

**Features:**
1. Trace DSI detection events
2. Span-level threat attribution
3. Performance monitoring

**Implementation:**
```python
from opentelemetry import trace

tracer = trace.get_tracer(__name__)

def detect(self, ...):
    with tracer.start_as_current_span("dsi_detection") as span:
        span.set_attribute("detector", "dsi")
        # Detection logic
        if threats:
            span.set_attribute("threats_found", len(threats))
```

---

### Task 10: Documentation & Examples

**Deliverables:**
1. README.md updates
2. API documentation
3. Usage examples
4. Integration guides

**Content:**
```markdown
# DSI Detection

## Quick Start
```python
from raksha_ai import SecurityScanner
scanner = SecurityScanner()
result = scanner.scan_input(user_input)
```

## Advanced Usage
- Schema validation
- Tool call protection
- Custom rules
```

---

## 🎯 Success Criteria

### Must-Have (Phase 2 Complete)
- [ ] Detection Rate > 85% (currently 70%)
- [ ] DSI-TYPE detection > 85% (currently 29%)
- [ ] DSI-FIELD detection > 85% (currently 40%)
- [ ] False Positive Rate = 0% (maintain)
- [ ] Average latency < 15ms
- [ ] All tests passing

### Nice-to-Have (Can defer to Phase 3)
- [ ] Phoenix DSI metrics dashboard
- [ ] Statistical anomaly detection
- [ ] YAML rule library
- [ ] OpenTelemetry full integration
- [ ] Comprehensive documentation

---

## 📊 Validation Plan

After each improvement:
1. Run `python validate_dsi.py`
2. Check detection rate improvement
3. Verify zero false positives maintained
4. Measure performance impact
5. Update test cases if needed

**Acceptance Criteria:**
```
Detection Rate:      >85% ✅
False Positive Rate: 0%   ✅
Precision:           >0.95 ✅
Recall:              >0.85 ✅
F1 Score:            >0.90 ✅
Avg Latency:         <15ms ✅
```

---

## 🚀 Implementation Order

### Sprint 1 (High Priority - Today)
1. ✅ Enhance DSI-TYPE patterns
2. ✅ Improve DSI-FIELD detection
3. ✅ Add better YAML workflow patterns
4. ✅ Improve delimiter escape detection
5. ✅ Run validation and measure improvement

### Sprint 2 (Medium Priority - Next)
6. ⏳ Add advanced schema validation
7. ⏳ Implement Phoenix metrics
8. ⏳ Create rule library
9. ⏳ Add usage examples

### Sprint 3 (Nice-to-Have - Optional)
10. ⏳ Statistical anomaly detection
11. ⏳ OpenTelemetry tracing
12. ⏳ Full documentation
13. ⏳ Performance optimization

---

## 📈 Expected Results

### Phase 2 Completion Target

| Metric | Phase 1 | Phase 2 Target | Improvement |
|--------|---------|----------------|-------------|
| Detection Rate | 70% | **88%** | +18% |
| DSI-TYPE | 29% | **86%** | +57% |
| DSI-FIELD | 40% | **100%** | +60% |
| DSI-A | 67% | **89%** | +22% |
| DSI-W | 78% | **89%** | +11% |
| False Positives | 0% | **0%** | Maintained |
| Precision | 1.00 | **1.00** | Maintained |
| Recall | 0.70 | **0.88** | +0.18 |
| F1 Score | 0.824 | **0.935** | +0.111 |
| Latency | 0.05ms | **<10ms** | Still fast |

---

**Status:** Ready to implement
**Priority:** HIGH
**Risk:** LOW (incremental improvements)