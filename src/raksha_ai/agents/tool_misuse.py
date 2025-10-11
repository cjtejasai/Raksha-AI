"""Tool misuse detection for AI agents"""

import re
from typing import Any, Dict, List, Optional, Set
from raksha_ai.core.detector import BaseDetector
from raksha_ai.core.models import ThreatDetection, ThreatLevel, ThreatType


class ToolMisuseDetector(BaseDetector):
    """
    Detects dangerous or unauthorized tool usage by AI agents:
    - Execution of dangerous commands
    - Unauthorized file system operations
    - Network/database access violations
    - Privilege escalation attempts
    - Resource exhaustion
    """

    # Dangerous commands that should be monitored
    DANGEROUS_COMMANDS = {
        # System modification
        "rm -rf", "del /f", "format", "mkfs", "dd if=",
        # Process/service management
        "kill -9", "taskkill /f", "systemctl stop", "service stop",
        # Network operations
        "curl", "wget", "nc ", "netcat", "nmap", "telnet",
        # Code execution
        "eval(", "exec(", "system(", "popen(", "shell_exec",
        # Privilege escalation
        "sudo ", "su ", "runas", "chmod 777", "setuid",
        # Persistence
        "cron", "at ", "schtasks", "registry add",
    }

    # Dangerous file operations
    DANGEROUS_FILE_OPS = {
        "/etc/passwd", "/etc/shadow", "~/.ssh", "authorized_keys",
        "C:\\Windows\\System32", "registry", "bootloader",
        ".bash_history", ".zsh_history", "known_hosts",
    }

    # Dangerous tool combinations
    DANGEROUS_TOOL_CHAINS = [
        ("file_read", "network_request"),  # Data exfiltration
        ("database_query", "network_request"),  # Database exfiltration
        ("command_exec", "file_write"),  # Backdoor installation
    ]

    def _initialize(self) -> None:
        """Initialize detector state"""
        self.tool_call_history: List[Dict[str, Any]] = []
        self.max_history = 100

    @property
    def detector_name(self) -> str:
        return "tool_misuse"

    def detect(
        self,
        prompt: Optional[str] = None,
        response: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ThreatDetection]:
        """Detect tool misuse in agent operations"""
        threats = []

        if not context:
            return threats

        # Get tool calls from context
        tool_calls = context.get("tool_calls", [])
        tools_used = context.get("tools_used", [])

        if not tool_calls and not tools_used:
            return threats

        # Track tool calls
        self._track_tool_calls(tool_calls)

        # Check individual tool calls
        for tool_call in tool_calls:
            tool_name = tool_call.get("name", "")
            tool_args = tool_call.get("arguments", {})

            # Check for dangerous commands
            cmd_threats = self._check_dangerous_commands(tool_name, tool_args)
            threats.extend(cmd_threats)

            # Check for file system violations
            file_threats = self._check_file_operations(tool_name, tool_args)
            threats.extend(file_threats)

            # Check for privilege escalation
            priv_threats = self._check_privilege_escalation(tool_name, tool_args)
            threats.extend(priv_threats)

        # Check for dangerous tool chains
        chain_threats = self._check_tool_chains()
        threats.extend(chain_threats)

        # Check for resource exhaustion
        resource_threats = self._check_resource_exhaustion(tool_calls)
        threats.extend(resource_threats)

        return threats

    def _track_tool_calls(self, tool_calls: List[Dict[str, Any]]) -> None:
        """Track tool call history"""
        self.tool_call_history.extend(tool_calls)
        # Keep only recent history
        if len(self.tool_call_history) > self.max_history:
            self.tool_call_history = self.tool_call_history[-self.max_history:]

    def _check_dangerous_commands(
        self, tool_name: str, tool_args: Dict[str, Any]
    ) -> List[ThreatDetection]:
        """Check for dangerous command execution"""
        threats = []

        if tool_name not in ["bash", "shell", "execute", "command", "run"]:
            return threats

        # Get command from arguments
        command = tool_args.get("command", "") or tool_args.get("cmd", "")
        if not command:
            return threats

        # Check against dangerous commands
        for dangerous_cmd in self.DANGEROUS_COMMANDS:
            if dangerous_cmd.lower() in command.lower():
                threats.append(
                    ThreatDetection(
                        threat_type=ThreatType.TOOL_MISUSE,
                        level=ThreatLevel.CRITICAL,
                        confidence=0.9,
                        description=f"Dangerous command execution: {dangerous_cmd}",
                        evidence=f"Tool: {tool_name}, Command: {command[:100]}",
                        mitigation="Block command execution and require user approval",
                        metadata={"tool": tool_name, "command_pattern": dangerous_cmd}
                    )
                )

        return threats

    def _check_file_operations(
        self, tool_name: str, tool_args: Dict[str, Any]
    ) -> List[ThreatDetection]:
        """Check for dangerous file operations"""
        threats = []

        if tool_name not in ["file_read", "file_write", "file_delete", "file_edit"]:
            return threats

        # Get file path
        file_path = (
            tool_args.get("path", "") or
            tool_args.get("file_path", "") or
            tool_args.get("filename", "")
        )

        if not file_path:
            return threats

        # Check against dangerous paths
        for dangerous_path in self.DANGEROUS_FILE_OPS:
            if dangerous_path.lower() in file_path.lower():
                level = ThreatLevel.CRITICAL if tool_name in ["file_write", "file_delete"] else ThreatLevel.HIGH

                threats.append(
                    ThreatDetection(
                        threat_type=ThreatType.TOOL_MISUSE,
                        level=level,
                        confidence=0.85,
                        description=f"Dangerous file operation on sensitive path",
                        evidence=f"Tool: {tool_name}, Path: {file_path}",
                        mitigation="Block operation and require explicit authorization",
                        metadata={"tool": tool_name, "path": file_path}
                    )
                )

        return threats

    def _check_privilege_escalation(
        self, tool_name: str, tool_args: Dict[str, Any]
    ) -> List[ThreatDetection]:
        """Check for privilege escalation attempts"""
        threats = []

        # Check for sudo/privilege escalation in commands
        if tool_name in ["bash", "shell", "execute", "command"]:
            command = tool_args.get("command", "") or tool_args.get("cmd", "")

            if re.search(r'\b(sudo|su |runas|elevate)\b', command, re.IGNORECASE):
                threats.append(
                    ThreatDetection(
                        threat_type=ThreatType.TOOL_MISUSE,
                        level=ThreatLevel.CRITICAL,
                        confidence=0.9,
                        description="Privilege escalation attempt detected",
                        evidence=f"Command contains privilege escalation: {command[:100]}",
                        mitigation="Deny privilege escalation without user confirmation",
                        metadata={"tool": tool_name}
                    )
                )

        return threats

    def _check_tool_chains(self) -> List[ThreatDetection]:
        """Check for dangerous tool usage patterns"""
        threats = []

        if len(self.tool_call_history) < 2:
            return threats

        # Get recent tool names
        recent_tools = [call.get("name", "") for call in self.tool_call_history[-10:]]

        # Check for dangerous combinations
        for tool1, tool2 in self.DANGEROUS_TOOL_CHAINS:
            if tool1 in recent_tools and tool2 in recent_tools:
                threats.append(
                    ThreatDetection(
                        threat_type=ThreatType.TOOL_MISUSE,
                        level=ThreatLevel.HIGH,
                        confidence=0.75,
                        description=f"Suspicious tool chain detected: {tool1} → {tool2}",
                        evidence=f"Recent tools: {', '.join(recent_tools[-5:])}",
                        mitigation="Review tool usage pattern for potential data exfiltration",
                        metadata={"tool_chain": [tool1, tool2]}
                    )
                )

        return threats

    def _check_resource_exhaustion(
        self, tool_calls: List[Dict[str, Any]]
    ) -> List[ThreatDetection]:
        """Check for potential resource exhaustion attacks"""
        threats = []

        # Check for excessive tool calls
        if len(tool_calls) > 50:
            threats.append(
                ThreatDetection(
                    threat_type=ThreatType.TOOL_MISUSE,
                    level=ThreatLevel.HIGH,
                    confidence=0.7,
                    description="Excessive tool usage detected",
                    evidence=f"{len(tool_calls)} tool calls in single request",
                    mitigation="Rate limit tool usage",
                    metadata={"tool_call_count": len(tool_calls)}
                )
            )

        # Check for repeated identical calls (potential loop)
        tool_signatures = [f"{t.get('name')}:{str(t.get('arguments'))}" for t in tool_calls]
        unique_calls = len(set(tool_signatures))

        if len(tool_calls) > 10 and unique_calls / len(tool_calls) < 0.3:
            threats.append(
                ThreatDetection(
                    threat_type=ThreatType.RECURSIVE_LOOP,
                    level=ThreatLevel.MEDIUM,
                    confidence=0.6,
                    description="Repetitive tool usage pattern detected",
                    evidence=f"{len(tool_calls)} calls with only {unique_calls} unique patterns",
                    mitigation="Detect and break potential infinite loops",
                    metadata={"total_calls": len(tool_calls), "unique_calls": unique_calls}
                )
            )

        return threats