"""Configuration management for security guard"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class DetectorSettings(BaseModel):
    """Settings for individual detector"""

    enabled: bool = True
    threshold: float = Field(default=0.7, ge=0.0, le=1.0)
    custom_patterns: List[str] = Field(default_factory=list)
    config: Dict[str, Any] = Field(default_factory=dict)


class SecurityConfig(BaseModel):
    """Main security configuration"""

    # Global settings
    safe_threshold: float = Field(default=0.7, ge=0.0, le=1.0)
    phoenix_enabled: bool = True
    phoenix_project: Optional[str] = None
    phoenix_endpoint: str = "http://localhost:6006"

    # Detector configurations
    detectors: Dict[str, DetectorSettings] = Field(
        default_factory=lambda: {
            "prompt_injection": DetectorSettings(enabled=True, threshold=0.7),
            "pii": DetectorSettings(enabled=True, threshold=0.8),
            "toxicity": DetectorSettings(enabled=True, threshold=0.8),
            "data_exfiltration": DetectorSettings(enabled=True, threshold=0.75),
            "tool_misuse": DetectorSettings(enabled=True, threshold=0.8),
            "goal_hijacking": DetectorSettings(enabled=True, threshold=0.7),
            "recursive_loop": DetectorSettings(enabled=True, threshold=0.7),
        }
    )

    # Logging settings
    log_level: str = "INFO"
    log_threats_to_file: bool = False
    log_file_path: Optional[str] = None

    # Response actions
    block_on_critical: bool = True
    block_on_high: bool = False
    require_approval_threshold: float = 0.5

    # Rate limiting
    max_evaluations_per_minute: Optional[int] = None
    max_evaluations_per_hour: Optional[int] = None


def load_config(config_path: Optional[Path] = None) -> SecurityConfig:
    """
    Load security configuration from file

    Args:
        config_path: Path to config file (JSON or YAML)

    Returns:
        SecurityConfig instance
    """
    if config_path is None:
        # Return default config
        return SecurityConfig()

    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    # Load based on file extension
    if config_path.suffix == ".json":
        with open(config_path, "r") as f:
            config_data = json.load(f)
    elif config_path.suffix in [".yaml", ".yml"]:
        try:
            import yaml

            with open(config_path, "r") as f:
                config_data = yaml.safe_load(f)
        except ImportError:
            raise ImportError("PyYAML required for YAML configs: pip install pyyaml")
    else:
        raise ValueError(f"Unsupported config file format: {config_path.suffix}")

    return SecurityConfig(**config_data)


def save_config(config: SecurityConfig, config_path: Path) -> None:
    """
    Save security configuration to file

    Args:
        config: SecurityConfig instance
        config_path: Path to save config file
    """
    config_data = config.model_dump()

    if config_path.suffix == ".json":
        with open(config_path, "w") as f:
            json.dump(config_data, f, indent=2)
    elif config_path.suffix in [".yaml", ".yml"]:
        try:
            import yaml

            with open(config_path, "w") as f:
                yaml.dump(config_data, f, default_flow_style=False)
        except ImportError:
            raise ImportError("PyYAML required for YAML configs: pip install pyyaml")
    else:
        raise ValueError(f"Unsupported config file format: {config_path.suffix}")