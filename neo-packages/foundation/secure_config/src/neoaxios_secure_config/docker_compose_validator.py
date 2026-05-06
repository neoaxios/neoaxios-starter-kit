# Copyright 2026 NeoAxios LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Docker Compose RAM share validation for multi-app containers.

Validates that the sum of NEO_APP_RAM_SHARE_PERCENT across services
in a docker-compose.yml does not exceed 100%.

This validation should be run at deployment time before starting containers
to prevent OOM conditions in multi-app environments.

Usage:
    python -m secure_config.docker_compose_validator docker-compose.yml

    # Or programmatically:
    from neoaxios_secure_config.docker_compose_validator import validate_ram_shares
    result = validate_ram_shares("docker-compose.yml")
    if not result.valid:
        print(f"Error: {result.error}")

"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from neoaxios_logging import auto_trace, get_telemetry

logger = get_telemetry(__name__)


@dataclass
class ValidationResult:
    """Result of RAM share validation.

    Attributes:
        valid: True if validation passed.
        total_share: Sum of all RAM share percentages.
        services: Dict of service name to share percentage.
        error: Error message if validation failed.
        warning: Warning message if shares are high but valid.
    """

    valid: bool
    total_share: int
    services: dict[str, int]
    error: str | None = None
    warning: str | None = None


@auto_trace(logger)
def extract_ram_share(
    service_config: dict[str, Any], service_name: str
) -> int | None:
    """Extract NEO_APP_RAM_SHARE_PERCENT from service environment.

    Args:
        service_config: Service configuration dict from docker-compose.
        service_name: Name of the service (for error messages).

    Returns:
        Share percentage if found, None if not specified.
    """
    environment = service_config.get("environment", [])

    # Handle both list and dict formats
    if isinstance(environment, list):
        for env_var in environment:
            if isinstance(env_var, str) and env_var.startswith("NEO_APP_RAM_SHARE_PERCENT="):
                _, value = env_var.split("=", 1)
                try:
                    return int(value)
                except ValueError:
                    # Invalid value - will be handled by runtime clamping
                    return None
    elif isinstance(environment, dict):
        value = environment.get("NEO_APP_RAM_SHARE_PERCENT")
        if value is not None:
            try:
                return int(value)
            except (ValueError, TypeError):
                return None

    return None


@auto_trace(logger)
def validate_ram_shares(compose_file: str | Path) -> ValidationResult:
    """Validate RAM share percentages in docker-compose file.

    Checks that the sum of NEO_APP_RAM_SHARE_PERCENT across all services
    does not exceed 100%. This prevents over-allocation that could lead
    to OOM conditions in multi-app containers.

    Args:
        compose_file: Path to docker-compose.yml file.

    Returns:
        ValidationResult with status and details.

    Raises:
        FileNotFoundError: If compose file doesn't exist.
        yaml.YAMLError: If compose file is not valid YAML.
    """
    compose_path = Path(compose_file)

    if not compose_path.exists():
        return ValidationResult(
            valid=False,
            total_share=0,
            services={},
            error=f"File not found: {compose_path}",
        )

    try:
        content = compose_path.read_text(encoding="utf-8")
        compose_data = yaml.safe_load(content) or {}
    except yaml.YAMLError as e:
        return ValidationResult(
            valid=False,
            total_share=0,
            services={},
            error=f"Invalid YAML: {e}",
        )

    services = compose_data.get("services", {})
    if not services:
        return ValidationResult(
            valid=True,
            total_share=0,
            services={},
            warning="No services found in docker-compose file",
        )

    # Extract RAM shares from each service
    shares: dict[str, int] = {}
    for service_name, service_config in services.items():
        if not isinstance(service_config, dict):
            continue

        share = extract_ram_share(service_config, service_name)
        if share is not None:
            shares[service_name] = share

    # If no services specify RAM share, validation passes (default behavior)
    if not shares:
        return ValidationResult(
            valid=True,
            total_share=0,
            services={},
        )

    total_share = sum(shares.values())

    # Check if total exceeds 100%
    if total_share > 100:
        service_list = ", ".join(f"{name}={pct}%" for name, pct in shares.items())
        return ValidationResult(
            valid=False,
            total_share=total_share,
            services=shares,
            error=(
                f"RAM share total ({total_share}%) exceeds 100%. "
                f"Services: {service_list}. "
                "Reduce NEO_APP_RAM_SHARE_PERCENT values to prevent OOM conditions."
            ),
        )

    # Check for high usage (warning if >90%)
    warning = None
    if total_share > 90:
        warning = (
            f"RAM share total ({total_share}%) is high. "
            "Consider reducing to leave headroom for system processes."
        )

    return ValidationResult(
        valid=True,
        total_share=total_share,
        services=shares,
        warning=warning,
    )


@auto_trace(logger)
def main() -> int:
    """CLI entrypoint for docker-compose validation.

    Returns:
        0 if validation passed, 1 if validation failed.
    """
    if len(sys.argv) < 2:
        print("Usage: python -m secure_config.docker_compose_validator <compose-file>")
        print("       Validates NEO_APP_RAM_SHARE_PERCENT totals in docker-compose.yml")
        return 1

    compose_file = sys.argv[1]
    result = validate_ram_shares(compose_file)

    if result.warning:
        print(f"Warning: {result.warning}", file=sys.stderr)

    if not result.valid:
        print(f"ERROR: {result.error}", file=sys.stderr)
        return 1

    if result.services:
        print(f"RAM share validation passed. Total: {result.total_share}%")
        for service, share in result.services.items():
            print(f"  {service}: {share}%")
    else:
        print("No NEO_APP_RAM_SHARE_PERCENT settings found (using defaults)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
