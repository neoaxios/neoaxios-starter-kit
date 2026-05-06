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

"""Runtime resource detection for worker auto-configuration.

Detects CPU and RAM at import time and populates NEO_SYSTEM_* environment
variables. Applications use these values to auto-configure worker counts.
Also provides GPU (CUDA) detection via ``detect_gpu()`` for packages that
optionally accelerate computation on NVIDIA GPUs.

Detection happens once at module import. Uses setdefault() for all env var
population, allowing container orchestration to override detected values.

Environment Variables Set:
    NEO_SYSTEM_CPU_LOGICAL_COUNT: Logical CPUs (threads) for I/O-bound workers
    NEO_SYSTEM_CPU_PHYSICAL_COUNT: Physical cores for CPU-bound workers
    NEO_SYSTEM_RAM_TOTAL_GB: Total physical RAM
    NEO_SYSTEM_RAM_AVAILABLE_GB: Available physical RAM at startup

Override Environment Variables:
    NEO_SYSTEM_CPU_LOGICAL_COUNT_OVERRIDE: Override detected logical CPU count
    NEO_SYSTEM_CPU_PHYSICAL_COUNT_OVERRIDE: Override detected physical CPU count
    NEO_SYSTEM_RAM_TOTAL_GB_OVERRIDE: Override detected total RAM
    NEO_SYSTEM_RAM_AVAILABLE_GB_OVERRIDE: Override detected available RAM

App Budget Environment Variables:
    NEO_APP_RAM_BUDGET_PERCENT: Percent of available RAM usable (default: 70)
    NEO_APP_RAM_SHARE_PERCENT: This app's share of RAM budget (default: 100)
    NEO_APP_WORKER_MEMORY_MB: Estimated per-worker RAM in MB (default: 150)
    NEO_APP_RAM_BUDGET_GB: Calculated RAM budget (available × budget% × share%)
    NEO_APP_RECOMMENDED_WORKERS: Calculated workers (max(1, min(cpu, budget/worker_mem)))

"""

from __future__ import annotations

import os
from dataclasses import dataclass

# Clamping constants
MIN_CPU_COUNT = 1
MAX_CPU_COUNT = 256
MIN_RAM_GB = 0.1
MAX_RAM_GB = 1024.0
MIN_PERCENT = 1
MAX_PERCENT = 100
MIN_WORKERS = 1
MAX_WORKERS = 256

# Fallback defaults when psutil unavailable
FALLBACK_CPU_LOGICAL = 1
FALLBACK_CPU_PHYSICAL = 1
FALLBACK_RAM_TOTAL_GB = 1.0
FALLBACK_RAM_AVAILABLE_GB = 1.0

# App budget defaults
DEFAULT_RAM_BUDGET_PERCENT = 70  # Reserve 30% for OS and other processes
DEFAULT_RAM_SHARE_PERCENT = 100  # Single app gets full budget
DEFAULT_WORKER_MEMORY_MB = 150   # FastAPI+Gunicorn worker footprint

# Detection state
_detected = False
_budget_calculated = False


@dataclass(frozen=True)
class SystemResources:
    """Detected system resources (immutable snapshot).

    Attributes:
        cpu_logical_count: Logical CPUs (threads) for I/O-bound workers.
        cpu_physical_count: Physical CPU cores for CPU-bound workers.
        ram_total_gb: Total physical RAM in GB (not swap).
        ram_available_gb: Available physical RAM in GB at detection time.
    """

    cpu_logical_count: int
    cpu_physical_count: int
    ram_total_gb: float
    ram_available_gb: float


# notrace: pre-telemetry bootstrap module, circular import prevents telemetry instrumentation
def _clamp(value: float | int, min_val: float | int, max_val: float | int) -> float | int:
    """Clamp value to [min_val, max_val] range."""
    return max(min_val, min(max_val, value))


# notrace: pre-telemetry bootstrap module, circular import prevents telemetry instrumentation
def _parse_int_override(env_var: str, min_val: int, max_val: int) -> int | None:
    """Parse integer override from environment variable.

    Returns None if not set or invalid (with warning to stderr).
    """
    value = os.environ.get(env_var)
    if value is None:
        return None
    try:
        parsed = int(value)
        clamped = _clamp(parsed, min_val, max_val)
        if clamped != parsed:
            # Log to stderr since we can't use telemetry (circular import)
            import sys

            print(
                f"Warning: {env_var}={parsed} clamped to {clamped} (valid range: [{min_val}, {max_val}])",
                file=sys.stderr,
            )
        return clamped
    except ValueError:
        import sys

        print(
            f"Warning: Invalid {env_var}={value!r}, ignoring override",
            file=sys.stderr,
        )
        return None


# notrace: pre-telemetry bootstrap module, circular import prevents telemetry instrumentation
def _parse_float_override(env_var: str, min_val: float, max_val: float) -> float | None:
    """Parse float override from environment variable.

    Returns None if not set or invalid (with warning to stderr).
    """
    value = os.environ.get(env_var)
    if value is None:
        return None
    try:
        parsed = float(value)
        clamped = _clamp(parsed, min_val, max_val)
        if abs(clamped - parsed) > 0.001:
            import sys

            print(
                f"Warning: {env_var}={parsed} clamped to {clamped} (valid range: [{min_val}, {max_val}])",
                file=sys.stderr,
            )
        return clamped
    except ValueError:
        import sys

        print(
            f"Warning: Invalid {env_var}={value!r}, ignoring override",
            file=sys.stderr,
        )
        return None


# notrace: pre-telemetry bootstrap module, circular import prevents telemetry instrumentation
def _detect_resources() -> SystemResources:
    """Detect system resources using psutil with fallbacks.

    Checks for override env vars first, then detects via psutil,
    falling back to safe defaults if psutil is unavailable.

    Returns:
        SystemResources with detected or overridden values.
    """
    # Check overrides first
    cpu_logical_override = _parse_int_override(
        "NEO_SYSTEM_CPU_LOGICAL_COUNT_OVERRIDE", MIN_CPU_COUNT, MAX_CPU_COUNT
    )
    cpu_physical_override = _parse_int_override(
        "NEO_SYSTEM_CPU_PHYSICAL_COUNT_OVERRIDE", MIN_CPU_COUNT, MAX_CPU_COUNT
    )
    ram_total_override = _parse_float_override(
        "NEO_SYSTEM_RAM_TOTAL_GB_OVERRIDE", MIN_RAM_GB, MAX_RAM_GB
    )
    ram_available_override = _parse_float_override(
        "NEO_SYSTEM_RAM_AVAILABLE_GB_OVERRIDE", MIN_RAM_GB, MAX_RAM_GB
    )

    # Detect via psutil if needed
    cpu_logical = cpu_logical_override
    cpu_physical = cpu_physical_override
    ram_total_gb = ram_total_override
    ram_available_gb = ram_available_override

    if any(v is None for v in [cpu_logical, cpu_physical, ram_total_gb, ram_available_gb]):
        try:
            import psutil

            if cpu_logical is None:
                detected = psutil.cpu_count(logical=True)
                cpu_logical = _clamp(detected or FALLBACK_CPU_LOGICAL, MIN_CPU_COUNT, MAX_CPU_COUNT)

            if cpu_physical is None:
                detected = psutil.cpu_count(logical=False)
                cpu_physical = _clamp(detected or FALLBACK_CPU_PHYSICAL, MIN_CPU_COUNT, MAX_CPU_COUNT)

            if ram_total_gb is None or ram_available_gb is None:
                mem = psutil.virtual_memory()
                if ram_total_gb is None:
                    ram_total_gb = _clamp(mem.total / (1024**3), MIN_RAM_GB, MAX_RAM_GB)
                if ram_available_gb is None:
                    ram_available_gb = _clamp(mem.available / (1024**3), MIN_RAM_GB, MAX_RAM_GB)

        except ImportError:
            import sys

            print(
                "Warning: psutil not available, using fallback values for resource detection",
                file=sys.stderr,
            )
            cpu_logical = cpu_logical or FALLBACK_CPU_LOGICAL
            cpu_physical = cpu_physical or FALLBACK_CPU_PHYSICAL
            ram_total_gb = ram_total_gb or FALLBACK_RAM_TOTAL_GB
            ram_available_gb = ram_available_gb or FALLBACK_RAM_AVAILABLE_GB

    # Ensure physical <= logical (sanity check)
    if cpu_physical > cpu_logical:
        cpu_physical = cpu_logical

    # Ensure available <= total (sanity check)
    if ram_available_gb > ram_total_gb:
        ram_available_gb = ram_total_gb

    return SystemResources(
        cpu_logical_count=cpu_logical,
        cpu_physical_count=cpu_physical,
        ram_total_gb=round(ram_total_gb, 2),
        ram_available_gb=round(ram_available_gb, 2),
    )


# notrace: pre-telemetry bootstrap module, circular import prevents telemetry instrumentation
def _detect_once() -> None:
    """Detect system resources and set NEO_SYSTEM_* env vars.

    Called once at module import. Only sets vars if not already set,
    allowing container orchestration to override by pre-setting env vars.
    """
    global _detected
    if _detected:
        return

    # Skip if already detected (externally set)
    if os.environ.get("NEO_SYSTEM_CPU_LOGICAL_COUNT"):
        _detected = True
        return

    resources = _detect_resources()

    # Set env vars using setdefault (allows pre-set overrides)
    os.environ.setdefault("NEO_SYSTEM_CPU_LOGICAL_COUNT", str(resources.cpu_logical_count))
    os.environ.setdefault("NEO_SYSTEM_CPU_PHYSICAL_COUNT", str(resources.cpu_physical_count))
    os.environ.setdefault("NEO_SYSTEM_RAM_TOTAL_GB", str(resources.ram_total_gb))
    os.environ.setdefault("NEO_SYSTEM_RAM_AVAILABLE_GB", str(resources.ram_available_gb))

    _detected = True


# notrace: pre-telemetry bootstrap module, circular import prevents telemetry instrumentation
def detect_system_resources() -> SystemResources:
    """Return detected or overridden system resources.

    Ensures detection has run, then returns current values from env vars.

    Returns:
        SystemResources with current detected/overridden values.
    """
    _detect_once()

    return SystemResources(
        cpu_logical_count=int(os.environ.get("NEO_SYSTEM_CPU_LOGICAL_COUNT", FALLBACK_CPU_LOGICAL)),
        cpu_physical_count=int(os.environ.get("NEO_SYSTEM_CPU_PHYSICAL_COUNT", FALLBACK_CPU_PHYSICAL)),
        ram_total_gb=float(os.environ.get("NEO_SYSTEM_RAM_TOTAL_GB", FALLBACK_RAM_TOTAL_GB)),
        ram_available_gb=float(os.environ.get("NEO_SYSTEM_RAM_AVAILABLE_GB", FALLBACK_RAM_AVAILABLE_GB)),
    )


# notrace: pre-telemetry bootstrap module, circular import prevents telemetry instrumentation
def get_cpu_logical_count() -> int:
    """Get detected logical CPU count (threads).

    Returns:
        Number of logical CPUs for I/O-bound worker configuration.
    """
    _detect_once()
    return int(os.environ.get("NEO_SYSTEM_CPU_LOGICAL_COUNT", FALLBACK_CPU_LOGICAL))


# notrace: pre-telemetry bootstrap module, circular import prevents telemetry instrumentation
def get_cpu_physical_count() -> int:
    """Get detected physical CPU count (cores).

    Returns:
        Number of physical CPU cores for CPU-bound worker configuration.
    """
    _detect_once()
    return int(os.environ.get("NEO_SYSTEM_CPU_PHYSICAL_COUNT", FALLBACK_CPU_PHYSICAL))


# notrace: pre-telemetry bootstrap module, circular import prevents telemetry instrumentation
def get_ram_total_gb() -> float:
    """Get detected total RAM in GB.

    Returns:
        Total physical RAM in GB.
    """
    _detect_once()
    return float(os.environ.get("NEO_SYSTEM_RAM_TOTAL_GB", FALLBACK_RAM_TOTAL_GB))


# notrace: pre-telemetry bootstrap module, circular import prevents telemetry instrumentation
def get_ram_available_gb() -> float:
    """Get detected available RAM in GB.

    Returns:
        Available physical RAM in GB at detection time.
    """
    _detect_once()
    return float(os.environ.get("NEO_SYSTEM_RAM_AVAILABLE_GB", FALLBACK_RAM_AVAILABLE_GB))


# =============================================================================
# App Budget Calculation (T-2)
# =============================================================================


# notrace: pre-telemetry bootstrap module, circular import prevents telemetry instrumentation
def calculate_app_budget() -> float:
    """Calculate this app's RAM budget based on budget% and share%.

    Formula: available_ram × (budget_percent / 100) × (share_percent / 100)

    Reads from environment variables:
        NEO_APP_RAM_BUDGET_PERCENT: Percent of available RAM usable (default: 70)
        NEO_APP_RAM_SHARE_PERCENT: This app's share of budget (default: 100)

    Sets environment variable:
        NEO_APP_RAM_BUDGET_GB: Calculated RAM budget in GB

    Returns:
        RAM budget in GB.
    """
    _detect_once()

    # Get configuration from env vars with defaults
    budget_percent_str = os.environ.get("NEO_APP_RAM_BUDGET_PERCENT")
    share_percent_str = os.environ.get("NEO_APP_RAM_SHARE_PERCENT")

    # Parse and clamp percentages
    if budget_percent_str is not None:
        budget_percent = _parse_int_override(
            "NEO_APP_RAM_BUDGET_PERCENT", MIN_PERCENT, MAX_PERCENT
        )
        if budget_percent is None:
            budget_percent = DEFAULT_RAM_BUDGET_PERCENT
    else:
        budget_percent = DEFAULT_RAM_BUDGET_PERCENT
        os.environ.setdefault("NEO_APP_RAM_BUDGET_PERCENT", str(budget_percent))

    if share_percent_str is not None:
        share_percent = _parse_int_override(
            "NEO_APP_RAM_SHARE_PERCENT", MIN_PERCENT, MAX_PERCENT
        )
        if share_percent is None:
            share_percent = DEFAULT_RAM_SHARE_PERCENT
    else:
        share_percent = DEFAULT_RAM_SHARE_PERCENT
        os.environ.setdefault("NEO_APP_RAM_SHARE_PERCENT", str(share_percent))

    # Calculate budget
    available_gb = get_ram_available_gb()
    budget_gb = available_gb * (budget_percent / 100) * (share_percent / 100)
    budget_gb = round(max(MIN_RAM_GB, budget_gb), 2)

    # Set result env var
    os.environ["NEO_APP_RAM_BUDGET_GB"] = str(budget_gb)

    return budget_gb


# notrace: pre-telemetry bootstrap module, circular import prevents telemetry instrumentation
def calculate_recommended_workers(worker_memory_mb: int | None = None) -> int:
    """Calculate recommended workers based on physical CPU cores and RAM budget.

    Formula: max(1, min(cpu_physical_count, ram_budget_gb / worker_memory_gb))

    Args:
        worker_memory_mb: Override default worker memory estimate (default: 150 MB).

    Reads from environment variables:
        NEO_APP_WORKER_MEMORY_MB: Estimated per-worker RAM in MB (default: 150)
        NEO_APP_RAM_BUDGET_GB: RAM budget (calculated if not set)
        NEO_SYSTEM_CPU_PHYSICAL_COUNT: Physical CPU core count

    Sets environment variable:
        NEO_APP_RECOMMENDED_WORKERS: Calculated worker count

    Returns:
        Recommended worker count (always >= 1).
    """
    global _budget_calculated

    _detect_once()

    # Ensure budget is calculated
    if not os.environ.get("NEO_APP_RAM_BUDGET_GB"):
        calculate_app_budget()

    # Get worker memory from param, env var, or default
    if worker_memory_mb is not None:
        worker_mem_mb = int(_clamp(worker_memory_mb, 1, 10000))
    else:
        worker_mem_str = os.environ.get("NEO_APP_WORKER_MEMORY_MB")
        if worker_mem_str is not None:
            try:
                worker_mem_mb = int(_clamp(int(worker_mem_str), 1, 10000))
            except ValueError:
                import sys
                print(
                    f"Warning: Invalid NEO_APP_WORKER_MEMORY_MB={worker_mem_str!r}, using default",
                    file=sys.stderr,
                )
                worker_mem_mb = DEFAULT_WORKER_MEMORY_MB
        else:
            worker_mem_mb = DEFAULT_WORKER_MEMORY_MB
            os.environ.setdefault("NEO_APP_WORKER_MEMORY_MB", str(worker_mem_mb))

    # Get budget and CPU count — use physical cores, not logical threads.
    # Each gunicorn/uvicorn worker is a full Python process; hyperthreading
    # gives no benefit due to the GIL, so sizing beyond physical cores
    # wastes RAM and increases context-switch overhead.
    budget_gb = float(os.environ.get("NEO_APP_RAM_BUDGET_GB", "1.0"))
    cpu_physical = get_cpu_physical_count()

    # Calculate workers: max(1, min(cores, budget / worker_mem))
    worker_memory_gb = worker_mem_mb / 1024
    ram_based_workers = int(budget_gb / worker_memory_gb) if worker_memory_gb > 0 else 1
    workers = max(MIN_WORKERS, min(cpu_physical, ram_based_workers))
    workers = int(_clamp(workers, MIN_WORKERS, MAX_WORKERS))

    # Set result env var
    os.environ["NEO_APP_RECOMMENDED_WORKERS"] = str(workers)
    _budget_calculated = True

    return workers


# notrace: pre-telemetry bootstrap module, circular import prevents telemetry instrumentation
def get_recommended_workers() -> int:
    """Get previously calculated recommended workers.

    Returns:
        Recommended worker count.

    Raises:
        RuntimeError: If calculate_recommended_workers() was not called.
    """
    workers_str = os.environ.get("NEO_APP_RECOMMENDED_WORKERS")
    if workers_str is None:
        raise RuntimeError(
            "NEO_APP_RECOMMENDED_WORKERS not set. "
            "Call calculate_recommended_workers() first."
        )
    return int(workers_str)


# notrace: pre-telemetry bootstrap module, circular import prevents telemetry instrumentation
def get_app_ram_budget_gb() -> float:
    """Get calculated app RAM budget in GB.

    Returns:
        RAM budget in GB.

    Raises:
        RuntimeError: If calculate_app_budget() was not called.
    """
    budget_str = os.environ.get("NEO_APP_RAM_BUDGET_GB")
    if budget_str is None:
        raise RuntimeError(
            "NEO_APP_RAM_BUDGET_GB not set. "
            "Call calculate_app_budget() first."
        )
    return float(budget_str)


# =============================================================================
# Startup Logging (T-3)
# =============================================================================


# notrace: pre-telemetry bootstrap module, circular import prevents telemetry instrumentation
def log_system_resources(logger: object | None = None) -> dict:
    """Log detected system resources.

    Logs the `system_resources_detected` event with all detected values.
    If no logger is provided, returns the data dict for caller to log.

    Args:
        logger: Optional logger with .info() method. If None, returns data only.

    Returns:
        Dict with detected resource values for logging.
    """
    _detect_once()

    data = {
        "cpu_logical_count": get_cpu_logical_count(),
        "cpu_physical_count": get_cpu_physical_count(),
        "ram_total_gb": get_ram_total_gb(),
        "ram_available_gb": get_ram_available_gb(),
    }

    if logger is not None and hasattr(logger, "info"):
        logger.info("system_resources_detected", **data)

    return data


# notrace: pre-telemetry bootstrap module, circular import prevents telemetry instrumentation
def log_app_budget(logger: object | None = None) -> dict:
    """Log calculated app budget and recommended workers.

    Logs the `app_budget_calculated` event with all calculated values.
    If no logger is provided, returns the data dict for caller to log.

    Args:
        logger: Optional logger with .info() method. If None, returns data only.

    Returns:
        Dict with calculated budget values for logging.
    """
    # Ensure calculations are done
    if not os.environ.get("NEO_APP_RECOMMENDED_WORKERS"):
        calculate_recommended_workers()

    data = {
        "ram_budget_percent": int(os.environ.get("NEO_APP_RAM_BUDGET_PERCENT", DEFAULT_RAM_BUDGET_PERCENT)),
        "ram_share_percent": int(os.environ.get("NEO_APP_RAM_SHARE_PERCENT", DEFAULT_RAM_SHARE_PERCENT)),
        "ram_budget_gb": float(os.environ.get("NEO_APP_RAM_BUDGET_GB", "0")),
        "worker_memory_mb": int(os.environ.get("NEO_APP_WORKER_MEMORY_MB", DEFAULT_WORKER_MEMORY_MB)),
        "recommended_workers": int(os.environ.get("NEO_APP_RECOMMENDED_WORKERS", "1")),
    }

    if logger is not None and hasattr(logger, "info"):
        logger.info("app_budget_calculated", **data)

    return data


# notrace: pre-telemetry bootstrap module, circular import prevents telemetry instrumentation
def log_runtime_detection(logger: object | None = None) -> tuple[dict, dict]:
    """Log both system resources and app budget in one call.

    Convenience function that logs both events. Call after calculate_recommended_workers().

    Args:
        logger: Optional logger with .info() method. If None, returns data only.

    Returns:
        Tuple of (system_resources_data, app_budget_data) dicts.
    """
    system_data = log_system_resources(logger)
    budget_data = log_app_budget(logger)
    return system_data, budget_data


# =============================================================================
# GPU Detection (T-4)
# =============================================================================


@dataclass(frozen=True)
class GpuStatus:
    """Detected GPU status (immutable snapshot).

    When ``available`` is True, ``device``, ``cuda_version``, and ``device_name``
    are populated. When ``available`` is False, ``reason`` explains why.

    Attributes:
        available: Whether a CUDA-compatible GPU was detected.
        device: PyTorch device string ("cuda" or "cpu").
        device_name: NVIDIA GPU model name (e.g. "NVIDIA A100"), or None.
        cuda_version: CUDA toolkit version string (e.g. "12.1"), or None.
        reason: Human-readable reason when GPU is unavailable, or None.
    """

    available: bool
    device: str
    device_name: str | None = None
    cuda_version: str | None = None
    reason: str | None = None


# Module-level cache for GPU detection result
_gpu_status: GpuStatus | None = None


# notrace: pre-telemetry bootstrap module, circular import prevents telemetry instrumentation
def detect_gpu() -> GpuStatus:
    """Detect GPU availability via PyTorch CUDA.

    Returns a cached ``GpuStatus`` with device details when a CUDA-compatible
    GPU is present, or an explanation when unavailable.  The result is cached
    for the process lifetime.

    Returns:
        GpuStatus with detection results.
    """
    global _gpu_status
    if _gpu_status is not None:
        return _gpu_status

    try:
        import torch

        if torch.cuda.is_available():
            _gpu_status = GpuStatus(
                available=True,
                device="cuda",
                device_name=torch.cuda.get_device_name(0),
                cuda_version=torch.version.cuda,
            )
        else:
            _gpu_status = GpuStatus(
                available=False,
                device="cpu",
                reason="No CUDA-compatible GPU detected",
            )
    except ImportError:
        _gpu_status = GpuStatus(
            available=False,
            device="cpu",
            reason="PyTorch not installed",
        )
    except RuntimeError as exc:
        _gpu_status = GpuStatus(
            available=False,
            device="cpu",
            reason=f"CUDA runtime error: {exc}",
        )
    except Exception as exc:
        _gpu_status = GpuStatus(
            available=False,
            device="cpu",
            reason=f"GPU detection failed: {exc}",
        )

    return _gpu_status


# Run detection at import time
_detect_once()
