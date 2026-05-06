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

"""
neoaxios-test-foundation: Shared test infrastructure for NeoAxios packages.

This package provides centralized test utilities, fixtures, mocks, and configuration
for all NeoAxios packages. It eliminates code duplication across package test suites.

Usage:
    from neoaxios_test_foundation.test_config import get_llm_model_name
    from neoaxios_test_foundation.fixtures import temp_project_dir
    from neoaxios_test_foundation.mock_llm_server import MockLLMServer
    from neoaxios_test_foundation.mock_service_endpoint import MockServiceEndpoint
    from neoaxios_test_foundation.redis_test_utils import cleanup_namespace_keys, make_test_namespace
"""

__version__ = "0.2.1"

# Tell pytest this is not a test module
__test__ = False

# Commonly used imports available at package level
from neoaxios_test_foundation.redis_cluster_utils import (
    check_cluster_available,
    create_cluster_client,
    detect_cluster_nodes,
    make_requires_redis_cluster_marker,
)
from neoaxios_test_foundation.redis_test_utils import cleanup_namespace_keys, make_test_namespace
from neoaxios_test_foundation.stats import compute_percentiles
from neoaxios_test_foundation.test_config import (
    DEFAULT_LLM_BACKEND_HOST,
    DEFAULT_LLM_BACKEND_PORT,
    DEFAULT_LLM_MODEL,
    get_llm_backend_url,
    get_llm_model_name,
)

__all__ = [
    # Version
    "__version__",
    # Test configuration
    "get_llm_model_name",
    "get_llm_backend_url",
    "DEFAULT_LLM_MODEL",
    "DEFAULT_LLM_BACKEND_HOST",
    "DEFAULT_LLM_BACKEND_PORT",
    # Statistical utilities
    "compute_percentiles",
    # Redis test utilities
    "cleanup_namespace_keys",
    "make_test_namespace",
    # Redis Cluster test utilities
    "check_cluster_available",
    "create_cluster_client",
    "detect_cluster_nodes",
    "make_requires_redis_cluster_marker",
]
