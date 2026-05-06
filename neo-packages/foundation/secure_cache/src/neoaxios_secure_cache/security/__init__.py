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

"""Security layer implementations.

This module provides security wrappers and components:
- SigningCacheWrapper: HMAC-SHA256 integrity verification
- EncryptingCacheWrapper: AES-256-GCM encryption with per-tenant keys
- KeyDerivation: HKDF-based key derivation
- TenantKeyCache: LRU cache for derived keys
- SequenceTracker: Replay protection via sequence numbers
- CanaryMonitor: Background integrity checking
- TamperDetectionState: Tamper detection state tracker
- Sensitive permission detection

All wrappers implement the CacheBackend protocol for composition.
"""

# Sensitive permission detection
from neoaxios_secure_cache.security.sensitive import (
    get_sensitive_patterns,
    is_sensitive_permission,
    register_sensitive_pattern,
    unregister_sensitive_pattern,
)

# Security wrappers and components
from neoaxios_secure_cache.security.signing import SigningCacheWrapper, create_signing_wrapper
from neoaxios_secure_cache.security.encryption import EncryptingCacheWrapper, create_encrypting_wrapper
from neoaxios_secure_cache.security.keys import (
    TenantKeyCache,
    create_tenant_key_cache,
    derive_kek,
    derive_signing_key,
    derive_tenant_key,
)
from neoaxios_secure_cache.security.sequence import SequenceTracker, create_sequence_tracker
from neoaxios_secure_cache.security.canary import CanaryMonitor, create_canary_monitor
from neoaxios_secure_cache.security.tamper_detection import TamperDetectionState, create_tamper_detection_state

__all__ = [
    # Sensitive permission detection
    "is_sensitive_permission",
    "register_sensitive_pattern",
    "unregister_sensitive_pattern",
    "get_sensitive_patterns",
    # Security wrappers
    "SigningCacheWrapper",
    "create_signing_wrapper",
    "EncryptingCacheWrapper",
    "create_encrypting_wrapper",
    # Key management
    "TenantKeyCache",
    "create_tenant_key_cache",
    "derive_signing_key",
    "derive_kek",
    "derive_tenant_key",
    # Replay protection
    "SequenceTracker",
    "create_sequence_tracker",
    # Integrity monitoring
    "CanaryMonitor",
    "create_canary_monitor",
    # Tamper detection
    "TamperDetectionState",
    "create_tamper_detection_state",
]
