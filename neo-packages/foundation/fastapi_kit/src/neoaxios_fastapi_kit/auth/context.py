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

"""Identity context for authorization framework.

Defines the immutable identity context that represents an authenticated user
across the authorization framework. Used by all resolvers, decoders, and
authorization checks.

Implemented as a Pydantic BaseModel with frozen=True to ensure:
- Immutability across async operations
- Compatibility with FastAPI/Pydantic v2 validation
- Automatic serialization/deserialization support

Usage:
    from neoaxios_fastapi_kit.auth.context import IdentityContext

    identity = IdentityContext(
        user_id="550e8400-e29b-41d4-a716-446655440000",
        tenant_id="660e8400-e29b-41d4-a716-446655440000",
        roles=frozenset({"admin", "user"}),
        permissions=frozenset({"document:read", "document:write"}),
    )
"""

from typing import Any, Dict, FrozenSet, Optional
from pydantic import BaseModel, ConfigDict


class IdentityContext(BaseModel):
    """Immutable identity context for the current request.

    Pydantic BaseModel with frozen=True ensures immutability across async operations
    while maintaining full compatibility with FastAPI and Pydantic v2 validation.
    Supports serialization to/from JSON and other formats.

    Attributes:
        user_id: Unique identifier for the user (UUID format recommended)
        tenant_id: Unique identifier for the user's tenant (UUID format recommended)
        roles: Set of role names assigned to the user
        permissions: Set of permissions in "resource:action" format
        attributes: Additional ABAC attributes (department, clearance, etc.)
        impersonator_id: User ID of the admin performing impersonation, if any
        provider: Identity provider name ("local", "azure", "aws", "google")
        issuer: Token issuer URL for verification (from JWT iss claim)
        provider_user_id: Original user ID from provider (before mapping to local user_id)
    """

    model_config = ConfigDict(frozen=True)

    user_id: str
    tenant_id: str
    roles: FrozenSet[str] = frozenset()
    permissions: FrozenSet[str] = frozenset()
    attributes: Dict[str, Any] = {}
    impersonator_id: Optional[str] = None
    provider: str = "local"
    issuer: Optional[str] = None
    provider_user_id: Optional[str] = None
