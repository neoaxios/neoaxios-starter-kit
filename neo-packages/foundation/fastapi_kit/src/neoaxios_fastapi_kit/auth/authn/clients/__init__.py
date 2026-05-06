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

"""Authentication client implementations.

Provides HTTP clients for external identity provider APIs including
Microsoft Graph API for Azure AD token introspection and user info.

Usage:
    from neoaxios_fastapi_kit.auth.authn.clients import GraphAPIClient, create_graph_api_client

    # Create client with Azure AD credentials
    client = create_graph_api_client(
        tenant_id="550e8400-e29b-41d4-a716-446655440000",
        client_id="my-client-id",
        client_secret="my-client-secret",
    )

    # Introspect a token to get user information
    user_info = await client.introspect_token(access_token)
    logger.info(f"User: {user_info.get('displayName')}")

    # Cleanup
    await client.close()
"""

# Re-export from canonical location to avoid code duplication
from neoaxios_fastapi_kit.auth.authn.decoders.providers.azure_graph import (
    GraphAPIClient,
    GraphAPIConfig,
    GraphAPIError,
    create_graph_api_client,
)

__all__ = [
    "GraphAPIClient",
    "GraphAPIConfig",
    "GraphAPIError",
    "create_graph_api_client",
]
