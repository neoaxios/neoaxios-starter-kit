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

"""Provider-specific token decoders.

Provider implementations for major identity providers (Okta, Auth0, Keycloak, Azure AD, etc.).
Each provider decoder extends the base OIDC decoder with provider-specific
features, claim mappings, and validation logic.

Also includes Azure AD tenant validation for multi-tenant isolation.

Usage:
    from neoaxios_fastapi_kit.auth.authn.decoders.providers import (
        OktaDecoder, Auth0Decoder, KeycloakDecoder, AzureADDecoder
    )

    # Okta decoder
    okta_decoder = OktaDecoder(
        tenant_id="dev-12345.okta.com",
        client_id="0oa2t1n3k4p5q6r7s8t9",
    )

    # Auth0 decoder
    auth0_decoder = Auth0Decoder(
        domain="myapp.us.auth0.com",
        client_id="abc123def456",
    )

    # Keycloak decoder
    keycloak_decoder = KeycloakDecoder(
        realm_name="myrealm",
        issuer="https://keycloak.example.com/realms/myrealm",
        client_id="my-client-id",
    )

    # Azure AD decoder (supports both user and app-only tokens)
    azure_decoder = AzureADDecoder(
        tenant_id="00000000-0000-0000-0000-000000000000",
        client_id="11111111-1111-1111-1111-111111111111",
    )

    identity = await decoder.decode(token)

    # Azure AD tenant validation for multi-tenant isolation
    from neoaxios_fastapi_kit.auth.authn.decoders.providers import (
        TenantResolver,
        TenantMode,
        create_single_tenant_resolver,
        create_multi_tenant_resolver,
    )

    # Single-tenant configuration (most secure)
    resolver = create_single_tenant_resolver(
        tenant_id="550e8400-e29b-41d4-a716-446655440000"
    )

    # Multi-tenant configuration with allowed tenants list
    resolver = create_multi_tenant_resolver(
        primary_tenant_id="550e8400-e29b-41d4-a716-446655440000",
        allowed_tenants=frozenset({
            "550e8400-e29b-41d4-a716-446655440000",
            "660e8400-e29b-41d4-a716-446655440000",
        }),
    )

    # Validate tenant from token claims (after signature verification)
    tenant_id = resolver.validate_token_tenant_claims(claims)
"""

from neoaxios_fastapi_kit.auth.authn.decoders.providers.okta import (
    OktaDecoder,
    create_okta_decoder,
)
from neoaxios_fastapi_kit.auth.authn.decoders.providers.auth0 import (
    Auth0Decoder,
    create_auth0_decoder,
)
from neoaxios_fastapi_kit.auth.authn.decoders.providers.keycloak import (
    KeycloakDecoder,
    create_keycloak_decoder,
)
from neoaxios_fastapi_kit.auth.authn.decoders.providers.azure import (
    AzureADDecoder,
    create_azure_ad_decoder,
    create_azure_decoder,
    TenantValidationError as AzureTenantValidationError,
    RoleEnrichmentStore,
    GraphAPIEnrichmentConfig,
)
from neoaxios_fastapi_kit.auth.authn.decoders.providers.azure_mapper import (
    AzureTokenMapper,
    create_azure_token_mapper,
    DIRECTORY_ROLE_MAPPINGS,
)
from neoaxios_fastapi_kit.auth.authn.decoders.providers.azure_graph import (
    GraphAPIClient,
    GraphAPIError,
    GraphAPIAuthenticationError,
    GraphAPIRateLimitError,
    GraphAPINotFoundError,
    create_graph_api_client,
)
from neoaxios_fastapi_kit.auth.authn.decoders.providers.azure_tenant import (
    TenantResolver,
    TenantConfig,
    TenantMode,
    TenantValidationError,
    TenantExtractionError,
    create_single_tenant_resolver,
    create_multi_tenant_resolver,
    TENANT_COMMON,
    TENANT_ORGANIZATIONS,
    TENANT_CONSUMERS,
    SPECIAL_TENANT_VALUES,
    DEFAULT_TENANT_ID_CLAIM,
    DEFAULT_APP_ID_CLAIM,
    DEFAULT_CLIENT_ID_CLAIM,
)

__all__ = [
    # Okta
    "OktaDecoder",
    "create_okta_decoder",
    # Auth0
    "Auth0Decoder",
    "create_auth0_decoder",
    # Keycloak
    "KeycloakDecoder",
    "create_keycloak_decoder",
    # Azure AD decoder
    "AzureADDecoder",
    "create_azure_ad_decoder",
    "create_azure_decoder",
    "AzureTenantValidationError",
    "RoleEnrichmentStore",
    "GraphAPIEnrichmentConfig",
    # Azure AD token mapper
    "AzureTokenMapper",
    "create_azure_token_mapper",
    "DIRECTORY_ROLE_MAPPINGS",
    # Azure AD Graph API client
    "GraphAPIClient",
    "GraphAPIError",
    "GraphAPIAuthenticationError",
    "GraphAPIRateLimitError",
    "GraphAPINotFoundError",
    "create_graph_api_client",
    # Azure AD tenant validation
    "TenantResolver",
    "TenantConfig",
    "TenantMode",
    "TenantValidationError",
    "TenantExtractionError",
    "create_single_tenant_resolver",
    "create_multi_tenant_resolver",
    "TENANT_COMMON",
    "TENANT_ORGANIZATIONS",
    "TENANT_CONSUMERS",
    "SPECIAL_TENANT_VALUES",
    "DEFAULT_TENANT_ID_CLAIM",
    "DEFAULT_APP_ID_CLAIM",
    "DEFAULT_CLIENT_ID_CLAIM",
]
