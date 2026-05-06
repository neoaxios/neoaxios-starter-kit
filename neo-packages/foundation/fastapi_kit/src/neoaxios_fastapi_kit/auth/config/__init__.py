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

"""Configuration system for identity provider decoders.

Provides Pydantic-based configuration schemas and loaders for all supported
identity providers. Supports YAML files, environment variables, and secrets
management.

Supported Providers:
- JWT: Generic JWT token decoder
- OIDC: Generic OpenID Connect provider
- Azure AD: Microsoft Azure Active Directory (comprehensive configuration)
- Cognito: AWS Cognito
- Google: Google IAM
- Okta: Okta identity provider
- Auth0: Auth0 identity provider
- Keycloak: Keycloak identity provider

Azure AD Configuration:
    The AzureConfig class provides comprehensive Azure AD configuration with
    support for Graph API integration, multi-tenant applications, and flexible
    role mapping. Key features:

    - SecretStr for client_secret (prevents accidental logging)
    - GUID validation for tenant_id and client_id
    - Automatic authority_url construction
    - Nested configurations: GraphAPIConfig, MultiTenantConfig, RolesMappingConfig
    - Hierarchical configuration discovery

Usage:
    from neoaxios_fastapi_kit.auth.config import (
        DecoderConfig,
        AzureConfig,
        load_config_from_yaml,
        load_config_from_env,
    )

    # Load from YAML
    config = load_config_from_yaml("/etc/auth/config.yaml")

    # Load from environment
    config = load_config_from_env()

    # Build manually (use env var reference for secrets)
    config = DecoderConfig(
        azure=AzureConfig(
            tenant_id="550e8400-e29b-41d4-a716-446655440000",
            client_id="660e8400-e29b-41d4-a716-446655440000",
            client_secret="env:AZURE_CLIENT_SECRET"
        )
    )

    # Comprehensive Azure configuration
    from neoaxios_fastapi_kit.auth.config import (
        AzureConfig,
        GraphAPIConfig,
        MultiTenantConfig,
        RolesMappingConfig,
        load_azure_config,
        create_azure_decoder,
    )

    # Load Azure config with auto-discovery
    azure_config = load_azure_config()

    # Or build manually with all options
    azure_config = AzureConfig(
        tenant_id="550e8400-e29b-41d4-a716-446655440000",
        client_id="660e8400-e29b-41d4-a716-446655440000",
        client_secret="env:AZURE_CLIENT_SECRET",
        graph_api=GraphAPIConfig(enabled=True, timeout_seconds=15),
        multi_tenant=MultiTenantConfig(mode="single"),
        roles_mapping=RolesMappingConfig(source="claims", default_roles=["user"])
    )
"""

from neoaxios_fastapi_kit.auth.config.app import (
    AuthConfig,
    configure_auth,
    get_auth,
)
from neoaxios_fastapi_kit.auth.config.loaders import (
    # Generic loaders
    load_config_from_dict,
    load_config_from_env,
    load_config_from_yaml,
    # Azure-specific loaders
    load_azure_config,
    load_azure_config_from_dict,
    load_azure_config_from_env,
    load_azure_config_from_yaml,
    create_azure_decoder,
    ConfigurationError,
)
from neoaxios_fastapi_kit.auth.config.schemas import (
    # Auth mode and environment constants
    AuthMode,
    ALLOWED_DEV_ENVIRONMENTS,
    # Generic decoder configuration
    DecoderConfig,
    CacheConfig,
    # Development JWT config
    DevJWTConfig,
    # Azure AD config with SecretStr (secure)
    AzureConfig,
    GraphAPIConfig,
    MultiTenantConfig,
    RolesMappingConfig,
    # Other providers
    CognitoConfig,
    GoogleConfig,
    JWTConfig,
    OIDCConfig,
    JWKSConfig,
    OIDCDiscoveryConfig,
    OktaConfig,
    Auth0Config,
    KeycloakConfig,
)

__all__ = [
    # FastAPI app configuration
    "AuthConfig",
    "configure_auth",
    "get_auth",
    # Auth mode and environment constants
    "AuthMode",
    "ALLOWED_DEV_ENVIRONMENTS",
    # Identity provider decoder configuration
    "DecoderConfig",
    "JWTConfig",
    "OIDCConfig",
    "JWKSConfig",
    "OIDCDiscoveryConfig",
    # Development JWT configuration
    "DevJWTConfig",
    # Azure AD configuration (SecretStr secure)
    "AzureConfig",
    "GraphAPIConfig",
    "MultiTenantConfig",
    "RolesMappingConfig",
    # Other providers
    "CognitoConfig",
    "GoogleConfig",
    "OktaConfig",
    "Auth0Config",
    "KeycloakConfig",
    "CacheConfig",
    # Generic configuration loaders
    "load_config_from_yaml",
    "load_config_from_env",
    "load_config_from_dict",
    # Azure-specific loaders and factory
    "load_azure_config",
    "load_azure_config_from_dict",
    "load_azure_config_from_env",
    "load_azure_config_from_yaml",
    "create_azure_decoder",
    # Errors
    "ConfigurationError",
]
