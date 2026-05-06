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

"""Multi-provider OIDC example with automatic token routing.

This example demonstrates handling tokens from multiple OIDC providers in a
single application. It shows:

- MultiProviderTokenDecoder for automatic provider detection
- Okta, Auth0, and Keycloak decoder setup
- Automatic token routing based on issuer claim
- Error handling for unknown providers
- Telemetry tracking for provider-specific metrics
- Real issuer patterns for production use

This is essential for:
- Applications supporting multiple identity providers
- B2B SaaS with customer-specific identity providers
- Migration scenarios (transitioning between providers)
- Multi-tenant applications with per-tenant IdPs

Requirements:
    pip install neoaxios-fastapi-kit

Environment Variables (optional):
    # Okta configuration
    OKTA_TENANT_ID: Okta tenant domain
    OKTA_CLIENT_ID: Okta client ID
    OKTA_AUTHORIZATION_SERVER_ID: Auth server ID (default: "default")

    # Auth0 configuration
    AUTH0_DOMAIN: Auth0 domain
    AUTH0_CLIENT_ID: Auth0 client ID
    AUTH0_AUDIENCE: Auth0 API identifier

    # Keycloak configuration
    KEYCLOAK_REALM_NAME: Keycloak realm name
    KEYCLOAK_ISSUER: Keycloak issuer URL
    KEYCLOAK_CLIENT_ID: Keycloak client ID

Usage:
    python multi_provider_oidc.py

Example Tokens:
    # Okta token (iss: https://dev-12345.okta.com/oauth2/default)
    # Auth0 token (iss: https://myapp.us.auth0.com/)
    # Keycloak token (iss: https://keycloak.example.com/realms/myrealm)
"""

import asyncio
import os
from typing import Dict, Optional

from neoaxios_logging import get_telemetry

# Import decoders from neoaxios_fastapi_kit
from neoaxios_fastapi_kit.auth.authn.decoders.multi_provider import (
    MultiProviderTokenDecoder,
    DEFAULT_ISSUER_PATTERNS,
)
from neoaxios_fastapi_kit.auth.authn.decoders.providers.okta import OktaDecoder
from neoaxios_fastapi_kit.auth.authn.decoders.providers.auth0 import Auth0Decoder
from neoaxios_fastapi_kit.auth.authn.decoders.providers.keycloak import (
    KeycloakDecoder,
)
from neoaxios_fastapi_kit.auth.authn.errors import TokenInvalidError, TokenExpiredError
from neoaxios_fastapi_kit.auth.context import IdentityContext

# Initialize logger for telemetry
logger = get_telemetry(__name__)


# =============================================================================
# Provider Configuration
# =============================================================================

def get_okta_config() -> Optional[dict]:
    """Load Okta configuration from environment.

    Returns:
        Dictionary with Okta configuration or None if not configured

    Example:
        config = get_okta_config()
        if config:
            decoder = OktaDecoder(**config)
    """
    tenant_id = os.getenv("OKTA_TENANT_ID")
    client_id = os.getenv("OKTA_CLIENT_ID")

    if not tenant_id or not client_id:
        logger.info("Okta not configured (missing OKTA_TENANT_ID or OKTA_CLIENT_ID)")
        return None

    config = {
        "tenant_id": tenant_id,
        "client_id": client_id,
        "authorization_server_id": os.getenv("OKTA_AUTHORIZATION_SERVER_ID", "default"),
        "audience": os.getenv("OKTA_AUDIENCE"),
    }

    logger.info("Loaded Okta configuration", tenant_id=tenant_id)
    return config


def get_auth0_config() -> Optional[dict]:
    """Load Auth0 configuration from environment.

    Returns:
        Dictionary with Auth0 configuration or None if not configured

    Example:
        config = get_auth0_config()
        if config:
            decoder = Auth0Decoder(**config)
    """
    domain = os.getenv("AUTH0_DOMAIN")
    client_id = os.getenv("AUTH0_CLIENT_ID")

    if not domain or not client_id:
        logger.info("Auth0 not configured (missing AUTH0_DOMAIN or AUTH0_CLIENT_ID)")
        return None

    config = {
        "domain": domain,
        "client_id": client_id,
        "audience": os.getenv("AUTH0_AUDIENCE"),
    }

    logger.info("Loaded Auth0 configuration", domain=domain)
    return config


def get_keycloak_config() -> Optional[dict]:
    """Load Keycloak configuration from environment.

    Returns:
        Dictionary with Keycloak configuration or None if not configured

    Example:
        config = get_keycloak_config()
        if config:
            decoder = KeycloakDecoder(**config)
    """
    realm_name = os.getenv("KEYCLOAK_REALM_NAME")
    issuer = os.getenv("KEYCLOAK_ISSUER")
    client_id = os.getenv("KEYCLOAK_CLIENT_ID")

    if not realm_name or not issuer or not client_id:
        logger.info(
            "Keycloak not configured (missing KEYCLOAK_REALM_NAME, "
            "KEYCLOAK_ISSUER, or KEYCLOAK_CLIENT_ID)"
        )
        return None

    config = {
        "realm_name": realm_name,
        "issuer": issuer,
        "client_id": client_id,
        "audience": os.getenv("KEYCLOAK_AUDIENCE"),
    }

    logger.info("Loaded Keycloak configuration", realm_name=realm_name, issuer=issuer)
    return config


# =============================================================================
# Multi-Provider Decoder Setup
# =============================================================================

async def create_multi_provider_decoder() -> MultiProviderTokenDecoder:
    """Create multi-provider decoder with all configured providers.

    Creates decoders for each configured provider and wraps them in
    MultiProviderTokenDecoder for automatic routing based on token issuer.

    Returns:
        MultiProviderTokenDecoder instance with all configured providers

    Raises:
        Exception: If no providers are configured

    Example:
        decoder = await create_multi_provider_decoder()
        identity = await decoder.decode(token)  # Automatically routes to correct provider
    """
    logger.info("Creating multi-provider OIDC decoder")

    decoders: Dict[str, Any] = {}
    issuer_patterns: Dict[str, str] = {}

    # Set up Okta decoder
    okta_config = get_okta_config()
    if okta_config:
        try:
            okta_decoder = OktaDecoder(**okta_config)
            decoders["okta"] = okta_decoder

            # Okta issuer pattern
            issuer_patterns["okta"] = DEFAULT_ISSUER_PATTERNS["okta"]

            logger.info(
                "Okta decoder registered",
                tenant_id=okta_config["tenant_id"],
                issuer=okta_decoder.issuer,
            )
        except Exception as e:
            logger.log_error(
                error=e,
                message="Failed to create Okta decoder",
            )

    # Set up Auth0 decoder
    auth0_config = get_auth0_config()
    if auth0_config:
        try:
            auth0_decoder = Auth0Decoder(**auth0_config)
            decoders["auth0"] = auth0_decoder

            # Auth0 issuer pattern
            issuer_patterns["auth0"] = DEFAULT_ISSUER_PATTERNS["auth0"]

            logger.info(
                "Auth0 decoder registered",
                domain=auth0_config["domain"],
                issuer=auth0_decoder.issuer,
            )
        except Exception as e:
            logger.log_error(
                error=e,
                message="Failed to create Auth0 decoder",
            )

    # Set up Keycloak decoder
    keycloak_config = get_keycloak_config()
    if keycloak_config:
        try:
            keycloak_decoder = KeycloakDecoder(**keycloak_config)
            decoders["keycloak"] = keycloak_decoder

            # Keycloak issuer pattern (contains /realms/)
            # Custom pattern to match Keycloak issuer format
            issuer_patterns["keycloak"] = r"https?://[^/]+/realms/[^/]+"

            logger.info(
                "Keycloak decoder registered",
                realm_name=keycloak_config["realm_name"],
                issuer=keycloak_decoder.issuer,
            )
        except Exception as e:
            logger.log_error(
                error=e,
                message="Failed to create Keycloak decoder",
            )

    # Validate at least one provider is configured
    if not decoders:
        error = Exception(
            "No identity providers configured. "
            "Set environment variables for at least one provider: "
            "OKTA_*, AUTH0_*, or KEYCLOAK_*"
        )
        logger.log_error(error=error)
        raise error

    # Create multi-provider decoder
    multi_decoder = MultiProviderTokenDecoder(
        decoders=decoders,
        issuer_patterns=issuer_patterns,
    )

    logger.info(
        "Multi-provider decoder created successfully",
        providers=list(decoders.keys()),
        provider_count=len(decoders),
    )

    return multi_decoder


# =============================================================================
# Token Routing and Validation
# =============================================================================

async def detect_provider(decoder: MultiProviderTokenDecoder, token: str) -> Optional[str]:
    """Detect identity provider from token without full validation.

    Args:
        decoder: MultiProviderTokenDecoder instance
        token: JWT token string

    Returns:
        Provider name (e.g., "okta", "auth0", "keycloak") or None if unknown

    Example:
        provider = await detect_provider(decoder, token)
        logger.info(f"Token is from provider: {provider}")
    """
    try:
        provider = decoder.detect_provider(token)
        logger.info(f"Detected provider: {provider}")
        return provider

    except TokenInvalidError as e:
        logger.log_error(
            error=e,
            message="Failed to detect provider from token",
        )
        return None

    except Exception as e:
        logger.log_error(
            error=e,
            message="Unexpected error detecting provider",
        )
        return None


async def validate_multi_provider_token(
    decoder: MultiProviderTokenDecoder,
    token: str
) -> Optional[IdentityContext]:
    """Validate token from any configured provider.

    Args:
        decoder: MultiProviderTokenDecoder instance
        token: JWT token string to validate

    Returns:
        IdentityContext with user identity if token is valid,
        None if token is invalid

    Example:
        identity = await validate_multi_provider_token(decoder, token)
        if identity:
            logger.info(f"Token valid from provider: {identity.provider}")
    """
    logger.info("Validating token with multi-provider decoder")

    try:
        # Decode token (automatically detects and routes to correct provider)
        identity = await decoder.decode(token)

        logger.info(
            "Token validation successful",
            provider=identity.provider,
            user_id=identity.user_id,
            issuer=identity.issuer,
        )

        return identity

    except TokenExpiredError as e:
        logger.log_error(
            error=e,
            message="Token has expired",
        )
        return None

    except TokenInvalidError as e:
        logger.log_error(
            error=e,
            message="Token validation failed",
        )
        return None

    except Exception as e:
        logger.log_error(
            error=e,
            message="Unexpected error during multi-provider validation",
        )
        return None


# =============================================================================
# Provider-Specific Identity Display
# =============================================================================

async def display_identity_by_provider(identity: IdentityContext) -> None:
    """Display identity context with provider-specific attributes.

    Args:
        identity: IdentityContext from token validation

    Example:
        await display_identity_by_provider(identity)
    """
    logger.info("=" * 60)
    logger.info(f"Identity from {identity.provider.upper()} Provider")
    logger.info("=" * 60)
    logger.info(f"User ID: {identity.user_id}")
    logger.info(f"Tenant ID: {identity.tenant_id}")
    logger.info(f"Provider: {identity.provider}")
    logger.info(f"Issuer: {identity.issuer}")

    # Display roles
    if identity.roles:
        logger.info(f"Roles ({len(identity.roles)}):")
        for role in sorted(identity.roles):
            logger.info(f"  - {role}")

    # Display permissions
    if identity.permissions:
        logger.info(f"Permissions ({len(identity.permissions)}):")
        for perm in sorted(identity.permissions):
            logger.info(f"  - {perm}")

    # Display provider-specific attributes
    if identity.provider == "okta":
        # Okta-specific attributes
        logger.info("Okta-specific attributes:")
        if "groups" in identity.attributes:
            groups = identity.attributes["groups"]
            logger.info(f"  Groups: {groups}")
        if "org" in identity.attributes:
            logger.info(f"  Organization: {identity.attributes['org']}")
        if "ver" in identity.attributes:
            logger.info(f"  Token version: {identity.attributes['ver']}")

    elif identity.provider == "auth0":
        # Auth0-specific attributes
        logger.info("Auth0-specific attributes:")
        if "org_id" in identity.attributes:
            logger.info(f"  Organization ID: {identity.attributes['org_id']}")
        if "email_verified" in identity.attributes:
            logger.info(f"  Email verified: {identity.attributes['email_verified']}")
        if "sub_iss" in identity.attributes:
            logger.info(f"  Identity provider: {identity.attributes['sub_iss']}")

    elif identity.provider == "keycloak":
        # Keycloak-specific attributes
        logger.info("Keycloak-specific attributes:")
        if "realm_name" in identity.attributes:
            logger.info(f"  Realm: {identity.attributes['realm_name']}")
        if "client_roles" in identity.attributes:
            client_roles = identity.attributes["client_roles"]
            logger.info(f"  Client roles: {client_roles}")
        if "preferred_username" in identity.attributes:
            logger.info(f"  Username: {identity.attributes['preferred_username']}")

    # Display all other attributes
    logger.info(f"All attributes ({len(identity.attributes)}):")
    for key, value in sorted(identity.attributes.items()):
        logger.info(f"  {key}: {value}")

    logger.info("=" * 60)


# =============================================================================
# Main Example
# =============================================================================

async def main() -> None:
    """Main example demonstrating multi-provider OIDC.

    Steps:
    1. Create multi-provider decoder
    2. List configured providers
    3. Validate tokens from different providers
    4. Display provider-specific identity attributes

    Example:
        python multi_provider_oidc.py
    """
    logger.info("Starting multi-provider OIDC example")

    try:
        # Step 1: Create multi-provider decoder
        decoder = await create_multi_provider_decoder()

        # Step 2: List configured providers
        providers = decoder.list_decoders()
        logger.info("=" * 60)
        logger.info("CONFIGURED PROVIDERS")
        logger.info("=" * 60)
        for provider_name, decoder_type in providers.items():
            logger.info(f"  {provider_name}: {decoder_type}")
        logger.info("=" * 60)

        # Step 3: Get test tokens for each provider
        test_tokens = {
            "okta": os.getenv("OKTA_TEST_TOKEN"),
            "auth0": os.getenv("AUTH0_TEST_TOKEN"),
            "keycloak": os.getenv("KEYCLOAK_TEST_TOKEN"),
        }

        # Validate tokens from each provider
        for provider_name, token in test_tokens.items():
            if not token:
                logger.info(f"No test token for {provider_name} provider")
                continue

            logger.info(f"\nValidating {provider_name.upper()} token...")

            # Detect provider
            detected_provider = await detect_provider(decoder, token)
            if detected_provider:
                logger.info(f"Provider detected: {detected_provider}")

            # Validate and extract identity
            identity = await validate_multi_provider_token(decoder, token)
            if identity:
                await display_identity_by_provider(identity)

        logger.info("Example completed successfully")

    except KeyboardInterrupt:
        logger.info("Example interrupted by user")

    except Exception as e:
        logger.log_error(
            error=e,
            message="Example failed with unexpected error",
        )


if __name__ == "__main__":
    asyncio.run(main())
