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

"""Simple OIDC decoder example demonstrating basic token validation.

This example shows the minimal setup required to validate OIDC tokens from
a generic OpenID Connect provider. It demonstrates:

- Creating an OIDC decoder with issuer and JWKS URI
- Validating tokens and extracting identity context
- Error handling for invalid and expired tokens
- Logging with telemetry instead of print statements

This is the quickest way to get started with OIDC authentication.

Requirements:
    pip install neoaxios-fastapi-kit

Environment Variables (optional):
    OIDC_ISSUER: OIDC issuer URL (e.g., "https://accounts.google.com")
    OIDC_CLIENT_ID: OAuth 2.0 client ID
    OIDC_JWKS_URI: JWKS endpoint URL (auto-discovered if not provided)

Usage:
    python oidc_simple.py

Testing Locally:
    1. Set up an OIDC provider (Google, Okta, Auth0, Keycloak)
    2. Create an OAuth 2.0 application
    3. Set environment variables or modify config below
    4. Run this script and provide a test token
    5. View telemetry logs in .telemetry/ directory
"""

import asyncio
import os
import sys
from typing import Optional

from neoaxios_logging import get_telemetry

# Import decoder from neoaxios_fastapi_kit
from neoaxios_fastapi_kit.auth.authn.decoders.oidc import OIDCDecoder
from neoaxios_fastapi_kit.auth.authn.errors import TokenInvalidError, TokenExpiredError
from neoaxios_fastapi_kit.auth.context import IdentityContext

# Initialize logger for telemetry
logger = get_telemetry(__name__)


# =============================================================================
# Configuration
# =============================================================================

def get_oidc_config() -> dict:
    """Load OIDC configuration from environment or defaults.

    Returns:
        Dictionary with OIDC configuration parameters

    Example:
        config = get_oidc_config()
        decoder = OIDCDecoder(**config)
    """
    # Read from environment variables or use defaults
    config = {
        "issuer": os.getenv(
            "OIDC_ISSUER",
            "https://accounts.google.com"  # Example: Google OIDC
        ),
        "client_id": os.getenv(
            "OIDC_CLIENT_ID",
            "your-client-id.apps.googleusercontent.com"  # Replace with your client ID
        ),
        "jwks_uri": os.getenv(
            "OIDC_JWKS_URI",
            "https://www.googleapis.com/oauth2/v3/certs"  # Google JWKS endpoint
        ),
        "audience": os.getenv("OIDC_AUDIENCE"),  # Optional
        "clock_skew_seconds": int(os.getenv("OIDC_CLOCK_SKEW", "30")),
    }

    logger.info(
        "Loaded OIDC configuration",
        issuer=config["issuer"],
        client_id=config["client_id"][:20] + "...",  # Log truncated for security
        jwks_uri=config["jwks_uri"],
        has_audience=bool(config["audience"]),
    )

    return config


# =============================================================================
# Decoder Setup
# =============================================================================

async def create_decoder() -> OIDCDecoder:
    """Create and configure OIDC decoder.

    Returns:
        Configured OIDCDecoder instance ready for token validation

    Raises:
        Exception: If configuration is invalid

    Example:
        decoder = await create_decoder()
        identity = await decoder.decode(token)
    """
    logger.info("Initializing OIDC decoder")

    try:
        # Load configuration
        config = get_oidc_config()

        # Create decoder with configuration
        decoder = OIDCDecoder(
            issuer=config["issuer"],
            client_id=config["client_id"],
            jwks_uri=config["jwks_uri"],
            audience=config.get("audience"),
            clock_skew_seconds=config["clock_skew_seconds"],
        )

        logger.info(
            "OIDC decoder initialized successfully",
            issuer=decoder.issuer,
            client_id=decoder.client_id[:20] + "...",
        )

        return decoder

    except Exception as e:
        logger.log_error(
            error=e,
            message="Failed to create OIDC decoder",
        )
        raise


# =============================================================================
# Token Validation
# =============================================================================

async def validate_token(decoder: OIDCDecoder, token: str) -> Optional[IdentityContext]:
    """Validate OIDC token and extract identity.

    Performs complete OIDC token validation:
    - JWT structure validation
    - JWKS signature verification
    - Issuer validation
    - Audience validation (if configured)
    - Expiration check
    - Claims extraction

    Args:
        decoder: Configured OIDCDecoder instance
        token: JWT token string to validate

    Returns:
        IdentityContext with user identity if token is valid,
        None if token is invalid

    Example:
        identity = await validate_token(decoder, "eyJhbGciOi...")
        if identity:
            logger.info("Token valid", user_id=identity.user_id)
    """
    logger.info("Validating OIDC token")

    try:
        # Decode and validate token
        identity = await decoder.decode(token)

        # Log successful validation with identity details
        logger.info(
            "Token validation successful",
            user_id=identity.user_id,
            tenant_id=identity.tenant_id,
            provider=identity.provider,
            issuer=identity.issuer,
            roles_count=len(identity.roles),
            permissions_count=len(identity.permissions),
            has_email=("email" in identity.attributes),
        )

        return identity

    except TokenExpiredError as e:
        # Token is expired
        logger.log_error(
            error=e,
            message="Token has expired",
        )
        return None

    except TokenInvalidError as e:
        # Token is invalid (signature, issuer, audience, etc.)
        logger.log_error(
            error=e,
            message="Token validation failed",
        )
        return None

    except Exception as e:
        # Unexpected error
        logger.log_error(
            error=e,
            message="Unexpected error during token validation",
        )
        return None


async def display_identity(identity: IdentityContext) -> None:
    """Display identity context information.

    Logs the extracted identity information in a readable format.
    Uses telemetry logger (not print) for production patterns.

    Args:
        identity: IdentityContext from token validation

    Example:
        await display_identity(identity)
    """
    logger.info("=" * 60)
    logger.info("OIDC Identity Context")
    logger.info("=" * 60)
    logger.info(f"User ID: {identity.user_id}")
    logger.info(f"Tenant ID: {identity.tenant_id}")
    logger.info(f"Provider: {identity.provider}")
    logger.info(f"Issuer: {identity.issuer}")
    logger.info(f"Provider User ID: {identity.provider_user_id}")

    # Display roles
    if identity.roles:
        logger.info(f"Roles ({len(identity.roles)}):")
        for role in sorted(identity.roles):
            logger.info(f"  - {role}")
    else:
        logger.info("Roles: None")

    # Display permissions
    if identity.permissions:
        logger.info(f"Permissions ({len(identity.permissions)}):")
        for perm in sorted(identity.permissions):
            logger.info(f"  - {perm}")
    else:
        logger.info("Permissions: None")

    # Display attributes
    if identity.attributes:
        logger.info(f"Attributes ({len(identity.attributes)}):")
        for key, value in sorted(identity.attributes.items()):
            logger.info(f"  - {key}: {value}")
    else:
        logger.info("Attributes: None")

    logger.info("=" * 60)


# =============================================================================
# Main Example
# =============================================================================

async def main() -> None:
    """Main example demonstrating OIDC token validation.

    Steps:
    1. Create OIDC decoder from configuration
    2. Prompt for token input (or use test token)
    3. Validate token and extract identity
    4. Display identity context

    Example:
        python oidc_simple.py
    """
    logger.info("Starting OIDC simple example")

    try:
        # Step 1: Create decoder
        decoder = await create_decoder()

        # Step 2: Get token
        # In production, tokens come from Authorization header
        # For testing, you can:
        # - Set OIDC_TEST_TOKEN environment variable
        # - Paste token when prompted
        # - Use token generation script (examples/token_generation.py)

        test_token = os.getenv("OIDC_TEST_TOKEN")

        if not test_token:
            logger.info("No test token in environment. Please provide token manually.")
            logger.info("To set token: export OIDC_TEST_TOKEN='your-token-here'")
            logger.info("Or use token_generation.py to generate test tokens")
            sys.exit(0)

        # Step 3: Validate token
        logger.info("Validating token...")
        identity = await validate_token(decoder, test_token)

        if identity:
            # Step 4: Display identity
            await display_identity(identity)
            logger.info("Example completed successfully")
        else:
            logger.info("Token validation failed. Check logs for details.")
            sys.exit(1)

    except KeyboardInterrupt:
        logger.info("Example interrupted by user")
        sys.exit(0)

    except Exception as e:
        logger.log_error(
            error=e,
            message="Example failed with unexpected error",
        )
        sys.exit(1)


if __name__ == "__main__":
    # Run example
    asyncio.run(main())
