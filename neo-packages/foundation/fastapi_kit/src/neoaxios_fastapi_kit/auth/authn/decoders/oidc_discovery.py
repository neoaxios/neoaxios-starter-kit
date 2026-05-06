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

"""OpenID Discovery Client for JWKS and issuer metadata.

Implements OpenID Connect Discovery 1.0 specification for fetching JWKS keys
and issuer metadata from identity providers. Supports caching, retries, and
defensive error handling for production reliability.

This client handles:
- .well-known/openid-configuration discovery endpoint
- JWKS (JSON Web Key Set) endpoint fetching
- Issuer URL validation (security requirement)
- HTTP client lifecycle management
- Exponential backoff retry logic
- Response validation and parsing

OpenID Connect Discovery Specification:
https://openid.net/specs/openid-connect-discovery-1_0.html

Usage:
    from neoaxios_fastapi_kit.auth.authn.decoders.oidc_discovery import (
        OpenIDDiscoveryClient,
        OpenIDDiscoveryMetadata,
    )

    client = OpenIDDiscoveryClient(timeout_seconds=10)

    # Discover issuer metadata
    metadata = await client.discover("https://accounts.google.com")
    logger.info(f"JWKS URI: {metadata.jwks_uri}")
    logger.info(f"Supported algorithms: {metadata.supported_algs}")

    # Fetch JWKS keys
    jwks = await client.get_jwks("https://accounts.google.com")
    logger.info(f"Keys: {jwks['keys']}")

    # Cleanup
    await client.close()

Example Discovery Response:
    {
        "issuer": "https://accounts.google.com",
        "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_endpoint": "https://oauth2.googleapis.com/token",
        "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
        "response_types_supported": ["code", "token", "id_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"]
    }

Example JWKS Response:
    {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "kid": "abc123",
                "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx...",
                "e": "AQAB"
            }
        ]
    }
"""

import asyncio
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import httpx
from neoaxios_secure_cache.defaults import (
    HTTPX_MAX_CONNECTIONS,
    HTTPX_MAX_KEEPALIVE_CONNECTIONS,
    HTTPX_MAX_RETRIES,
)
from neoaxios_logging import auto_trace, get_telemetry

from neoaxios_fastapi_kit.auth.authn.errors import TokenInvalidError

logger = get_telemetry(__name__)


# =============================================================================
# Data Models
# =============================================================================


@dataclass(frozen=True)
class OpenIDDiscoveryMetadata:
    """OpenID Connect Discovery metadata from .well-known/openid-configuration.

    Represents the issuer's discovery document containing endpoints and
    capabilities. All fields are validated and guaranteed to be present
    after successful discovery.

    Attributes:
        issuer: The issuer identifier (must match discovery URL)
        jwks_uri: URL of the JWKS endpoint for fetching public keys
        supported_algs: List of supported signing algorithms (e.g., RS256, ES256)
        token_endpoint: OAuth 2.0 token endpoint URL (optional)
        authorization_endpoint: OAuth 2.0 authorization endpoint URL (optional)
        userinfo_endpoint: UserInfo endpoint URL (optional)
        introspection_endpoint: Token introspection endpoint URL (optional)
        revocation_endpoint: Token revocation endpoint URL (optional)
        response_types_supported: Supported OAuth response types (optional)
        subject_types_supported: Supported subject identifier types (optional)
        scopes_supported: Supported OAuth scopes (optional)

    Security:
        - issuer must match the URL used for discovery (prevents issuer confusion)
        - jwks_uri must be HTTPS (prevents downgrade attacks)
        - All endpoints must use HTTPS in production
    """

    issuer: str
    jwks_uri: str
    supported_algs: List[str]
    token_endpoint: Optional[str] = None
    authorization_endpoint: Optional[str] = None
    userinfo_endpoint: Optional[str] = None
    introspection_endpoint: Optional[str] = None
    revocation_endpoint: Optional[str] = None
    response_types_supported: Optional[List[str]] = None
    subject_types_supported: Optional[List[str]] = None
    scopes_supported: Optional[List[str]] = None


# =============================================================================
# OpenID Discovery Client
# =============================================================================


class OpenIDDiscoveryClient:
    """OpenID Connect Discovery client for fetching JWKS and metadata.

    Implements OpenID Connect Discovery 1.0 specification with production-ready
    features including:
    - Async HTTP client with connection pooling
    - Configurable timeouts and retries
    - Exponential backoff for transient failures
    - SSL certificate validation (no insecure mode)
    - Defensive response parsing
    - Issuer URL validation (security requirement)

    The client manages its own HTTP client lifecycle. Call close() when done
    or use as async context manager:

        async with OpenIDDiscoveryClient() as client:
            metadata = await client.discover(issuer)

    Attributes:
        timeout_seconds: Default timeout for HTTP requests (default: 10)
        max_retries: Maximum number of retry attempts (default: 3)
        retry_backoff_base: Base delay for exponential backoff in seconds (default: 0.5)
        user_agent: User-Agent header for HTTP requests (default: neoaxios-fastapi-kit/1.0)
    """

    @auto_trace(logger)
    def __init__(
        self,
        timeout_seconds: int = 10,
        max_retries: int = HTTPX_MAX_RETRIES,
        retry_backoff_base: float = 0.5,
        user_agent: str = "neoaxios-fastapi-kit/1.0",
    ):
        """Initialize OpenID Discovery Client.

        Args:
            timeout_seconds: Timeout for HTTP requests in seconds (default: 10).
                           Applies to both discovery and JWKS fetches.
                           Range: 1-60 seconds recommended.
            max_retries: Maximum number of retry attempts for transient failures
                        (default: 3). Set to 0 to disable retries.
            retry_backoff_base: Base delay for exponential backoff in seconds
                               (default: 0.5). Delay = base * (2 ** retry_attempt).
                               Range: 0.1-5.0 seconds recommended.
            user_agent: User-Agent header for traceability (default: neoaxios-fastapi-kit/1.0).
                       Helps identity providers track client behavior.

        Example:
            # Production configuration with retries
            client = OpenIDDiscoveryClient(
                timeout_seconds=10,
                max_retries=3,
                retry_backoff_base=0.5,
            )

            # Fast-fail configuration (no retries)
            client = OpenIDDiscoveryClient(
                timeout_seconds=5,
                max_retries=0,
            )
        """
        if timeout_seconds < 1 or timeout_seconds > 60:
            error = TokenInvalidError(
                f"timeout_seconds must be between 1 and 60, got {timeout_seconds}"
            )
            logger.log_error(error=error)
            raise error

        if max_retries < 0 or max_retries > 10:
            error = TokenInvalidError(
                f"max_retries must be between 0 and 10, got {max_retries}"
            )
            logger.log_error(error=error)
            raise error

        if retry_backoff_base < 0.1 or retry_backoff_base > 5.0:
            error = TokenInvalidError(
                f"retry_backoff_base must be between 0.1 and 5.0, got {retry_backoff_base}"
            )
            logger.log_error(error=error)
            raise error

        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.retry_backoff_base = retry_backoff_base
        self.user_agent = user_agent

        # Create async HTTP client with connection pooling
        # Limits connections to prevent resource exhaustion
        self._http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout_seconds),
            headers={"User-Agent": user_agent},
            limits=httpx.Limits(max_keepalive_connections=HTTPX_MAX_KEEPALIVE_CONNECTIONS, max_connections=HTTPX_MAX_CONNECTIONS),
            verify=True,  # Always validate SSL certificates
        )

        logger.info(
            f"Initialized OpenIDDiscoveryClient: "
            f"timeout={timeout_seconds}s, max_retries={max_retries}, "
            f"backoff_base={retry_backoff_base}s, user_agent={user_agent}"
        )

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit with cleanup."""
        await self.close()

    @auto_trace(logger)
    async def close(self) -> None:
        """Close HTTP client and cleanup resources.

        Always call this method when done with the client, or use the client
        as an async context manager to ensure cleanup.

        Example:
            client = OpenIDDiscoveryClient()
            try:
                metadata = await client.discover(issuer)
            finally:
                await client.close()
        """
        if self._http_client:
            await self._http_client.aclose()
            logger.debug("Closed HTTP client")

    @auto_trace(logger)
    async def discover(self, issuer: str) -> OpenIDDiscoveryMetadata:
        """Discover OpenID configuration from issuer.

        Fetches the .well-known/openid-configuration document from the issuer
        and validates required fields. Performs security validation to prevent
        issuer confusion attacks.

        Args:
            issuer: Issuer URL (e.g., "https://accounts.google.com").
                   Must be HTTPS in production (HTTP allowed for localhost only).
                   Must not contain wildcards or path components.

        Returns:
            OpenIDDiscoveryMetadata with validated issuer configuration

        Raises:
            TokenInvalidError: If issuer URL is invalid, discovery fails,
                              response is malformed, or required fields are missing

        Example:
            metadata = await client.discover("https://accounts.google.com")
            logger.info(f"JWKS URI: {metadata.jwks_uri}")
            logger.info(f"Token endpoint: {metadata.token_endpoint}")
            logger.info(f"Supported algs: {metadata.supported_algs}")
        """
        # Validate issuer URL format and security
        self._validate_issuer_url(issuer)

        # Build discovery URL
        discovery_url = self._build_discovery_url(issuer)

        logger.info(f"Starting OpenID discovery for issuer: {issuer}")

        # Fetch discovery document with retries
        discovery_doc = await self._fetch_with_retry(discovery_url)

        # Validate and parse discovery document
        metadata = self._parse_discovery_response(issuer, discovery_doc)

        logger.info(
            f"Successfully discovered OpenID configuration: "
            f"issuer={metadata.issuer}, jwks_uri={metadata.jwks_uri}, "
            f"supported_algs={metadata.supported_algs}"
        )

        return metadata

    @auto_trace(logger)
    async def get_jwks(self, issuer: str) -> Dict[str, Any]:
        """Fetch JWKS (JSON Web Key Set) from issuer.

        Discovers the JWKS endpoint via OpenID discovery and fetches the
        public keys. The JWKS contains cryptographic keys used to verify
        JWT signatures.

        Args:
            issuer: Issuer URL (e.g., "https://accounts.google.com")

        Returns:
            JWKS dictionary with "keys" array containing JWK objects.
            Format: {"keys": [{"kty": "RSA", "kid": "...", "n": "...", "e": "..."}]}

        Raises:
            TokenInvalidError: If discovery fails, JWKS fetch fails,
                              or response is malformed

        Example:
            jwks = await client.get_jwks("https://accounts.google.com")
            for key in jwks["keys"]:
                logger.info(f"Key ID: {key['kid']}, Type: {key['kty']}")
        """
        # Discover issuer metadata to get JWKS URI
        metadata = await self.discover(issuer)

        logger.info(f"Fetching JWKS from: {metadata.jwks_uri}")

        # Fetch JWKS with retries
        jwks_doc = await self._fetch_with_retry(metadata.jwks_uri)

        # Parse and validate JWKS response
        jwks = self._parse_jwks_response(jwks_doc)

        logger.info(
            f"Successfully fetched JWKS: "
            f"keys_count={len(jwks.get('keys', []))}, "
            f"issuer={issuer}"
        )

        return jwks

    @auto_trace(logger)
    def _validate_issuer_url(self, issuer: str) -> None:
        """Validate issuer URL format and security requirements.

        Security checks:
        - Must use HTTPS (HTTP allowed for localhost/127.0.0.1 only)
        - Must not contain wildcards or path components
        - Must be a valid URL
        - Must not be empty or None

        Args:
            issuer: Issuer URL to validate

        Raises:
            TokenInvalidError: If issuer URL is invalid or insecure

        Example:
            self._validate_issuer_url("https://accounts.google.com")  # OK
            self._validate_issuer_url("http://localhost:8080")  # OK (localhost)
            self._validate_issuer_url("http://example.com")  # ERROR (not HTTPS)
        """
        if not issuer:
            error = TokenInvalidError("Issuer URL cannot be empty")
            logger.log_error(error=error)
            raise error

        # Parse URL
        try:
            parsed = urlparse(issuer)
        except Exception as e:
            error = TokenInvalidError(f"Invalid issuer URL: {str(e)}")
            logger.log_error(error=error)
            raise error

        # Validate scheme (HTTPS required, HTTP allowed for localhost only)
        if parsed.scheme not in ("https", "http"):
            error = TokenInvalidError(
                f"Issuer URL must use https:// scheme (got {parsed.scheme}://)"
            )
            logger.log_error(error=error)
            raise error

        if parsed.scheme == "http":
            # Allow HTTP for localhost/127.0.0.1 only (development)
            if parsed.hostname not in ("localhost", "127.0.0.1"):
                error = TokenInvalidError(
                    f"HTTP issuer URLs only allowed for localhost, got {parsed.hostname}"
                )
                logger.log_error(error=error)
                raise error

        # Validate hostname (no wildcards)
        if not parsed.hostname or "*" in parsed.hostname:
            error = TokenInvalidError(f"Invalid issuer hostname: {parsed.hostname}")
            logger.log_error(error=error)
            raise error

        # Warn if issuer has path components (unusual but allowed by spec)
        if parsed.path and parsed.path != "/":
            logger.warning(
                f"Issuer URL contains path component: {issuer}. "
                f"Ensure this matches the 'iss' claim in tokens exactly."
            )

        logger.debug(f"Issuer URL validation passed: {issuer}")

    @auto_trace(logger)
    def _build_discovery_url(self, issuer: str) -> str:
        """Build OpenID discovery URL from issuer.

        Constructs the .well-known/openid-configuration URL according to
        OpenID Connect Discovery specification.

        Args:
            issuer: Base issuer URL

        Returns:
            Full discovery URL (issuer + /.well-known/openid-configuration)

        Example:
            url = self._build_discovery_url("https://accounts.google.com")
            # Returns: "https://accounts.google.com/.well-known/openid-configuration"
        """
        # Ensure issuer ends with / for proper URL joining
        if not issuer.endswith("/"):
            issuer = issuer + "/"

        discovery_url = urljoin(issuer, ".well-known/openid-configuration")

        logger.debug(f"Built discovery URL: {discovery_url}")

        return discovery_url

    @auto_trace(logger)
    async def _fetch_with_retry(self, url: str) -> Dict[str, Any]:
        """Fetch URL with exponential backoff retry logic.

        Retries on transient HTTP errors (5xx, connection errors, timeouts).
        Does not retry on client errors (4xx).

        Args:
            url: URL to fetch

        Returns:
            Parsed JSON response as dictionary

        Raises:
            TokenInvalidError: If all retries fail or non-retryable error occurs

        Retry Strategy:
            - Attempt 0: Immediate
            - Attempt 1: Wait 0.5s (backoff_base * 2^0)
            - Attempt 2: Wait 1.0s (backoff_base * 2^1)
            - Attempt 3: Wait 2.0s (backoff_base * 2^2)
        """
        last_error: Optional[Exception] = None

        for attempt in range(self.max_retries + 1):
            try:
                # Exponential backoff (skip delay on first attempt)
                if attempt > 0:
                    delay = self.retry_backoff_base * (2 ** (attempt - 1))
                    logger.debug(
                        f"Retry attempt {attempt}/{self.max_retries} "
                        f"after {delay}s delay"
                    )
                    await asyncio.sleep(delay)

                # Make HTTP GET request
                response = await self._http_client.get(url)

                # Check HTTP status
                if response.status_code == 200:
                    # Success - parse JSON
                    try:
                        data = response.json()
                        logger.debug(
                            f"Successfully fetched {url}: "
                            f"status={response.status_code}, "
                            f"keys_count={len(data)}"
                        )
                        return data
                    except Exception as e:
                        error = TokenInvalidError(
                            f"Failed to parse JSON response from {url}: {str(e)}"
                        )
                        logger.log_error(error=error)
                        raise error

                # Client errors (4xx) - do not retry
                if 400 <= response.status_code < 500:
                    error = TokenInvalidError(
                        f"HTTP {response.status_code} from {url}: {response.text[:200]}"
                    )
                    logger.log_error(error=error)
                    raise error

                # Server errors (5xx) - retry
                last_error = TokenInvalidError(
                    f"HTTP {response.status_code} from {url}: {response.text[:200]}"
                )
                logger.warning(
                    f"Server error (will retry): "
                    f"status={response.status_code}, attempt={attempt}"
                )

            except httpx.TimeoutException as e:
                # Timeout - retry
                last_error = TokenInvalidError(f"Timeout fetching {url}: {str(e)}")
                logger.warning(f"Timeout (will retry): attempt={attempt}, url={url}")

            except httpx.RequestError as e:
                # Connection error - retry
                last_error = TokenInvalidError(f"Connection error fetching {url}: {str(e)}")
                logger.warning(
                    f"Connection error (will retry): attempt={attempt}, url={url}"
                )

            except TokenInvalidError:
                # Already logged, re-raise
                raise

            except Exception as e:
                # Unexpected error - do not retry
                error = TokenInvalidError(f"Unexpected error fetching {url}: {str(e)}")
                logger.log_error(error=error)
                raise error

        # All retries exhausted
        error = TokenInvalidError(
            f"Failed to fetch {url} after {self.max_retries + 1} attempts. "
            f"Last error: {str(last_error)}"
        )
        logger.log_error(error=error)
        raise error

    @auto_trace(logger)
    def _parse_discovery_response(
        self, issuer: str, discovery_doc: Dict[str, Any]
    ) -> OpenIDDiscoveryMetadata:
        """Parse and validate OpenID discovery response.

        Validates required fields and issuer matching per OpenID Connect
        Discovery specification.

        Args:
            issuer: Expected issuer URL (must match discovery_doc["issuer"])
            discovery_doc: Raw discovery document from .well-known endpoint

        Returns:
            OpenIDDiscoveryMetadata with validated fields

        Raises:
            TokenInvalidError: If required fields missing or issuer mismatch

        Security:
            - Issuer must match exactly (prevents issuer confusion attacks)
            - JWKS URI must be HTTPS (prevents downgrade attacks)
        """
        # Validate required fields presence
        required_fields = ["issuer", "jwks_uri"]
        missing_fields = [f for f in required_fields if f not in discovery_doc]

        if missing_fields:
            error = TokenInvalidError(
                f"Discovery document missing required fields: {missing_fields}. "
                f"Present fields: {list(discovery_doc.keys())}"
            )
            logger.log_error(error=error)
            raise error

        # Validate issuer matches (security requirement)
        # Normalize both issuers to handle trailing slash inconsistency
        discovered_issuer = discovery_doc["issuer"]
        normalized_expected = issuer.rstrip('/') if issuer else issuer
        normalized_discovered = discovered_issuer.rstrip('/') if discovered_issuer else discovered_issuer

        if normalized_discovered != normalized_expected:
            error = TokenInvalidError(
                f"Issuer mismatch: expected '{issuer}', "
                f"got '{discovered_issuer}' from discovery document. "
                f"This may indicate an issuer confusion attack."
            )
            logger.log_error(error=error)
            raise error

        # Validate issuer uses HTTPS (security requirement)
        issuer_parsed = urlparse(normalized_discovered)
        if issuer_parsed.scheme != "https":
            error = TokenInvalidError(
                f"HTTP issuer URLs only allowed for localhost, got: {normalized_discovered}"
            )
            logger.log_error(error=error)
            raise error

        # Validate JWKS URI is HTTPS (security requirement)
        jwks_uri = discovery_doc["jwks_uri"]
        jwks_parsed = urlparse(jwks_uri)
        if jwks_parsed.scheme == "http":
            # Allow HTTP for localhost only
            if jwks_parsed.hostname not in ("localhost", "127.0.0.1"):
                error = TokenInvalidError(
                    f"JWKS URI must use HTTPS, got: {jwks_uri}"
                )
                logger.log_error(error=error)
                raise error

        # Extract supported algorithms
        supported_algs = discovery_doc.get(
            "id_token_signing_alg_values_supported",
            ["RS256"],  # Default to RS256 if not specified
        )

        # Build metadata object (use normalized issuer for consistency)
        metadata = OpenIDDiscoveryMetadata(
            issuer=normalized_discovered,
            jwks_uri=jwks_uri,
            supported_algs=supported_algs,
            token_endpoint=discovery_doc.get("token_endpoint"),
            authorization_endpoint=discovery_doc.get("authorization_endpoint"),
            userinfo_endpoint=discovery_doc.get("userinfo_endpoint"),
            introspection_endpoint=discovery_doc.get("introspection_endpoint"),
            revocation_endpoint=discovery_doc.get("revocation_endpoint"),
            response_types_supported=discovery_doc.get("response_types_supported"),
            subject_types_supported=discovery_doc.get("subject_types_supported"),
            scopes_supported=discovery_doc.get("scopes_supported"),
        )

        logger.debug(
            f"Parsed discovery metadata: "
            f"issuer={metadata.issuer}, jwks_uri={metadata.jwks_uri}, "
            f"supported_algs={metadata.supported_algs}"
        )

        return metadata

    @auto_trace(logger)
    def _parse_jwks_response(self, jwks_doc: Dict[str, Any]) -> Dict[str, Any]:
        """Parse and validate JWKS response.

        Validates JWKS structure according to RFC 7517 (JSON Web Key).

        Args:
            jwks_doc: Raw JWKS document from jwks_uri endpoint

        Returns:
            Validated JWKS dictionary with "keys" array

        Raises:
            TokenInvalidError: If JWKS is malformed or has no keys

        JWKS Format:
            {
                "keys": [
                    {
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "key-id-1",
                        "n": "modulus...",
                        "e": "exponent..."
                    }
                ]
            }
        """
        # Validate "keys" field exists
        if "keys" not in jwks_doc:
            error = TokenInvalidError(
                f"JWKS missing 'keys' field. Present fields: {list(jwks_doc.keys())}"
            )
            logger.log_error(error=error)
            raise error

        # Validate "keys" is a list
        keys = jwks_doc["keys"]
        if not isinstance(keys, list):
            error = TokenInvalidError(
                f"JWKS 'keys' must be array, got {type(keys).__name__}"
            )
            logger.log_error(error=error)
            raise error

        # Validate at least one key present
        if len(keys) == 0:
            error = TokenInvalidError("JWKS contains no keys")
            logger.log_error(error=error)
            raise error

        # Validate each key has required fields
        for i, key in enumerate(keys):
            if not isinstance(key, dict):
                error = TokenInvalidError(
                    f"JWKS key {i} must be object, got {type(key).__name__}"
                )
                logger.log_error(error=error)
                raise error

            # Check for kty (key type) - required by RFC 7517
            if "kty" not in key:
                error = TokenInvalidError(f"JWKS key {i} missing required field 'kty'")
                logger.log_error(error=error)
                raise error

        logger.debug(f"Parsed JWKS: keys_count={len(keys)}")

        return jwks_doc


# =============================================================================
# Factory Function
# =============================================================================


@auto_trace(logger)
def create_oidc_discovery_client(
    timeout_seconds: int = 10,
    max_retries: int = HTTPX_MAX_RETRIES,
    retry_backoff_base: float = 0.5,
    user_agent: str = "neoaxios-fastapi-kit/1.0",
) -> OpenIDDiscoveryClient:
    """Factory function for OpenIDDiscoveryClient instantiation.

    Creates an OpenIDDiscoveryClient with validated parameters.

    Args:
        timeout_seconds: HTTP request timeout in seconds (default: 10, range: 1-60)
        max_retries: Maximum retry attempts (default: 3, range: 0-10)
        retry_backoff_base: Exponential backoff base delay (default: 0.5, range: 0.1-5.0)
        user_agent: User-Agent header for requests (default: neoaxios-fastapi-kit/1.0)

    Returns:
        OpenIDDiscoveryClient instance configured with validated parameters

    Raises:
        TokenInvalidError: If parameters are invalid

    Example:
        client = create_oidc_discovery_client(timeout_seconds=10, max_retries=3)
        async with client:
            metadata = await client.discover("https://accounts.google.com")
    """
    return OpenIDDiscoveryClient(
        timeout_seconds=timeout_seconds,
        max_retries=max_retries,
        retry_backoff_base=retry_backoff_base,
        user_agent=user_agent,
    )
