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

"""Microsoft Graph API Client for Azure AD token introspection and user lookups.

Implements async HTTP client for Microsoft Graph API operations including token
introspection, user profile retrieval, group memberships, and directory roles.
Designed for per-tenant credential isolation with production-ready reliability.

This client handles:
- Token introspection via Microsoft Graph API
- User profile lookups by object ID
- Group membership retrieval (transitive)
- Directory role assignments
- Per-tenant client credentials OAuth flow
- Exponential backoff retry logic
- Rate limiting with Retry-After header support

Microsoft Graph API Documentation:
https://docs.microsoft.com/en-us/graph/overview

Security Considerations:
- HTTPS-only communication (HTTP rejected)
- SSL verification always enabled
- Credentials never exposed in logs or errors
- Per-tenant credential isolation
- Thread-safe token caching with asyncio.Lock

Usage:
    from neoaxios_fastapi_kit.auth.authn.decoders.providers.azure_graph import (
        GraphAPIClient,
        GraphAPIError,
        create_graph_api_client,
    )

    # Create client for tenant
    client = GraphAPIClient(
        tenant_id="your-tenant-id",
        client_id="your-client-id",
        client_secret="your-client-secret",
    )

    # Use as async context manager
    async with client:
        # Introspect token
        token_info = await client.introspect_token(access_token)
        if token_info.get("active"):
            logger.info("Token is active")

        # Get user profile
        user = await client.get_user(user_object_id)
        logger.info(f"User: {user.get('displayName')}")

        # Get user groups
        groups = await client.get_user_groups(user_object_id)
        logger.info(f"Groups: {groups}")

        # Get directory roles
        roles = await client.get_directory_roles(user_object_id)
        logger.info(f"Roles: {roles}")

    # Or use factory function
    client = create_graph_api_client(
        tenant_id="your-tenant-id",
        client_id="your-client-id",
        client_secret="your-client-secret",
    )

Environment Variables (for factory function):
- AZURE_TENANT_ID: Azure AD tenant ID
- AZURE_CLIENT_ID: Application (client) ID
- AZURE_CLIENT_SECRET: Client secret value
- AZURE_GRAPH_TIMEOUT: Request timeout in seconds (default: 30)
- AZURE_GRAPH_MAX_RETRIES: Maximum retry attempts (default: 3)

Microsoft Graph Endpoints Used:
- Token endpoint: https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
- User profile: https://graph.microsoft.com/v1.0/users/{id}
- User groups: https://graph.microsoft.com/v1.0/users/{id}/transitiveMemberOf/microsoft.graph.group
- Directory roles: https://graph.microsoft.com/v1.0/users/{id}/transitiveMemberOf/microsoft.graph.directoryRole
"""

import asyncio
import os
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

if TYPE_CHECKING:
    from neoaxios_secure_cache import CacheNamespace
    from neoaxios_secure_cache import CacheBackend

import httpx
from pydantic import SecretStr
from neoaxios_secure_cache.defaults import (
    HTTPX_MAX_CONNECTIONS,
    HTTPX_MAX_KEEPALIVE_CONNECTIONS,
    HTTPX_MAX_RETRIES,
)
from neoaxios_logging import TraceDisabledReason, auto_trace, get_telemetry

from neoaxios_fastapi_kit.auth.cache_keys import graph_token_key
from neoaxios_fastapi_kit.auth.errors import AuthError

logger = get_telemetry(__name__)


# =============================================================================
# Error Types
# =============================================================================


class GraphAPIError(AuthError):
    """Error from Microsoft Graph API operations.

    Raised when:
    - Graph API returns error response
    - Authentication to Graph API fails
    - Network or timeout errors occur
    - Rate limiting is exceeded after retries
    - Response parsing fails

    Attributes:
        status_code: HTTP status code (default 500 for internal errors)
        error_code: Machine-readable error code
        tenant_id: Tenant context for error (for logging, not exposed to clients)
        endpoint: API endpoint that failed (for logging)
        graph_error_code: Original Microsoft Graph error code (if available)
    """

    status_code: int = 500
    error_code: str = "GRAPH_API_ERROR"

    def __init__(
        self,
        message: str,
        *,
        status_code: Optional[int] = None,
        graph_error_code: Optional[str] = None,
        tenant_id: Optional[str] = None,
        endpoint: Optional[str] = None,
    ):
        """Initialize GraphAPIError with context.

        Args:
            message: Human-readable error description (no secrets)
            status_code: HTTP status code override
            graph_error_code: Microsoft Graph error code (e.g., "Authorization_RequestDenied")
            tenant_id: Tenant ID for context (logged but not in message)
            endpoint: API endpoint for context (logged but not in message)
        """
        super().__init__(message)
        if status_code is not None:
            self.status_code = status_code
        self.graph_error_code = graph_error_code
        self.tenant_id = tenant_id
        self.endpoint = endpoint


class GraphAPIAuthenticationError(GraphAPIError):
    """Authentication to Graph API failed.

    Raised when:
    - Client credentials are invalid
    - Token acquisition fails
    - Access token has expired and refresh fails
    """

    status_code: int = 401
    error_code: str = "GRAPH_AUTH_ERROR"


class GraphAPIRateLimitError(GraphAPIError):
    """Graph API rate limit exceeded.

    Raised when:
    - 429 Too Many Requests received
    - All retry attempts exhausted
    - Retry-After delay exceeds maximum wait time

    Attributes:
        retry_after: Seconds to wait before retrying (from Retry-After header)
    """

    status_code: int = 429
    error_code: str = "GRAPH_RATE_LIMIT"

    def __init__(
        self,
        message: str,
        *,
        retry_after: Optional[int] = None,
        tenant_id: Optional[str] = None,
        endpoint: Optional[str] = None,
    ):
        super().__init__(message, status_code=429, tenant_id=tenant_id, endpoint=endpoint)
        self.retry_after = retry_after


class GraphAPINotFoundError(GraphAPIError):
    """Requested resource not found in Graph API.

    Raised when:
    - User object ID does not exist
    - Group or role not found
    - Resource was deleted
    """

    status_code: int = 404
    error_code: str = "GRAPH_NOT_FOUND"


# =============================================================================
# Data Models
# =============================================================================


@dataclass(frozen=True)
class GraphAPIConfig:
    """Configuration for Microsoft Graph API client.

    Immutable configuration object containing all settings for GraphAPIClient.
    Use create_graph_api_config() factory for validated construction.

    Attributes:
        tenant_id: Azure AD tenant ID (GUID or domain)
        client_id: Application (client) ID for authentication
        client_secret: Client secret for authentication (wrapped in SecretStr)
        authority_url: Azure AD authority URL (auto-constructed from tenant_id)
        graph_base_url: Microsoft Graph API base URL
        scopes: OAuth scopes for Graph API access
        timeout_seconds: HTTP request timeout (1-60 seconds)
        max_retries: Maximum retry attempts for transient failures (0-5)
        backoff_base: Base delay for exponential backoff (0.1-5.0 seconds)
        max_retry_after: Maximum Retry-After delay to wait (seconds)
        user_agent: User-Agent header for requests
    """

    tenant_id: str
    client_id: str
    client_secret: SecretStr
    authority_url: str
    graph_base_url: str
    scopes: Tuple[str, ...]
    timeout_seconds: int
    max_retries: int
    backoff_base: float
    max_retry_after: int
    user_agent: str


# =============================================================================
# Token Record (for GraphTokenStore)
# =============================================================================


@dataclass(frozen=True)
class TokenRecord:
    """Immutable token record for distributed cache storage.

    Stores Graph API access token with metadata for serialization and cache
    management. Token is considered expired 5 minutes before actual expiration
    to allow for clock drift and network latency.

    Attributes:
        access_token: The access token (wrapped in SecretStr)
        expires_at: Unix timestamp when token expires
        token_type: Token type (usually "Bearer")

    Usage:
        record = TokenRecord(
            access_token=SecretStr("..."),
            expires_at=time.time() + 3600,
            token_type="Bearer",
        )
    """

    access_token: SecretStr
    expires_at: float
    token_type: str = "Bearer"

    @auto_trace(logger, disabled=TraceDisabledReason.TRIVIAL_GETTER)
    def is_expired(self, buffer_seconds: int = 300) -> bool:
        """Check if token is expired or will expire soon.

        Args:
            buffer_seconds: Buffer time before actual expiration (default: 5 minutes)

        Returns:
            True if token is expired or will expire within buffer time
        """
        return time.time() >= (self.expires_at - buffer_seconds)

    @auto_trace(logger, disabled=TraceDisabledReason.TRIVIAL_GETTER)
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary for cache storage.

        Note: access_token is serialized as plain string for JSON compatibility.
        The value is still protected in transit/at rest by cache encryption.

        Returns:
            Dictionary with token_type, expires_at, access_token
        """
        return {
            "access_token": self.access_token.get_secret_value(),
            "expires_at": self.expires_at,
            "token_type": self.token_type,
        }

    @classmethod
    @auto_trace(logger, disabled=TraceDisabledReason.TRIVIAL_GETTER)
    def from_dict(cls, data: Dict[str, Any]) -> "TokenRecord":
        """Deserialize from dictionary.

        Args:
            data: Dictionary with access_token, expires_at, token_type

        Returns:
            TokenRecord instance
        """
        return cls(
            access_token=SecretStr(data["access_token"]),
            expires_at=data["expires_at"],
            token_type=data.get("token_type", "Bearer"),
        )


# =============================================================================
# Graph Token Store (Redis-backed)
# =============================================================================


class GraphTokenStore:
    """Redis-backed Graph API token cache with namespace-aware keys.

    Replaces in-memory token caching with distributed cache storage. Uses
    CacheBackend protocol for Redis (or other distributed cache) storage,
    enabling Graph API tokens to be shared across multiple application instances.

    Key Format:
        {namespace.base()}:graph_token:{tenant_id}

    Thread Safety:
        All operations are async and thread-safe through the CacheBackend interface.

    Security:
        - Tokens stored using SecretStr wrapper
        - Cache encryption recommended for at-rest protection
        - TTL computed from token expiration with safety buffer

    Args:
        backend: Cache backend implementation (required - fail fast on misconfiguration)
        namespace: Cache namespace for hierarchical key prefixing (required)
        expiry_buffer_seconds: Safety buffer before actual expiration (default: 300 = 5 min)

    Usage:
        from neoaxios_secure_cache.backends.redis import RedisCacheBackend
        from neoaxios_secure_cache import CacheNamespace
        from neoaxios_fastapi_kit.auth.authn.decoders.providers.azure_graph import (
            GraphTokenStore,
            TokenRecord,
        )

        namespace = CacheNamespace(
            org="neo",
            env="prod",
            service="auth-api",
            app="gateway",
        )
        backend = RedisCacheBackend(url="redis://localhost:6379")
        store = GraphTokenStore(backend=backend, namespace=namespace)

        # Cache token
        record = TokenRecord(
            access_token=SecretStr("..."),
            expires_at=time.time() + 3600,
            token_type="Bearer",
        )
        await store.set("tenant123", record)

        # Retrieve cached token
        cached = await store.get("tenant123")
        if cached and not cached.is_expired():
            use_token(cached.access_token)

        # Delete token (e.g., on logout or credential rotation)
        await store.delete("tenant123")
    """

    def __init__(
        self,
        backend: "CacheBackend",
        namespace: "CacheNamespace",
        expiry_buffer_seconds: int = 300,
    ) -> None:
        """Initialize Graph token store.

        Args:
            backend: Cache backend (required)
            namespace: Cache namespace (required)
            expiry_buffer_seconds: Buffer before expiration for TTL calculation (default: 300)
        """
        self._backend = backend
        self._namespace = namespace
        self._expiry_buffer_seconds = expiry_buffer_seconds

    @auto_trace(logger)
    async def get(self, tenant_id: str) -> Optional[TokenRecord]:
        """Get cached token for tenant.

        Args:
            tenant_id: Azure AD tenant ID

        Returns:
            TokenRecord if valid cache entry exists, None otherwise
        """
        key = graph_token_key(self._namespace, tenant_id)
        result = await self._backend.get(key)

        if result is not None:
            try:
                record = TokenRecord.from_dict(result)
                # Check if token is expired
                if record.is_expired(self._expiry_buffer_seconds):
                    logger.debug(
                        f"Graph token expired: tenant_id={tenant_id}, "
                        f"expires_at={record.expires_at}"
                    )
                    # Clean up expired entry
                    await self._backend.delete(key)
                    return None

                logger.debug(
                    f"Graph token store hit: tenant_id={tenant_id}, "
                    f"expires_at={record.expires_at}"
                )
                return record
            except (KeyError, TypeError) as e:
                logger.warning(
                    f"Invalid cached token data: tenant_id={tenant_id}, error={e}"
                )
                await self._backend.delete(key)
                return None

        logger.debug(f"Graph token store miss: tenant_id={tenant_id}")
        return None

    @auto_trace(logger)
    async def set(self, tenant_id: str, record: TokenRecord) -> None:
        """Cache token for tenant.

        TTL is computed from the token's expires_at minus safety buffer,
        ensuring the cache entry expires before the token becomes invalid.

        Args:
            tenant_id: Azure AD tenant ID
            record: TokenRecord with access_token, expires_at, token_type
        """
        key = graph_token_key(self._namespace, tenant_id)

        # Compute TTL from expiration time minus buffer
        ttl = int(record.expires_at - time.time() - self._expiry_buffer_seconds)

        if ttl <= 0:
            logger.warning(
                f"Token already expired or expires too soon: tenant_id={tenant_id}, "
                f"expires_at={record.expires_at}, computed_ttl={ttl}"
            )
            return

        # Store serialized token
        await self._backend.set(key, record.to_dict(), ttl_seconds=ttl)

        logger.debug(
            f"Graph token store set: tenant_id={tenant_id}, "
            f"expires_at={record.expires_at}, ttl={ttl}s"
        )

    @auto_trace(logger)
    async def delete(self, tenant_id: str) -> bool:
        """Delete cached token for tenant.

        Used for explicit invalidation (logout, credential rotation, etc.).

        Args:
            tenant_id: Azure AD tenant ID

        Returns:
            True if entry existed and was deleted, False otherwise
        """
        key = graph_token_key(self._namespace, tenant_id)
        existed = await self._backend.exists(key)
        await self._backend.delete(key)

        if existed:
            logger.info(f"Graph token store deleted: tenant_id={tenant_id}")

        return existed



# =============================================================================
# Graph API Client
# =============================================================================


class GraphAPIClient:
    """Async HTTP client for Microsoft Graph API operations.

    Production-ready client for interacting with Microsoft Graph API to support
    Azure AD token validation workflows. Provides per-tenant credential isolation,
    automatic token management, and robust error handling.

    Features:
    - Async HTTP client with connection pooling
    - Per-tenant client credentials OAuth flow
    - Thread-safe token caching with asyncio.Lock
    - Exponential backoff retry logic for transient failures
    - Rate limiting support with Retry-After header handling
    - HTTPS-only (HTTP rejected for security)
    - Comprehensive error handling with context

    The client manages its own HTTP client lifecycle. Call close() when done
    or use as async context manager:

        async with GraphAPIClient(tenant_id, client_id, client_secret) as client:
            user = await client.get_user(object_id)

    Thread Safety:
        - Token cache protected by asyncio.Lock
        - Safe for concurrent use in async context
        - HTTP client is connection-pooled

    Security:
        - Credentials never logged or included in error messages
        - HTTPS enforced for all API calls
        - SSL verification always enabled
        - Token cached per-tenant instance (no global state)
    """

    # Default Microsoft Graph API base URL
    DEFAULT_GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"

    # Default Azure AD authority URL template
    DEFAULT_AUTHORITY_TEMPLATE = "https://login.microsoftonline.com/{tenant_id}"

    # Default scope for Microsoft Graph API
    DEFAULT_SCOPES = ("https://graph.microsoft.com/.default",)

    # Transient HTTP status codes that should trigger retry
    RETRYABLE_STATUS_CODES = frozenset({429, 500, 502, 503, 504})

    @auto_trace(logger)
    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: Union[SecretStr, str],
        *,
        authority_url: Optional[str] = None,
        graph_base_url: Optional[str] = None,
        scopes: Optional[Tuple[str, ...]] = None,
        timeout_seconds: int = 30,
        max_retries: int = HTTPX_MAX_RETRIES,
        backoff_base: float = 0.5,
        max_retry_after: int = 60,
        user_agent: str = "neoaxios-fastapi-kit-graph/1.0",
        token_store: Optional["GraphTokenStore"] = None,
    ):
        """Initialize Graph API client with tenant credentials.

        Creates an async HTTP client configured for Microsoft Graph API access
        using client credentials OAuth flow. The client is ready for use after
        construction but does not make network calls until methods are invoked.

        Args:
            tenant_id: Azure AD tenant ID (GUID like "12345678-1234-1234-1234-123456789abc"
                      or verified domain like "contoso.onmicrosoft.com")
            client_id: Application (client) ID from Azure AD app registration
            client_secret: Client secret value from Azure AD app registration.
                          SECURITY: Never log or expose this value.
            authority_url: Azure AD authority URL. Defaults to
                          "https://login.microsoftonline.com/{tenant_id}".
                          Override for sovereign clouds (e.g., Azure Government).
            graph_base_url: Microsoft Graph API base URL. Defaults to
                           "https://graph.microsoft.com/v1.0".
                           Override for sovereign clouds or beta API.
            scopes: OAuth scopes for token request. Defaults to
                   ("https://graph.microsoft.com/.default",) for app-only access.
            timeout_seconds: HTTP request timeout in seconds (default: 30).
                           Range: 1-60 seconds. Applied to all API calls.
            max_retries: Maximum retry attempts for transient failures (default: 3).
                        Range: 0-5. Set to 0 to disable retries.
            backoff_base: Base delay for exponential backoff in seconds (default: 0.5).
                         Range: 0.1-5.0. Delay = base * (2 ** retry_attempt).
            max_retry_after: Maximum Retry-After delay to wait in seconds (default: 60).
                            If server requests longer delay, error is raised immediately.
            user_agent: User-Agent header for requests (default: neoaxios-fastapi-kit-graph/1.0).
            token_store: Token store with CacheBackend and CacheNamespace.
                        Required. Raises ValueError if not provided.

        Raises:
            GraphAPIError: If configuration parameters are invalid

        Example:
            # Basic configuration
            client = GraphAPIClient(
                tenant_id="12345678-1234-1234-1234-123456789abc",
                client_id="app-client-id",
                client_secret="app-client-secret",
            )

            # Custom configuration for Azure Government
            client = GraphAPIClient(
                tenant_id="tenant-id",
                client_id="client-id",
                client_secret="secret",
                authority_url="https://login.microsoftonline.us/tenant-id",
                graph_base_url="https://graph.microsoft.us/v1.0",
            )

            # Fast-fail configuration (no retries)
            client = GraphAPIClient(
                tenant_id="tenant-id",
                client_id="client-id",
                client_secret="secret",
                max_retries=0,
                timeout_seconds=10,
            )
        """
        # Validate required parameters
        self._validate_required_params(tenant_id, client_id, client_secret)

        # Validate numeric parameters
        self._validate_timeout(timeout_seconds, max_retries, backoff_base)

        # Store configuration (credentials kept private)
        # Wrap client_secret in SecretStr if not already
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret: SecretStr = (
            client_secret if isinstance(client_secret, SecretStr)
            else SecretStr(client_secret)
        )

        # Build authority URL if not provided
        self._authority_url = authority_url or self.DEFAULT_AUTHORITY_TEMPLATE.format(
            tenant_id=tenant_id
        )

        # Validate authority URL is HTTPS
        self._validate_https_url(self._authority_url, "authority_url")

        # Set Graph API base URL
        self._graph_base_url = graph_base_url or self.DEFAULT_GRAPH_BASE_URL

        # Validate Graph base URL is HTTPS
        self._validate_https_url(self._graph_base_url, "graph_base_url")

        # Set OAuth scopes
        self._scopes = scopes or self.DEFAULT_SCOPES

        # Store timeout and retry configuration
        self._timeout_seconds = timeout_seconds
        self._max_retries = max_retries
        self._backoff_base = backoff_base
        self._max_retry_after = max_retry_after
        self._user_agent = user_agent

        # Initialize token caching (required)
        if token_store is None:
            raise ValueError(
                "GraphAPIClient requires token_store parameter. "
                "Pass a GraphTokenStore instance with CacheBackend and CacheNamespace "
                "for distributed caching."
            )
        self._token_store: "GraphTokenStore" = token_store
        self._token_lock = asyncio.Lock()

        # Create async HTTP client with connection pooling
        self._http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout_seconds),
            headers={"User-Agent": user_agent},
            limits=httpx.Limits(max_keepalive_connections=HTTPX_MAX_KEEPALIVE_CONNECTIONS, max_connections=HTTPX_MAX_CONNECTIONS),
            verify=True,  # Always validate SSL certificates
        )

        # Track client state
        self._closed = False

        logger.info(
            f"Initialized GraphAPIClient: tenant_id={tenant_id}, "
            f"authority_url={self._authority_url}, "
            f"graph_base_url={self._graph_base_url}, "
            f"timeout={timeout_seconds}s, max_retries={max_retries}"
        )

    @auto_trace(logger)
    def _validate_required_params(
        self, tenant_id: str, client_id: str, client_secret: Union[SecretStr, str]
    ) -> None:
        """Validate required constructor parameters.

        Args:
            tenant_id: Azure AD tenant ID
            client_id: Application client ID
            client_secret: Client secret (SecretStr or str)

        Raises:
            GraphAPIError: If any required parameter is missing or empty
        """
        if not tenant_id or not tenant_id.strip():
            error = GraphAPIError(
                "tenant_id is required and cannot be empty",
                status_code=400,
            )
            logger.log_error(error=error)
            raise error

        if not client_id or not client_id.strip():
            error = GraphAPIError(
                "client_id is required and cannot be empty",
                status_code=400,
            )
            logger.log_error(error=error)
            raise error

        # Extract secret value for validation
        secret_value = (
            client_secret.get_secret_value() if isinstance(client_secret, SecretStr)
            else client_secret
        )
        if not secret_value:
            error = GraphAPIError(
                "client_secret is required",
                status_code=400,
            )
            logger.log_error(error=error)
            raise error

    @auto_trace(logger)
    def _validate_timeout(
        self, timeout_seconds: int, max_retries: int, backoff_base: float
    ) -> None:
        """Validate timeout and retry configuration.

        Ensures:
        - Timeout is within valid range (1-60 seconds)
        - Max retries is within valid range (0-5)
        - Backoff base is within valid range (0.1-5.0 seconds)
        - Timeout is sufficient for retry strategy

        Args:
            timeout_seconds: HTTP request timeout
            max_retries: Maximum retry attempts
            backoff_base: Exponential backoff base delay

        Raises:
            GraphAPIError: If parameters are invalid or inconsistent
        """
        if timeout_seconds < 1 or timeout_seconds > 60:
            error = GraphAPIError(
                f"timeout_seconds must be between 1 and 60, got {timeout_seconds}",
                status_code=400,
            )
            logger.log_error(error=error)
            raise error

        if max_retries < 0 or max_retries > 5:
            error = GraphAPIError(
                f"max_retries must be between 0 and 5, got {max_retries}",
                status_code=400,
            )
            logger.log_error(error=error)
            raise error

        if backoff_base < 0.1 or backoff_base > 5.0:
            error = GraphAPIError(
                f"backoff_base must be between 0.1 and 5.0, got {backoff_base}",
                status_code=400,
            )
            logger.log_error(error=error)
            raise error

        # Validate timeout is sufficient for maximum backoff
        if max_retries > 0:
            max_backoff = backoff_base * (2**max_retries)
            if timeout_seconds <= max_backoff:
                error = GraphAPIError(
                    f"timeout_seconds ({timeout_seconds}) should be greater than "
                    f"max possible backoff delay ({max_backoff:.1f}s) for "
                    f"max_retries={max_retries} and backoff_base={backoff_base}",
                    status_code=400,
                )
                logger.log_error(error=error)
                raise error

    @auto_trace(logger)
    def _validate_https_url(self, url: str, param_name: str) -> None:
        """Validate URL uses HTTPS scheme.

        Security requirement: All Graph API communication must use HTTPS.
        HTTP is rejected to prevent credential interception.

        Args:
            url: URL to validate
            param_name: Parameter name for error messages

        Raises:
            GraphAPIError: If URL does not use HTTPS
        """
        parsed = urlparse(url)
        if parsed.scheme != "https":
            error = GraphAPIError(
                f"{param_name} must use HTTPS, got: {parsed.scheme}://",
                status_code=400,
            )
            logger.log_error(error=error)
            raise error

    # -------------------------------------------------------------------------
    # Context Manager Protocol
    # -------------------------------------------------------------------------

    async def __aenter__(self) -> "GraphAPIClient":
        """Async context manager entry.

        Returns:
            Self for use in async with statement
        """
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit with cleanup.

        Ensures HTTP client is properly closed even if exception occurs.
        """
        await self.close()

    @auto_trace(logger)
    async def close(self) -> None:
        """Close HTTP client and cleanup resources.

        Always call this method when done with the client, or use the client
        as an async context manager to ensure cleanup.

        Safe to call multiple times (idempotent).

        Example:
            client = GraphAPIClient(tenant_id, client_id, client_secret)
            try:
                user = await client.get_user(object_id)
            finally:
                await client.close()
        """
        if self._closed:
            return

        if self._http_client:
            await self._http_client.aclose()
            logger.debug("Closed HTTP client")

        self._closed = True

        logger.info(f"GraphAPIClient closed: tenant_id={self._tenant_id}")

    # -------------------------------------------------------------------------
    # Properties
    # -------------------------------------------------------------------------

    @property
    def tenant_id(self) -> str:
        """Get tenant ID (read-only)."""
        return self._tenant_id

    @property
    def is_closed(self) -> bool:
        """Check if client has been closed."""
        return self._closed

    # -------------------------------------------------------------------------
    # Token Management (Private)
    # -------------------------------------------------------------------------

    @auto_trace(logger)
    async def _get_access_token(self) -> str:
        """Get valid access token for Graph API requests.

        Acquires access token using client credentials OAuth flow. Tokens are
        cached per-tenant with thread-safe access via asyncio.Lock. Expired
        tokens are automatically refreshed.

        Uses distributed Redis cache via GraphTokenStore for token storage.

        Returns:
            Valid access token string

        Raises:
            GraphAPIAuthenticationError: If token acquisition fails

        Thread Safety:
            Uses asyncio.Lock to prevent concurrent token refresh
        """
        async with self._token_lock:
            # Check distributed cache first
            cached_record = await self._token_store.get(self._tenant_id)
            if cached_record is not None and not cached_record.is_expired():
                logger.debug(
                    f"Using distributed cache token for tenant_id={self._tenant_id}, "
                    f"expires_at={cached_record.expires_at}"
                )
                return cached_record.access_token.get_secret_value()

            # Acquire new token
            logger.info(f"Acquiring new access token for tenant_id={self._tenant_id}")

            token_url = f"{self._authority_url}/oauth2/v2.0/token"

            # Prepare token request (client credentials flow)
            # Extract secret value for HTTP request
            token_data = {
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret.get_secret_value(),
                "scope": " ".join(self._scopes),
            }

            try:
                response = await self._http_client.post(
                    token_url,
                    data=token_data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )

                if response.status_code == 200:
                    token_response = response.json()

                    # Extract token info
                    access_token = token_response.get("access_token")
                    expires_in = token_response.get("expires_in", 3600)
                    token_type = token_response.get("token_type", "Bearer")

                    if not access_token:
                        error = GraphAPIAuthenticationError(
                            "Token response missing access_token",
                            tenant_id=self._tenant_id,
                        )
                        logger.log_error(error=error)
                        raise error

                    # Cache token with expiration
                    # Wrap access_token in SecretStr
                    expires_at = time.time() + expires_in

                    # Store in distributed cache
                    token_record = TokenRecord(
                        access_token=SecretStr(access_token),
                        expires_at=expires_at,
                        token_type=token_type,
                    )
                    await self._token_store.set(self._tenant_id, token_record)

                    logger.info(
                        f"Acquired access token for tenant_id={self._tenant_id}, "
                        f"expires_in={expires_in}s"
                    )

                    return access_token  # Return raw string for immediate use

                # Handle error response
                error_msg = self._extract_error_message(response)
                error = GraphAPIAuthenticationError(
                    f"Failed to acquire access token: {error_msg}",
                    tenant_id=self._tenant_id,
                    status_code=response.status_code,
                )
                logger.log_error(error=error)
                raise error

            except httpx.TimeoutException as e:
                error = GraphAPIAuthenticationError(
                    "Timeout acquiring access token",
                    tenant_id=self._tenant_id,
                )
                logger.log_error(error=error)
                raise error from e

            except httpx.RequestError as e:
                error = GraphAPIAuthenticationError(
                    "Network error acquiring access token",
                    tenant_id=self._tenant_id,
                )
                logger.log_error(error=error)
                raise error from e

    @auto_trace(logger)
    def _extract_error_message(self, response: httpx.Response) -> str:
        """Extract error message from API response.

        Attempts to parse Microsoft Graph error format:
        {
            "error": {
                "code": "Authorization_RequestDenied",
                "message": "Insufficient privileges"
            }
        }

        Args:
            response: HTTP response object

        Returns:
            Error message string (without sensitive data)
        """
        try:
            error_data = response.json()
            error_obj = error_data.get("error", {})

            if isinstance(error_obj, dict):
                code = error_obj.get("code", "Unknown")
                message = error_obj.get("message", "No message")
                return f"[{code}] {message}"

            return str(error_data)[:200]
        except Exception:
            return f"HTTP {response.status_code}: {response.text[:200]}"

    @auto_trace(logger)
    def _extract_graph_error_code(self, response: httpx.Response) -> Optional[str]:
        """Extract Microsoft Graph error code from response.

        Args:
            response: HTTP response object

        Returns:
            Graph error code string or None
        """
        try:
            error_data = response.json()
            error_obj = error_data.get("error", {})
            if isinstance(error_obj, dict):
                return error_obj.get("code")
        except Exception:
            pass
        return None

    # -------------------------------------------------------------------------
    # HTTP Request Methods (Private)
    # -------------------------------------------------------------------------

    @auto_trace(logger)
    async def _request_with_retry(
        self,
        method: str,
        url: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
        retry_on_auth_failure: bool = True,
    ) -> Dict[str, Any]:
        """Make HTTP request with retry logic.

        Implements exponential backoff retry for transient failures (5xx, 429).
        Handles 401 by refreshing access token and retrying once.
        Respects Retry-After header for rate limiting.

        Args:
            method: HTTP method (GET, POST, etc.)
            url: Full URL to request
            json_body: Optional JSON body for POST requests
            retry_on_auth_failure: Whether to retry on 401 (default: True)

        Returns:
            Parsed JSON response as dictionary

        Raises:
            GraphAPIError: If all retries fail or non-retryable error occurs
            GraphAPIRateLimitError: If rate limited after retries
            GraphAPINotFoundError: If resource not found (404)
            GraphAPIAuthenticationError: If authentication fails after retry
        """
        last_error: Optional[Exception] = None
        auth_retry_done = False

        for attempt in range(self._max_retries + 1):
            try:
                # Exponential backoff (skip delay on first attempt)
                if attempt > 0:
                    delay = self._backoff_base * (2 ** (attempt - 1))
                    logger.debug(
                        f"Retry attempt {attempt}/{self._max_retries} "
                        f"after {delay}s delay, url={url}"
                    )
                    await asyncio.sleep(delay)

                # Get access token
                access_token = await self._get_access_token()

                # Prepare headers
                headers = {
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json",
                    "ConsistencyLevel": "eventual",  # Required for some Graph queries
                }

                # Make request
                if method.upper() == "GET":
                    response = await self._http_client.get(url, headers=headers)
                elif method.upper() == "POST":
                    response = await self._http_client.post(
                        url, headers=headers, json=json_body
                    )
                else:
                    error = GraphAPIError(
                        f"Unsupported HTTP method: {method}",
                        status_code=400,
                        tenant_id=self._tenant_id,
                    )
                    logger.log_error(error=error)
                    raise error

                # Record metrics
                logger.record_metric(
                    name="graph_api_request",
                    value=response.elapsed.total_seconds() if response.elapsed else 0,
                    tags={
                        "tenant_id": self._tenant_id,
                        "method": method,
                        "status_code": str(response.status_code),
                        "endpoint": self._sanitize_endpoint(url),
                    },
                )

                # Handle success
                if response.status_code == 200:
                    try:
                        return response.json()
                    except Exception as e:
                        error = GraphAPIError(
                            "Failed to parse JSON response",
                            status_code=500,
                            tenant_id=self._tenant_id,
                            endpoint=url,
                        )
                        logger.log_error(error=error)
                        raise error from e

                # Handle 204 No Content (success with empty body)
                if response.status_code == 204:
                    return {}

                # Handle 401 Unauthorized - try token refresh once
                if response.status_code == 401:
                    if retry_on_auth_failure and not auth_retry_done:
                        logger.warning(
                            f"401 Unauthorized, refreshing token and retrying: url={url}"
                        )
                        auth_retry_done = True
                        # Clear cached token to force refresh
                        async with self._token_lock:
                            await self._token_store.delete(self._tenant_id)
                        continue

                    error = GraphAPIAuthenticationError(
                        f"Authentication failed: {self._extract_error_message(response)}",
                        tenant_id=self._tenant_id,
                        endpoint=url,
                        graph_error_code=self._extract_graph_error_code(response),
                    )
                    logger.log_error(error=error)
                    raise error

                # Handle 404 Not Found - do not retry
                if response.status_code == 404:
                    error = GraphAPINotFoundError(
                        f"Resource not found: {self._extract_error_message(response)}",
                        tenant_id=self._tenant_id,
                        endpoint=url,
                        graph_error_code=self._extract_graph_error_code(response),
                    )
                    logger.log_error(error=error)
                    raise error

                # Handle 429 Rate Limited
                if response.status_code == 429:
                    retry_after = self._parse_retry_after(response)

                    if retry_after and retry_after <= self._max_retry_after:
                        logger.warning(
                            f"Rate limited (429), waiting {retry_after}s before retry: "
                            f"url={url}, attempt={attempt}"
                        )
                        await asyncio.sleep(retry_after)
                        continue

                    error = GraphAPIRateLimitError(
                        f"Rate limit exceeded, retry_after={retry_after}s",
                        retry_after=retry_after,
                        tenant_id=self._tenant_id,
                        endpoint=url,
                    )
                    logger.log_error(error=error)
                    raise error

                # Handle other 4xx client errors - do not retry
                if 400 <= response.status_code < 500:
                    error = GraphAPIError(
                        f"Client error: {self._extract_error_message(response)}",
                        status_code=response.status_code,
                        tenant_id=self._tenant_id,
                        endpoint=url,
                        graph_error_code=self._extract_graph_error_code(response),
                    )
                    logger.log_error(error=error)
                    raise error

                # Handle 5xx server errors - retry
                if response.status_code >= 500:
                    last_error = GraphAPIError(
                        f"Server error: {self._extract_error_message(response)}",
                        status_code=response.status_code,
                        tenant_id=self._tenant_id,
                        endpoint=url,
                    )
                    logger.warning(
                        f"Server error (will retry): status={response.status_code}, "
                        f"attempt={attempt}, url={url}"
                    )
                    continue

                # Unexpected status code
                last_error = GraphAPIError(
                    f"Unexpected response: {self._extract_error_message(response)}",
                    status_code=response.status_code,
                    tenant_id=self._tenant_id,
                    endpoint=url,
                )
                logger.warning(
                    f"Unexpected status (will retry): status={response.status_code}, "
                    f"attempt={attempt}, url={url}"
                )

            except (GraphAPIError, GraphAPIAuthenticationError, GraphAPINotFoundError):
                # Already logged, re-raise
                raise

            except httpx.TimeoutException:
                last_error = GraphAPIError(
                    "Request timeout",
                    status_code=504,
                    tenant_id=self._tenant_id,
                    endpoint=url,
                )
                logger.warning(
                    f"Timeout (will retry): attempt={attempt}, url={url}"
                )

            except httpx.RequestError:
                last_error = GraphAPIError(
                    "Network error",
                    status_code=503,
                    tenant_id=self._tenant_id,
                    endpoint=url,
                )
                logger.warning(
                    f"Network error (will retry): attempt={attempt}, url={url}"
                )

            except Exception as e:
                # Unexpected error - do not retry
                error = GraphAPIError(
                    "Unexpected error",
                    status_code=500,
                    tenant_id=self._tenant_id,
                    endpoint=url,
                )
                logger.log_error(error=error)
                raise error from e

        # All retries exhausted
        if last_error:
            logger.log_error(error=last_error)
            raise last_error

        # Should not reach here, but handle defensively
        error = GraphAPIError(
            f"Request failed after {self._max_retries + 1} attempts",
            status_code=500,
            tenant_id=self._tenant_id,
            endpoint=url,
        )
        logger.log_error(error=error)
        raise error

    @auto_trace(logger)
    def _parse_retry_after(self, response: httpx.Response) -> Optional[int]:
        """Parse Retry-After header from response.

        Supports both integer seconds and HTTP-date formats.

        Args:
            response: HTTP response object

        Returns:
            Number of seconds to wait, or None if header not present/parseable
        """
        retry_after = response.headers.get("Retry-After")
        if not retry_after:
            return None

        try:
            # Try parsing as integer seconds
            return int(retry_after)
        except ValueError:
            # Could be HTTP-date format, default to reasonable value
            logger.debug(f"Could not parse Retry-After header: {retry_after}")
            return 60

    @auto_trace(logger)
    def _sanitize_endpoint(self, url: str) -> str:
        """Sanitize endpoint URL for logging/metrics.

        Removes user IDs and other sensitive path components.

        Args:
            url: Full URL

        Returns:
            Sanitized endpoint pattern
        """
        # Extract path from URL
        parsed = urlparse(url)
        path = parsed.path

        # Replace GUIDs with placeholder
        import re
        sanitized = re.sub(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "{id}",
            path,
            flags=re.IGNORECASE,
        )

        return sanitized

    # -------------------------------------------------------------------------
    # Public API Methods
    # -------------------------------------------------------------------------

    @auto_trace(logger)
    async def introspect_token(self, token: str) -> Dict[str, Any]:
        """Introspect an access token for validity and claims.

        Uses Microsoft Graph API to validate token and retrieve associated user
        information. This is useful for opaque tokens or when additional
        validation beyond JWT verification is needed.

        Note: Microsoft Graph API does not have a dedicated token introspection
        endpoint. This method retrieves the /me endpoint using the provided token
        to verify token validity and get user info.

        Args:
            token: Access token to introspect

        Returns:
            Dictionary with token info:
            {
                "active": True/False,
                "user_id": "object-id" (if active),
                "display_name": "User Name" (if active),
                "email": "user@example.com" (if active),
                "tenant_id": "tenant-id",
            }

        Raises:
            GraphAPIError: If introspection fails due to network/server error

        Notes:
            - Returns {"active": False} for invalid/expired tokens instead of raising
            - This is a client-provided token, not using service credentials
        """
        logger.info(f"Introspecting token for tenant_id={self._tenant_id}")

        # Use /me endpoint with provided token to validate and get user info
        url = f"{self._graph_base_url}/me"

        try:
            # Make request with provided token (not service credentials)
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }

            response = await self._http_client.get(url, headers=headers)

            # Record metrics
            logger.record_metric(
                name="graph_api_introspect",
                value=response.elapsed.total_seconds() if response.elapsed else 0,
                tags={
                    "tenant_id": self._tenant_id,
                    "status_code": str(response.status_code),
                },
            )

            if response.status_code == 200:
                user_data = response.json()
                result = {
                    "active": True,
                    "user_id": user_data.get("id"),
                    "display_name": user_data.get("displayName"),
                    "email": user_data.get("mail") or user_data.get("userPrincipalName"),
                    "tenant_id": self._tenant_id,
                }
                logger.info(
                    f"Token introspection successful: user_id={result.get('user_id')}"
                )
                return result

            # Token is invalid or expired
            logger.info(
                f"Token introspection failed: status={response.status_code}"
            )
            return {
                "active": False,
                "tenant_id": self._tenant_id,
            }

        except httpx.TimeoutException:
            error = GraphAPIError(
                "Token introspection timeout",
                status_code=504,
                tenant_id=self._tenant_id,
                endpoint="/me",
            )
            logger.log_error(error=error)
            raise error

        except httpx.RequestError:
            error = GraphAPIError(
                "Token introspection network error",
                status_code=503,
                tenant_id=self._tenant_id,
                endpoint="/me",
            )
            logger.log_error(error=error)
            raise error

    @auto_trace(logger)
    async def get_user(self, object_id: str) -> Dict[str, Any]:
        """Get user profile by object ID.

        Retrieves user profile from Microsoft Graph API including display name,
        email, job title, and other directory attributes.

        Args:
            object_id: Azure AD user object ID (GUID)

        Returns:
            User profile dictionary:
            {
                "id": "object-id",
                "displayName": "User Name",
                "mail": "user@example.com",
                "userPrincipalName": "user@tenant.onmicrosoft.com",
                "jobTitle": "Engineer",
                ...
            }

        Raises:
            GraphAPINotFoundError: If user not found
            GraphAPIError: If request fails

        Example:
            user = await client.get_user("12345678-1234-1234-1234-123456789abc")
            logger.info(f"User: {user['displayName']}")
        """
        if not object_id or not object_id.strip():
            error = GraphAPIError(
                "object_id is required",
                status_code=400,
                tenant_id=self._tenant_id,
            )
            logger.log_error(error=error)
            raise error

        logger.info(
            f"Getting user profile: object_id={object_id}, tenant_id={self._tenant_id}"
        )

        url = f"{self._graph_base_url}/users/{object_id}"

        try:
            user_data = await self._request_with_retry("GET", url)
            logger.info(
                f"Retrieved user profile: object_id={object_id}, "
                f"displayName={user_data.get('displayName')}"
            )
            return user_data

        except GraphAPINotFoundError:
            logger.warning(
                f"User not found: object_id={object_id}, tenant_id={self._tenant_id}"
            )
            raise

    @auto_trace(logger)
    async def get_user_groups(self, object_id: str) -> List[str]:
        """Get user's group memberships.

        Retrieves all groups the user is a member of, including transitive
        memberships (groups containing groups the user belongs to).

        Args:
            object_id: Azure AD user object ID (GUID)

        Returns:
            List of group display names. Empty list if user has no groups
            or if groups cannot be retrieved.

        Raises:
            GraphAPIError: If request fails with server error

        Notes:
            - Returns empty list for 404 (user not found) for graceful degradation
            - Uses transitive membership to include nested group memberships
            - Maximum 999 groups returned per request (pagination not implemented)

        Example:
            groups = await client.get_user_groups("12345678-1234-1234-1234-123456789abc")
            logger.info(f"User is member of: {groups}")
        """
        if not object_id or not object_id.strip():
            logger.warning("get_user_groups called with empty object_id")
            return []

        logger.info(
            f"Getting user groups: object_id={object_id}, tenant_id={self._tenant_id}"
        )

        # Use transitive membership to get all groups including nested
        url = (
            f"{self._graph_base_url}/users/{object_id}"
            f"/transitiveMemberOf/microsoft.graph.group"
            f"?$select=displayName&$top=999"
        )

        try:
            response_data = await self._request_with_retry("GET", url)

            # Extract group names from response
            groups = []
            for group in response_data.get("value", []):
                display_name = group.get("displayName")
                if display_name:
                    groups.append(display_name)

            logger.info(
                f"Retrieved {len(groups)} groups for user: object_id={object_id}"
            )
            return groups

        except GraphAPINotFoundError:
            # User not found - return empty list for graceful degradation
            logger.warning(
                f"User not found when getting groups: object_id={object_id}"
            )
            return []

        except GraphAPIError as e:
            # Log but return empty list for non-critical failures
            if e.status_code >= 500:
                raise
            logger.warning(
                f"Failed to get user groups: object_id={object_id}, error={e.message}"
            )
            return []

    @auto_trace(logger)
    async def get_directory_roles(self, object_id: str) -> List[str]:
        """Get user's directory role assignments.

        Retrieves all Azure AD directory roles assigned to the user, including
        transitive assignments through role-assignable groups.

        Args:
            object_id: Azure AD user object ID (GUID)

        Returns:
            List of directory role display names. Empty list if user has no roles
            or if roles cannot be retrieved.

        Raises:
            GraphAPIError: If request fails with server error

        Notes:
            - Returns empty list for 404 (user not found) for graceful degradation
            - Uses transitive membership to include roles assigned through groups
            - Common roles: "Global Administrator", "User Administrator", etc.

        Example:
            roles = await client.get_directory_roles("12345678-...")
            if "Global Administrator" in roles:
                logger.info("User is a global admin")
        """
        if not object_id or not object_id.strip():
            logger.warning("get_directory_roles called with empty object_id")
            return []

        logger.info(
            f"Getting directory roles: object_id={object_id}, tenant_id={self._tenant_id}"
        )

        # Use transitive membership to get all directory roles
        url = (
            f"{self._graph_base_url}/users/{object_id}"
            f"/transitiveMemberOf/microsoft.graph.directoryRole"
            f"?$select=displayName&$top=999"
        )

        try:
            response_data = await self._request_with_retry("GET", url)

            # Extract role names from response
            roles = []
            for role in response_data.get("value", []):
                display_name = role.get("displayName")
                if display_name:
                    roles.append(display_name)

            logger.info(
                f"Retrieved {len(roles)} directory roles for user: object_id={object_id}"
            )
            return roles

        except GraphAPINotFoundError:
            # User not found - return empty list for graceful degradation
            logger.warning(
                f"User not found when getting roles: object_id={object_id}"
            )
            return []

        except GraphAPIError as e:
            # Log but return empty list for non-critical failures
            if e.status_code >= 500:
                raise
            logger.warning(
                f"Failed to get directory roles: object_id={object_id}, error={e.message}"
            )
            return []


# =============================================================================
# Factory Function
# =============================================================================


@auto_trace(logger)
def create_graph_api_client(
    tenant_id: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[Union[SecretStr, str]] = None,
    *,
    authority_url: Optional[str] = None,
    graph_base_url: Optional[str] = None,
    timeout_seconds: Optional[int] = None,
    max_retries: Optional[int] = None,
    backoff_base: Optional[float] = None,
    token_store: Optional["GraphTokenStore"] = None,
) -> GraphAPIClient:
    """Factory function for GraphAPIClient instantiation.

    Creates a GraphAPIClient with configuration from parameters or environment
    variables. Validates all required configuration is present.

    Environment Variables (used if parameters not provided):
    - AZURE_TENANT_ID: Azure AD tenant ID
    - AZURE_CLIENT_ID: Application (client) ID
    - AZURE_CLIENT_SECRET: Client secret value
    - AZURE_GRAPH_TIMEOUT: Request timeout in seconds (default: 30)
    - AZURE_GRAPH_MAX_RETRIES: Maximum retry attempts (default: 3)
    - AZURE_AUTHORITY_URL: Azure AD authority URL (optional)
    - AZURE_GRAPH_BASE_URL: Graph API base URL (optional)

    Args:
        tenant_id: Azure AD tenant ID (or None to read from AZURE_TENANT_ID)
        client_id: Application client ID (or None to read from AZURE_CLIENT_ID)
        client_secret: Client secret (or None to read from AZURE_CLIENT_SECRET)
        authority_url: Azure AD authority URL override
        graph_base_url: Graph API base URL override
        timeout_seconds: Request timeout (or None to read from AZURE_GRAPH_TIMEOUT)
        max_retries: Max retry attempts (or None to read from AZURE_GRAPH_MAX_RETRIES)
        backoff_base: Exponential backoff base delay in seconds
        token_store: Redis-backed token store for distributed caching

    Returns:
        GraphAPIClient instance configured from parameters or environment

    Raises:
        GraphAPIError: If required configuration (tenant_id, client_id, client_secret)
                      is missing from both parameters and environment

    Example:
        # Create from environment variables
        client = create_graph_api_client()

        # Create with explicit parameters
        client = create_graph_api_client(
            tenant_id="12345678-1234-1234-1234-123456789abc",
            client_id="app-client-id",
            client_secret="app-client-secret",
            timeout_seconds=60,
        )

        # Mixed: some from params, some from environment
        client = create_graph_api_client(
            tenant_id="explicit-tenant",
            # client_id and client_secret read from environment
        )
    """
    # Read from environment if not provided
    tenant_id = tenant_id or os.getenv("AZURE_TENANT_ID")
    client_id = client_id or os.getenv("AZURE_CLIENT_ID")
    client_secret = client_secret or os.getenv("AZURE_CLIENT_SECRET")

    # Read optional config from environment
    authority_url = authority_url or os.getenv("AZURE_AUTHORITY_URL")
    graph_base_url = graph_base_url or os.getenv("AZURE_GRAPH_BASE_URL")

    # Read numeric config with defaults
    if timeout_seconds is None:
        env_timeout = os.getenv("AZURE_GRAPH_TIMEOUT")
        timeout_seconds = int(env_timeout) if env_timeout else 30

    if max_retries is None:
        env_retries = os.getenv("AZURE_GRAPH_MAX_RETRIES")
        max_retries = int(env_retries) if env_retries else HTTPX_MAX_RETRIES

    if backoff_base is None:
        backoff_base = 0.5

    # Validate required configuration
    if not tenant_id:
        error = GraphAPIError(
            "tenant_id is required. Provide via parameter or AZURE_TENANT_ID "
            "environment variable.",
            status_code=400,
        )
        logger.log_error(error=error)
        raise error

    if not client_id:
        error = GraphAPIError(
            "client_id is required. Provide via parameter or AZURE_CLIENT_ID "
            "environment variable.",
            status_code=400,
        )
        logger.log_error(error=error)
        raise error

    if not client_secret:
        error = GraphAPIError(
            "client_secret is required. Provide via parameter or AZURE_CLIENT_SECRET "
            "environment variable.",
            status_code=400,
        )
        logger.log_error(error=error)
        raise error

    logger.info(
        f"Creating GraphAPIClient from factory: tenant_id={tenant_id}, "
        f"timeout={timeout_seconds}s, max_retries={max_retries}"
    )

    return GraphAPIClient(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
        authority_url=authority_url,
        graph_base_url=graph_base_url,
        timeout_seconds=timeout_seconds,
        max_retries=max_retries,
        backoff_base=backoff_base,
        token_store=token_store,
    )


# =============================================================================
# Module Exports
# =============================================================================


__all__ = [
    # Client
    "GraphAPIClient",
    "GraphAPIConfig",
    # Redis-backed stores
    "TokenRecord",
    "GraphTokenStore",
    # Errors
    "GraphAPIError",
    "GraphAPIAuthenticationError",
    "GraphAPIRateLimitError",
    "GraphAPINotFoundError",
    # Factory
    "create_graph_api_client",
]
