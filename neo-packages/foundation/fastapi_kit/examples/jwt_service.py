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

"""Complete FastAPI service example with JWT authentication.

This example demonstrates:
- JWT token generation and validation
- Protected routes with permission checking
- Simple JWT decoder implementation
- Error handling for authentication failures
- Complete working service (approximately 100 lines)

Run this example:
    python examples/jwt_service.py

Test with:
    # Get token
    curl http://localhost:8000/generate-token

    # Access protected endpoint
    curl -H "Authorization: Bearer <token>" http://localhost:8000/documents
"""

import jwt
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthCredentials
from pydantic import BaseModel

from neoaxios_fastapi_kit.auth.context import IdentityContext
from neoaxios_logging import get_telemetry, auto_trace

# Initialize logger
logger = get_telemetry(__name__)

# Security scheme
security = HTTPBearer()


class SimpleJWTDecoder:
    """Simple JWT decoder for demonstration.

    Uses shared secret (HS256) for simplicity. Production should use RS256.
    """

    def __init__(self, secret: str, algorithm: str = "HS256", issuer: str = None):
        self.secret = secret
        self.algorithm = algorithm
        self.issuer = issuer

    @auto_trace(logger)
    async def decode(self, token: str) -> IdentityContext:
        """Decode and validate JWT token."""
        try:
            payload = jwt.decode(
                token,
                self.secret,
                algorithms=[self.algorithm],
                issuer=self.issuer,
                options={"verify_exp": True},
            )

            return IdentityContext(
                user_id=payload.get("sub"),
                tenant_id=payload.get("tenant_id", "default"),
                roles=frozenset(payload.get("roles", [])),
                permissions=frozenset(payload.get("permissions", [])),
                provider="local",
                issuer=payload.get("iss"),
            )

        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
            )
        except jwt.InvalidTokenError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token: {str(e)}",
            )

    @auto_trace(logger)
    async def validate(self, token: str) -> bool:
        """Check if token is valid."""
        try:
            await self.decode(token)
            return True
        except HTTPException:
            return False

    @auto_trace(logger)
    async def is_revoked(self, token: str) -> bool:
        """Check if token is revoked (always False for simple implementation)."""
        return False


# Application setup
app = FastAPI(
    title="JWT Authentication Example",
    description="Demonstrates JWT-based authentication with neoaxios_fastapi_kit",
    version="1.0.0",
)

# JWT decoder with shared secret
SECRET_KEY = "dev-secret-change-in-production"
decoder = SimpleJWTDecoder(
    secret=SECRET_KEY,
    issuer="https://local.test",
)


# Response models
class TokenResponse(BaseModel):
    """Token response model."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int


class Document(BaseModel):
    """Document model."""

    id: str
    title: str
    owner: str


# Dependency: Extract identity from token
async def get_current_identity(
    credentials: HTTPAuthCredentials = Depends(security),
) -> IdentityContext:
    """Extract identity from JWT token.

    Args:
        credentials: HTTP bearer credentials from request

    Returns:
        IdentityContext with user information

    Raises:
        HTTPException: If token is invalid
    """
    token = credentials.credentials
    return await decoder.decode(token)


# Dependency: Require specific permission
def require_permission(permission: str):
    """Create dependency that requires specific permission.

    Args:
        permission: Required permission (e.g., "document:read")

    Returns:
        Dependency function
    """

    async def check_permission(
        identity: IdentityContext = Depends(get_current_identity),
    ) -> IdentityContext:
        """Check if user has required permission."""
        if permission not in identity.permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required permission: {permission}",
            )
        return identity

    return check_permission


# Helper: Generate JWT token
def generate_token(
    user_id: str,
    tenant_id: str = "default",
    roles: list = None,
    permissions: list = None,
    expires_in: int = 3600,
) -> str:
    """Generate JWT token for testing.

    Args:
        user_id: User identifier
        tenant_id: Tenant identifier
        roles: List of role names
        permissions: List of permissions
        expires_in: Token expiry in seconds

    Returns:
        JWT token string
    """
    now = datetime.now(timezone.utc)

    payload = {
        "sub": user_id,
        "tenant_id": tenant_id,
        "roles": roles or [],
        "permissions": permissions or [],
        "iss": "https://local.test",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=expires_in)).timestamp()),
    }

    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


# Routes

@app.get("/")
async def root():
    """Public endpoint - no authentication required."""
    return {
        "message": "JWT Authentication Example",
        "endpoints": {
            "generate_token": "/generate-token",
            "documents": "/documents (requires auth)",
            "create_document": "/documents (POST, requires auth)",
        },
    }


@app.get("/generate-token", response_model=TokenResponse)
async def get_token(
    user_id: str = "user-123",
    permissions: str = "document:read,document:write",
):
    """Generate test JWT token.

    Args:
        user_id: User identifier
        permissions: Comma-separated permissions

    Returns:
        Token response with access token
    """
    token = generate_token(
        user_id=user_id,
        tenant_id="tenant-456",
        roles=["user", "editor"],
        permissions=permissions.split(","),
        expires_in=3600,
    )

    return TokenResponse(
        access_token=token,
        expires_in=3600,
    )


@app.get("/documents")
async def list_documents(
    identity: IdentityContext = Depends(require_permission("document:read")),
) -> list[Document]:
    """List documents - requires document:read permission.

    Args:
        identity: Current user identity (injected)

    Returns:
        List of documents
    """
    logger.info(
        "User listing documents",
        user_id=identity.user_id,
        tenant_id=identity.tenant_id,
    )

    return [
        Document(id="doc-1", title="Project Proposal", owner=identity.user_id),
        Document(id="doc-2", title="Meeting Notes", owner=identity.user_id),
    ]


@app.post("/documents")
async def create_document(
    document: Document,
    identity: IdentityContext = Depends(require_permission("document:write")),
) -> Document:
    """Create document - requires document:write permission.

    Args:
        document: Document to create
        identity: Current user identity (injected)

    Returns:
        Created document
    """
    logger.info(
        "User creating document",
        user_id=identity.user_id,
        document_id=document.id,
    )

    # Set owner to current user
    document.owner = identity.user_id
    return document


@app.get("/me")
async def get_current_user(
    identity: IdentityContext = Depends(get_current_identity),
):
    """Get current user information.

    Args:
        identity: Current user identity (injected)

    Returns:
        User information
    """
    return {
        "user_id": identity.user_id,
        "tenant_id": identity.tenant_id,
        "roles": list(identity.roles),
        "permissions": list(identity.permissions),
        "provider": identity.provider,
    }


# Error handlers

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Handle HTTP exceptions with consistent format."""
    return {
        "error": exc.detail,
        "status_code": exc.status_code,
    }


if __name__ == "__main__":
    import uvicorn

    print("=" * 60)
    print("JWT Authentication Example Service")
    print("=" * 60)
    print("\nStarting server at http://localhost:8000")
    print("\nTo get a token:")
    print("  curl http://localhost:8000/generate-token")
    print("\nTo access protected endpoint:")
    print("  curl -H 'Authorization: Bearer <token>' http://localhost:8000/documents")
    print("\n" + "=" * 60 + "\n")

    uvicorn.run(app, host="0.0.0.0", port=8000)
