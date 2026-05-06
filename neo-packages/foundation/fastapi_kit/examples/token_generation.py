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

"""JWT Token Generation Utility

This utility helps with JWT token generation and debugging for development and testing.

Features:
- Generate RSA key pairs
- Create JWT tokens with custom claims
- Decode tokens without verification (for debugging)
- Validate token structure and claims
- Display token information in human-readable format

Usage:
    # Generate RSA key pair
    python token_generation.py generate-keys

    # Generate test token
    python token_generation.py generate-token --user-id user-123

    # Decode and inspect token
    python token_generation.py decode-token <token>

    # Validate token
    python token_generation.py validate-token <token> --public-key public_key.pem
"""

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional

try:
    import jwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("Error: Required packages not installed.")
    print("Install with: pip install pyjwt cryptography")
    sys.exit(1)


def generate_rsa_keys(
    private_key_path: str = "private_key.pem",
    public_key_path: str = "public_key.pem",
    key_size: int = 2048,
) -> None:
    """Generate RSA key pair for JWT signing.

    Args:
        private_key_path: Output path for private key
        public_key_path: Output path for public key
        key_size: RSA key size in bits (2048 or 4096)
    """
    print(f"Generating {key_size}-bit RSA key pair...")

    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend(),
    )

    # Write private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(private_key_path, "wb") as f:
        f.write(private_pem)
    print(f"Private key saved to: {private_key_path}")

    # Extract and write public key
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(public_key_path, "wb") as f:
        f.write(public_pem)
    print(f"Public key saved to: {public_key_path}")

    print("\nDone! Keep private_key.pem secure and never commit it to version control.")


def generate_token(
    user_id: str,
    tenant_id: str = "default-tenant",
    roles: List[str] = None,
    permissions: List[str] = None,
    issuer: str = "https://local.test",
    audience: Optional[str] = None,
    expires_in: int = 3600,
    private_key_path: Optional[str] = None,
    secret: Optional[str] = None,
    algorithm: str = "RS256",
    extra_claims: Dict[str, Any] = None,
) -> str:
    """Generate JWT token.

    Args:
        user_id: User identifier (sub claim)
        tenant_id: Tenant identifier
        roles: List of user roles
        permissions: List of user permissions
        issuer: Token issuer (iss claim)
        audience: Token audience (aud claim)
        expires_in: Token expiry in seconds
        private_key_path: Path to private key (for RS256)
        secret: Shared secret (for HS256)
        algorithm: JWT algorithm (RS256 or HS256)
        extra_claims: Additional claims to include

    Returns:
        JWT token string
    """
    now = datetime.now(timezone.utc)

    # Build payload
    payload = {
        "sub": user_id,
        "tenant_id": tenant_id,
        "roles": roles or [],
        "permissions": permissions or [],
        "iss": issuer,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=expires_in)).timestamp()),
    }

    if audience:
        payload["aud"] = audience

    if extra_claims:
        payload.update(extra_claims)

    # Load signing key
    if algorithm.startswith("RS"):
        if not private_key_path:
            raise ValueError("private_key_path required for RS algorithms")
        with open(private_key_path, "rb") as f:
            signing_key = f.read()
    elif algorithm.startswith("HS"):
        if not secret:
            raise ValueError("secret required for HS algorithms")
        signing_key = secret
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    # Generate token
    token = jwt.encode(payload, signing_key, algorithm=algorithm)

    return token


def decode_token_unsafe(token: str) -> Dict[str, Any]:
    """Decode JWT token without signature verification (for debugging).

    Args:
        token: JWT token string

    Returns:
        Decoded payload
    """
    return jwt.decode(
        token,
        options={
            "verify_signature": False,
            "verify_exp": False,
            "verify_iss": False,
            "verify_aud": False,
        },
    )


def validate_token(
    token: str,
    public_key_path: Optional[str] = None,
    secret: Optional[str] = None,
    algorithm: str = "RS256",
    issuer: Optional[str] = None,
    audience: Optional[str] = None,
) -> tuple[bool, str]:
    """Validate JWT token.

    Args:
        token: JWT token string
        public_key_path: Path to public key (for RS256)
        secret: Shared secret (for HS256)
        algorithm: JWT algorithm
        issuer: Expected issuer
        audience: Expected audience

    Returns:
        Tuple of (is_valid, message)
    """
    try:
        # Load verification key
        if algorithm.startswith("RS"):
            if not public_key_path:
                return False, "public_key_path required for RS algorithms"
            with open(public_key_path, "rb") as f:
                verification_key = f.read()
        elif algorithm.startswith("HS"):
            if not secret:
                return False, "secret required for HS algorithms"
            verification_key = secret
        else:
            return False, f"Unsupported algorithm: {algorithm}"

        # Validate token
        jwt.decode(
            token,
            verification_key,
            algorithms=[algorithm],
            issuer=issuer,
            audience=audience,
        )

        return True, "Token is valid"

    except jwt.ExpiredSignatureError:
        return False, "Token has expired"
    except jwt.InvalidAudienceError:
        return False, "Invalid audience"
    except jwt.InvalidIssuerError:
        return False, "Invalid issuer"
    except jwt.InvalidSignatureError:
        return False, "Invalid signature"
    except jwt.DecodeError as e:
        return False, f"Decode error: {e}"
    except Exception as e:
        return False, f"Validation error: {e}"


def display_token_info(token: str) -> None:
    """Display human-readable token information.

    Args:
        token: JWT token string
    """
    try:
        # Split token parts
        parts = token.split(".")
        if len(parts) != 3:
            print("Error: Invalid JWT format (expected 3 parts)")
            return

        # Decode header
        header = jwt.get_unverified_header(token)

        # Decode payload
        payload = decode_token_unsafe(token)

        # Calculate expiry
        exp_timestamp = payload.get("exp")
        if exp_timestamp:
            exp_datetime = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)
            now = datetime.now(timezone.utc)
            if exp_datetime > now:
                time_left = exp_datetime - now
                exp_status = f"Expires in {time_left.total_seconds():.0f} seconds"
            else:
                time_ago = now - exp_datetime
                exp_status = f"Expired {time_ago.total_seconds():.0f} seconds ago"
        else:
            exp_status = "No expiration"

        # Display information
        print("\n" + "=" * 60)
        print("JWT Token Information")
        print("=" * 60)

        print("\nHeader:")
        print(json.dumps(header, indent=2))

        print("\nPayload:")
        print(json.dumps(payload, indent=2, default=str))

        print("\nToken Details:")
        print(f"  Algorithm: {header.get('alg', 'Unknown')}")
        print(f"  Type: {header.get('typ', 'Unknown')}")
        print(f"  Issuer: {payload.get('iss', 'Not specified')}")
        print(f"  Subject (User ID): {payload.get('sub', 'Not specified')}")
        print(f"  Audience: {payload.get('aud', 'Not specified')}")
        print(f"  Tenant ID: {payload.get('tenant_id', 'Not specified')}")
        print(f"  Issued At: {datetime.fromtimestamp(payload.get('iat', 0), tz=timezone.utc)}")
        print(f"  Expiration: {exp_status}")

        if payload.get("roles"):
            print(f"  Roles: {', '.join(payload['roles'])}")
        if payload.get("permissions"):
            print(f"  Permissions: {', '.join(payload['permissions'])}")

        print("\nRaw Token:")
        print(token)
        print("=" * 60 + "\n")

    except Exception as e:
        print(f"Error displaying token info: {e}")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="JWT Token Generation and Debugging Utility"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Generate keys command
    keys_parser = subparsers.add_parser(
        "generate-keys", help="Generate RSA key pair"
    )
    keys_parser.add_argument(
        "--private-key",
        default="private_key.pem",
        help="Private key output path (default: private_key.pem)",
    )
    keys_parser.add_argument(
        "--public-key",
        default="public_key.pem",
        help="Public key output path (default: public_key.pem)",
    )
    keys_parser.add_argument(
        "--key-size",
        type=int,
        default=2048,
        choices=[2048, 4096],
        help="RSA key size in bits (default: 2048)",
    )

    # Generate token command
    token_parser = subparsers.add_parser(
        "generate-token", help="Generate JWT token"
    )
    token_parser.add_argument(
        "--user-id", default="user-123", help="User ID (default: user-123)"
    )
    token_parser.add_argument(
        "--tenant-id",
        default="tenant-456",
        help="Tenant ID (default: tenant-456)",
    )
    token_parser.add_argument(
        "--roles", help="Comma-separated roles (e.g., admin,user)"
    )
    token_parser.add_argument(
        "--permissions",
        help="Comma-separated permissions (e.g., document:read,document:write)",
    )
    token_parser.add_argument(
        "--issuer", default="https://local.test", help="Issuer claim"
    )
    token_parser.add_argument("--audience", help="Audience claim")
    token_parser.add_argument(
        "--expires-in",
        type=int,
        default=3600,
        help="Token expiry in seconds (default: 3600)",
    )
    token_parser.add_argument(
        "--algorithm",
        choices=["RS256", "HS256"],
        default="RS256",
        help="JWT algorithm (default: RS256)",
    )
    token_parser.add_argument("--private-key", help="Private key path (for RS256)")
    token_parser.add_argument("--secret", help="Shared secret (for HS256)")

    # Decode token command
    decode_parser = subparsers.add_parser(
        "decode-token", help="Decode and display token information"
    )
    decode_parser.add_argument("token", help="JWT token to decode")

    # Validate token command
    validate_parser = subparsers.add_parser(
        "validate-token", help="Validate JWT token"
    )
    validate_parser.add_argument("token", help="JWT token to validate")
    validate_parser.add_argument(
        "--algorithm",
        choices=["RS256", "HS256"],
        default="RS256",
        help="JWT algorithm (default: RS256)",
    )
    validate_parser.add_argument("--public-key", help="Public key path (for RS256)")
    validate_parser.add_argument("--secret", help="Shared secret (for HS256)")
    validate_parser.add_argument("--issuer", help="Expected issuer")
    validate_parser.add_argument("--audience", help="Expected audience")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    # Execute command
    if args.command == "generate-keys":
        generate_rsa_keys(
            private_key_path=args.private_key,
            public_key_path=args.public_key,
            key_size=args.key_size,
        )

    elif args.command == "generate-token":
        # Parse roles and permissions
        roles = args.roles.split(",") if args.roles else ["user"]
        permissions = (
            args.permissions.split(",")
            if args.permissions
            else ["document:read"]
        )

        # Determine signing key
        if args.algorithm == "RS256":
            private_key = args.private_key or "private_key.pem"
            if not Path(private_key).exists():
                print(f"Error: Private key not found: {private_key}")
                print("Generate keys with: python token_generation.py generate-keys")
                return
        else:
            private_key = None

        # Generate token
        token = generate_token(
            user_id=args.user_id,
            tenant_id=args.tenant_id,
            roles=roles,
            permissions=permissions,
            issuer=args.issuer,
            audience=args.audience,
            expires_in=args.expires_in,
            private_key_path=private_key,
            secret=args.secret or "dev-secret-key",
            algorithm=args.algorithm,
        )

        print("\nGenerated JWT Token:")
        print("=" * 60)
        print(token)
        print("=" * 60)
        print("\nToken Details:")
        display_token_info(token)
        print("\nUse this token with:")
        print(f"  curl -H 'Authorization: Bearer {token}' http://localhost:8000/protected")

    elif args.command == "decode-token":
        display_token_info(args.token)

    elif args.command == "validate-token":
        is_valid, message = validate_token(
            token=args.token,
            public_key_path=args.public_key,
            secret=args.secret,
            algorithm=args.algorithm,
            issuer=args.issuer,
            audience=args.audience,
        )

        print("\nValidation Result:")
        print("=" * 60)
        if is_valid:
            print(f"✓ {message}")
        else:
            print(f"✗ {message}")
        print("=" * 60)

        # Also display token info
        if is_valid:
            display_token_info(args.token)


if __name__ == "__main__":
    main()
