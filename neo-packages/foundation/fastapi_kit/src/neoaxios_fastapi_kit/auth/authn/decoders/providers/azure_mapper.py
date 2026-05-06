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

"""Azure-specific token mapper for Azure AD/Entra ID tokens.

Maps Azure AD/Entra ID token claims to the IdentityContext format used by the
authorization framework. This mapper handles Azure-specific claim structures
including roles, groups, directory roles (wids), and delegated permissions (scp).

Azure Token Structure:
    Azure AD issues tokens from: https://login.microsoftonline.com/{tenant_id}/v2.0
    or https://sts.windows.net/{tenant_id}/ for v1.0 tokens

Azure-Specific Claims:
    - oid: Object ID (unique per tenant, primary user identifier)
    - sub: Subject (unique per application+user combination)
    - tid: Tenant ID (Azure AD directory ID)
    - roles: App roles assigned to user (string array)
    - groups: Security group object IDs (string array)
    - wids: Directory role template IDs (string array, Azure AD built-in roles)
    - scp: Delegated permissions/scopes (space-separated string)
    - appid/azp: Client application ID
    - upn: User principal name (email-like identifier)
    - email: Email address
    - name: Full display name
    - given_name/family_name: Name parts

Directory Role Template IDs (wids):
    Azure AD uses GUIDs for built-in directory roles:
    - 62e90394-69f5-4237-9190-012177145e10: Global Administrator
    - 9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3: Application Administrator
    - 88d8e3e3-8f55-4a1e-953a-9b9898b8876b: Directory Readers
    - f28a1f50-f6e7-4571-818b-6a12f2af6b6c: SharePoint Administrator
    - 29232cdf-9323-42fd-ade2-1d097af3e4de: Exchange Administrator
    - fe930be7-5e62-47db-91af-98c3a49a38b1: User Administrator
    - And many more...

Usage:
    from neoaxios_fastapi_kit.auth.authn.decoders.providers.azure_mapper import (
        AzureTokenMapper,
        create_azure_token_mapper,
    )

    # Create mapper with default configuration
    mapper = AzureTokenMapper()

    # Or with custom configuration
    mapper = AzureTokenMapper(
        role_claim="roles",
        groups_claim="groups",
        include_directory_roles=True,
    )

    # Map token claims to identity
    identity_dict = mapper.map_identity(claims)

    # Or extract specific claim types
    roles = mapper.map_roles(claims)
    permissions = mapper.map_permissions(claims)
    groups = mapper.map_groups(claims)
    directory_roles = mapper.map_directory_roles(claims)

Environment Variables:
    - AZURE_ROLE_CLAIM: Custom role claim name (default: "roles")
    - AZURE_GROUPS_CLAIM: Custom groups claim name (default: "groups")
    - AZURE_INCLUDE_DIRECTORY_ROLES: Include wids mapping (default: "true")
"""

import os
from typing import Any, Dict, FrozenSet, List, Mapping, Optional

from neoaxios_logging import get_telemetry, auto_trace

logger = get_telemetry(__name__)


# =============================================================================
# Directory Role Template ID Mappings
# =============================================================================

# Azure AD built-in directory role template IDs mapped to human-readable names
# Reference: https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference
DIRECTORY_ROLE_MAPPINGS: Mapping[str, str] = {
    # Administrator roles
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "cf1c38e5-3621-4004-a7cb-879624dced7c": "Application Developer",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "729827e3-9c14-49f7-bb1b-9608f156bbb8": "Helpdesk Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
    "b0f54661-2d74-4c50-afa3-1ec803f12efe": "Billing Administrator",
    "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
    "11648597-926c-4cf3-9c36-bcebb0ba8dcc": "Power Platform Administrator",
    "e6d1a23a-da11-4be4-9570-befc86d067a7": "Compliance Administrator",
    "966707d0-3269-4727-9be2-8c3a10f19b9d": "Password Administrator",

    # Reader roles
    "88d8e3e3-8f55-4a1e-953a-9b9898b8876b": "Directory Readers",
    "4a5d8f65-41da-4de4-8968-e035b65339cf": "Reports Reader",
    "5d6b6bb7-de71-4623-b4af-96380a352509": "Security Reader",

    # Service-specific roles
    "f023fd81-a637-4b56-95fd-791ac0226033": "Service Support Administrator",
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
    "baf37b3a-610e-45da-9e62-d9d1e5e8914b": "Teams Administrator",
    "69091246-20e8-4a56-aa4d-066075b2a7a8": "Teams Communications Administrator",
    "112ca1a2-15ad-4102-995e-45b0bc479a6a": "Teams Communications Support Engineer",
    "fcf91098-03e3-41a9-b5ba-6f0ec8188a12": "Teams Communications Support Specialist",
    "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8": "Teams Devices Administrator",

    # Identity governance roles
    "45d8d3c5-c802-45c6-b32a-1d70b5e1e86e": "Identity Governance Administrator",
    "2b745bdf-0803-4d80-aa65-822c4493daac": "External Identity Provider Administrator",

    # Hybrid identity roles
    "d29b2b05-8046-44ba-8758-1e26182fcf32": "Directory Synchronization Accounts",

    # Device roles
    "7698a772-787b-4ac8-901f-60d6b08affd2": "Cloud Device Administrator",
    "9f06204d-73c1-4d4c-880a-6edb90606fd8": "Azure AD Joined Device Local Administrator",

    # Application roles
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "e3973bdf-4987-49ae-837a-ba8e231c7286": "Domain Name Administrator",

    # Authentication roles
    "c4e39bd9-1100-46d3-8c65-fb160da0071f": "Authentication Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
    "0526716b-113d-4c15-b2c8-68e3c22b9f80": "Authentication Policy Administrator",

    # License and subscription roles
    "4d6ac14f-3453-41d0-bef9-a3e0c569773a": "License Administrator",

    # Printer roles
    "644ef478-e28f-4e28-b9dc-3fdde9aa0b1f": "Printer Administrator",
    "e8cef6f1-e4bd-4ea8-bc07-4b8d950f4477": "Printer Technician",

    # Knowledge roles
    "744ec460-397e-42ad-a462-8b3f9747a02c": "Knowledge Administrator",
    "3a2c62db-5318-420d-8d74-23affee5d9d5": "Knowledge Manager",

    # Insights roles
    "eb1f4a8d-243a-41f0-9fbd-c7cdf6c5ef7c": "Insights Administrator",
    "25df335f-86eb-4119-b717-0ff02de207e9": "Insights Business Leader",

    # Guest roles
    "95e79109-95c0-4d8e-aee3-d01accf2d47b": "Guest Inviter",

    # Search roles
    "8835291a-918c-4fd7-a9ce-faa49f0cf7d9": "Search Administrator",
    "9c6df0f2-1e7c-4dc3-b195-66dfbd24aa8f": "Search Editor",

    # Message center roles
    "790c1fb9-7f7d-4f88-86a1-ef1f95c05c1b": "Message Center Privacy Reader",
    "17315797-102d-40b4-93e0-432062caca18": "Message Center Reader",

    # Office apps roles
    "2b499bcd-da44-4968-8aec-78e1674fa64d": "Office Apps Administrator",

    # Fabric roles
    "a9ea8996-122f-4c74-9520-8edcd192826c": "Fabric Administrator",

    # Attribute roles
    "58a13ea3-c632-46ae-9ee0-9c0d43cd7f3d": "Attribute Assignment Administrator",
    "ffd52fa5-98dc-465c-991d-fc073eb59f8f": "Attribute Assignment Reader",
    "8424c6f0-a189-499e-bbd0-26c1753c96d4": "Attribute Definition Administrator",
    "1d336d2c-4ae8-42ef-9711-b3604ce3fc2c": "Attribute Definition Reader",

    # Azure DevOps
    "e3973bdf-4987-49ae-837a-ba8e231c7286": "Azure DevOps Administrator",

    # Azure Information Protection
    "7495fdc4-34c4-4d15-a289-98788ce399fd": "Azure Information Protection Administrator",

    # B2C roles
    "0f971eea-41eb-4569-a71e-57bb8a3eff1e": "External ID User Flow Administrator",
    "a9ea8996-122f-4c74-9520-8edcd192826c": "External ID User Flow Attribute Administrator",
    "be2f45a1-457d-42af-a067-6ec1fa63bc45": "B2C IEF Keyset Administrator",
    "aaf43236-0c0d-4d5f-883a-6955382ac081": "B2C IEF Policy Administrator",

    # Intune roles
    "3a2c62db-5318-420d-8d74-23affee5d9d5": "Intune Administrator",

    # Windows Update roles
    "32696413-001a-46ae-978c-ce0f6b3620d2": "Windows Update Deployment Administrator",

    # Yammer roles
    "810a2642-a034-447f-a5e8-41beaa378541": "Yammer Administrator",
}


# =============================================================================
# AzureTokenMapper Class
# =============================================================================


class AzureTokenMapper:
    """Maps Azure AD/Entra ID token claims to IdentityContext format.

    This mapper is a pure function component that extracts and transforms
    Azure-specific claims into the standardized format used by the authorization
    framework. It handles:

    - Role extraction from 'roles' claim (app roles)
    - Permission extraction from 'scp' claim (delegated permissions)
    - Group membership from 'groups' claim (security group IDs)
    - Directory role mapping from 'wids' claim (Azure AD built-in roles)
    - Full identity mapping combining all claims

    The mapper is stateless and deterministic - the same input claims will
    always produce the same output. Configuration is immutable after construction.

    Attributes:
        role_claim: Name of claim containing app roles (default: "roles")
        groups_claim: Name of claim containing group IDs (default: "groups")
        include_directory_roles: Whether to map wids to role names (default: True)
        directory_role_mapping: Custom GUID-to-name mapping for directory roles

    Example:
        mapper = AzureTokenMapper(
            role_claim="roles",
            groups_claim="groups",
            include_directory_roles=True,
        )

        claims = {
            "oid": "12345678-1234-1234-1234-123456789012",
            "tid": "tenant-id",
            "roles": ["admin", "user"],
            "scp": "User.Read Files.ReadWrite",
            "groups": ["group-id-1", "group-id-2"],
            "wids": ["62e90394-69f5-4237-9190-012177145e10"],
        }

        identity_dict = mapper.map_identity(claims)
        # identity_dict["roles"] = frozenset({"admin", "user"})
        # identity_dict["permissions"] = frozenset({"User.Read", "Files.ReadWrite"})
        # identity_dict["attributes"]["groups"] = ["group-id-1", "group-id-2"]
        # identity_dict["attributes"]["directory_roles"] = ["Global Administrator"]
    """

    @auto_trace(logger)
    def __init__(
        self,
        role_claim: str = "roles",
        groups_claim: str = "groups",
        include_directory_roles: bool = True,
        directory_role_mapping: Optional[Mapping[str, str]] = None,
    ):
        """Initialize Azure token mapper with configuration.

        Args:
            role_claim: Name of claim containing app roles. Azure AD uses
                       'roles' by default for app role assignments.
                       Default: "roles"
            groups_claim: Name of claim containing group IDs. Azure AD uses
                         'groups' by default for security group memberships.
                         Default: "groups"
            include_directory_roles: Whether to extract and map directory
                                    role template IDs from 'wids' claim.
                                    Default: True
            directory_role_mapping: Optional custom mapping of directory role
                                   template IDs (GUIDs) to human-readable names.
                                   If not provided, uses built-in DIRECTORY_ROLE_MAPPINGS.
                                   Unknown GUIDs are used as-is.

        Example:
            # Default configuration
            mapper = AzureTokenMapper()

            # Custom role claim name
            mapper = AzureTokenMapper(role_claim="custom_roles")

            # Disable directory role mapping
            mapper = AzureTokenMapper(include_directory_roles=False)

            # Custom directory role mapping
            mapper = AzureTokenMapper(
                directory_role_mapping={
                    "custom-guid-1": "Custom Role 1",
                    "custom-guid-2": "Custom Role 2",
                }
            )
        """
        # Validate and normalize configuration
        self._role_claim = role_claim.strip() if role_claim else "roles"
        self._groups_claim = groups_claim.strip() if groups_claim else "groups"
        self._include_directory_roles = include_directory_roles
        self._directory_role_mapping = (
            directory_role_mapping if directory_role_mapping is not None
            else DIRECTORY_ROLE_MAPPINGS
        )

        logger.info(
            f"Initialized AzureTokenMapper: role_claim='{self._role_claim}', "
            f"groups_claim='{self._groups_claim}', "
            f"include_directory_roles={self._include_directory_roles}, "
            f"directory_role_mapping_count={len(self._directory_role_mapping)}"
        )

    @property
    def role_claim(self) -> str:
        """Get the configured role claim name."""
        return self._role_claim

    @property
    def groups_claim(self) -> str:
        """Get the configured groups claim name."""
        return self._groups_claim

    @property
    def include_directory_roles(self) -> bool:
        """Get whether directory role mapping is enabled."""
        return self._include_directory_roles

    # =========================================================================
    # Core Mapping Methods
    # =========================================================================

    @auto_trace(logger)
    def map_roles(self, claims: Dict[str, Any]) -> FrozenSet[str]:
        """Extract app roles from Azure AD token claims.

        Azure AD stores app role assignments in the 'roles' claim as a string
        array. This method also supports comma-separated and space-separated
        string formats for flexibility.

        Azure roles claim formats:
        - Array format: ["role1", "role2", "role3"]
        - Comma-separated: "role1,role2,role3"
        - Space-separated: "role1 role2 role3"

        Args:
            claims: Dictionary of Azure AD token claims

        Returns:
            FrozenSet of normalized role names (lowercase, trimmed).
            Empty frozenset if no roles or malformed claim.

        Example:
            claims = {"roles": ["Admin", "User", "Reader"]}
            roles = mapper.map_roles(claims)
            # roles = frozenset({"admin", "user", "reader"})

            claims = {"roles": "Admin,User,Reader"}
            roles = mapper.map_roles(claims)
            # roles = frozenset({"admin", "user", "reader"})
        """
        roles_value = claims.get(self._role_claim)

        if roles_value is None:
            logger.debug(
                f"No '{self._role_claim}' claim found in token, returning empty roles"
            )
            return frozenset()

        roles = self._parse_claim_to_set(roles_value, self._role_claim)

        # Normalize: lowercase and trim
        normalized_roles = frozenset(
            role.lower().strip() for role in roles if role.strip()
        )

        logger.debug(
            f"Mapped {len(normalized_roles)} roles from '{self._role_claim}' claim"
        )

        return normalized_roles

    @auto_trace(logger)
    def map_permissions(self, claims: Dict[str, Any]) -> FrozenSet[str]:
        """Extract delegated permissions from Azure AD token claims.

        Azure AD stores delegated permissions (scopes) in the 'scp' claim as
        a space-separated string. This is the OAuth 2.0 scope format used by
        Azure AD for delegated permissions.

        Azure scp claim format:
        - Space-separated string: "User.Read Files.ReadWrite openid profile"

        Args:
            claims: Dictionary of Azure AD token claims

        Returns:
            FrozenSet of permission strings (case-preserved, trimmed).
            Empty frozenset if no permissions or malformed claim.

        Example:
            claims = {"scp": "User.Read Files.ReadWrite openid profile"}
            permissions = mapper.map_permissions(claims)
            # permissions = frozenset({"User.Read", "Files.ReadWrite", "openid", "profile"})
        """
        scp_value = claims.get("scp")

        if scp_value is None:
            logger.debug(
                "No 'scp' claim found in token, returning empty permissions"
            )
            return frozenset()

        # Azure uses space-separated scopes
        if isinstance(scp_value, str):
            permissions = frozenset(
                scope.strip() for scope in scp_value.split() if scope.strip()
            )
        elif isinstance(scp_value, list):
            # Handle array format (non-standard but possible)
            permissions = frozenset(
                str(scope).strip() for scope in scp_value if str(scope).strip()
            )
        else:
            logger.warning(
                f"Unexpected 'scp' claim type: {type(scp_value)}, expected str. "
                f"Returning empty permissions."
            )
            return frozenset()

        logger.debug(f"Mapped {len(permissions)} permissions from 'scp' claim")

        return permissions

    @auto_trace(logger)
    def map_groups(self, claims: Dict[str, Any]) -> List[str]:
        """Extract group memberships from Azure AD token claims.

        Azure AD stores security group memberships in the 'groups' claim as an
        array of group object IDs (GUIDs). If the user has too many groups,
        Azure may set '_claim_names' and '_claim_sources' for groups overage,
        requiring a Graph API call to fetch all groups.

        This method logs a warning if groups overage is detected but does not
        perform the Graph API call (that's the responsibility of a separate
        component per Agent 10).

        Args:
            claims: Dictionary of Azure AD token claims

        Returns:
            List of group object IDs (strings).
            Empty list if no groups or malformed claim.

        Example:
            claims = {
                "groups": [
                    "11111111-1111-1111-1111-111111111111",
                    "22222222-2222-2222-2222-222222222222",
                ]
            }
            groups = mapper.map_groups(claims)
            # groups = ["11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"]

        Notes:
            - Groups claim contains object IDs, not group names
            - For groups overage, check '_claim_names' for 'groups' key
            - Graph API endpoint for groups: /me/memberOf
        """
        groups_value = claims.get(self._groups_claim)

        # Check for groups overage indicator
        claim_names = claims.get("_claim_names", {})
        if isinstance(claim_names, dict) and "groups" in claim_names:
            logger.warning(
                "Groups overage detected: token contains '_claim_names' with 'groups' key. "
                "Fetch complete group list from Microsoft Graph API (/me/memberOf). "
                "Groups in token may be incomplete."
            )

        if groups_value is None:
            logger.debug(
                f"No '{self._groups_claim}' claim found in token, returning empty groups"
            )
            return []

        if isinstance(groups_value, list):
            groups = [str(g).strip() for g in groups_value if str(g).strip()]
        elif isinstance(groups_value, str):
            # Handle comma-separated format (non-standard but defensive)
            groups = [g.strip() for g in groups_value.split(",") if g.strip()]
        else:
            logger.warning(
                f"Unexpected '{self._groups_claim}' claim type: {type(groups_value)}, "
                f"expected list. Returning empty groups."
            )
            return []

        logger.debug(
            f"Mapped {len(groups)} groups from '{self._groups_claim}' claim"
        )

        return groups

    @auto_trace(logger)
    def map_directory_roles(self, claims: Dict[str, Any]) -> List[str]:
        """Extract and map directory role template IDs from Azure AD token.

        Azure AD stores directory role assignments in the 'wids' claim as an
        array of role template IDs (GUIDs). These are Azure AD built-in roles
        like Global Administrator, Application Administrator, etc.

        This method maps GUIDs to human-readable names using the configured
        directory role mapping. Unknown GUIDs are preserved as-is.

        Args:
            claims: Dictionary of Azure AD token claims

        Returns:
            List of directory role names (or GUIDs if not mapped).
            Empty list if no directory roles, disabled, or malformed claim.

        Example:
            claims = {
                "wids": [
                    "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
                    "88d8e3e3-8f55-4a1e-953a-9b9898b8876b",  # Directory Readers
                ]
            }
            roles = mapper.map_directory_roles(claims)
            # roles = ["Global Administrator", "Directory Readers"]

            # Unknown GUID preserved as-is
            claims = {"wids": ["unknown-guid-value"]}
            roles = mapper.map_directory_roles(claims)
            # roles = ["unknown-guid-value"]
        """
        if not self._include_directory_roles:
            logger.debug("Directory role mapping disabled, returning empty list")
            return []

        wids_value = claims.get("wids")

        if wids_value is None:
            logger.debug(
                "No 'wids' claim found in token, returning empty directory roles"
            )
            return []

        if not isinstance(wids_value, list):
            logger.warning(
                f"Unexpected 'wids' claim type: {type(wids_value)}, expected list. "
                f"Returning empty directory roles."
            )
            return []

        directory_roles = []
        for wid in wids_value:
            wid_str = str(wid).strip().lower()
            if not wid_str:
                continue

            # Look up GUID in mapping, fallback to GUID as-is
            role_name = self._directory_role_mapping.get(wid_str, wid_str)
            directory_roles.append(role_name)

        logger.debug(
            f"Mapped {len(directory_roles)} directory roles from 'wids' claim"
        )

        return directory_roles

    @auto_trace(logger)
    def map_identity(self, claims: Dict[str, Any]) -> Dict[str, Any]:
        """Map all Azure AD token claims to IdentityContext-compatible dictionary.

        Performs comprehensive mapping of Azure AD token claims to the format
        expected by IdentityContext. This is the main entry point for full
        token mapping.

        Azure Claim Mapping:
            | Azure Claim          | IdentityContext Field      | Notes                          |
            |---------------------|---------------------------|--------------------------------|
            | oid                 | provider_user_id          | Object ID (unique per tenant)  |
            | sub                 | user_id                   | Subject                        |
            | tid                 | tenant_id                 | Tenant ID                      |
            | roles               | roles                     | App roles assigned             |
            | groups              | attributes["groups"]      | Security groups                |
            | wids                | attributes["directory_roles"] | Azure AD built-in roles    |
            | appid/azp           | attributes["app_id"]      | Client application ID          |
            | scp                 | permissions               | Delegated permissions          |
            | upn                 | attributes["upn"]         | User principal name            |
            | email               | attributes["email"]       | Email address                  |
            | name                | attributes["name"]        | Full name                      |
            | given_name          | attributes["given_name"]  | First name                     |
            | family_name         | attributes["family_name"] | Last name                      |

        Args:
            claims: Dictionary of Azure AD token claims

        Returns:
            Dictionary compatible with IdentityContext constructor containing:
            - user_id: From 'sub' claim
            - tenant_id: From 'tid' claim
            - provider_user_id: From 'oid' claim
            - roles: FrozenSet from 'roles' claim
            - permissions: FrozenSet from 'scp' claim
            - attributes: Dict with groups, directory_roles, and other claims
            - provider: "azure"
            - issuer: From 'iss' claim

        Example:
            claims = {
                "oid": "obj-id-123",
                "sub": "sub-id-456",
                "tid": "tenant-id-789",
                "iss": "https://login.microsoftonline.com/tenant-id/v2.0",
                "roles": ["admin", "user"],
                "scp": "User.Read Files.ReadWrite",
                "groups": ["group-1", "group-2"],
                "wids": ["62e90394-69f5-4237-9190-012177145e10"],
                "upn": "user@example.com",
                "email": "user@example.com",
                "name": "John Doe",
                "given_name": "John",
                "family_name": "Doe",
                "appid": "app-client-id",
            }

            identity_dict = mapper.map_identity(claims)
            # identity_dict = {
            #     "user_id": "sub-id-456",
            #     "tenant_id": "tenant-id-789",
            #     "provider_user_id": "obj-id-123",
            #     "roles": frozenset({"admin", "user"}),
            #     "permissions": frozenset({"User.Read", "Files.ReadWrite"}),
            #     "attributes": {
            #         "groups": ["group-1", "group-2"],
            #         "directory_roles": ["Global Administrator"],
            #         "upn": "user@example.com",
            #         "email": "user@example.com",
            #         "name": "John Doe",
            #         "given_name": "John",
            #         "family_name": "Doe",
            #         "app_id": "app-client-id",
            #     },
            #     "provider": "azure",
            #     "issuer": "https://login.microsoftonline.com/tenant-id/v2.0",
            # }
        """
        # Extract core identity fields
        user_id = claims.get("sub", "")
        tenant_id = claims.get("tid", "")
        provider_user_id = claims.get("oid", "")
        issuer = claims.get("iss", "")

        # Map roles and permissions
        roles = self.map_roles(claims)
        permissions = self.map_permissions(claims)

        # Map groups and directory roles
        groups = self.map_groups(claims)
        directory_roles = self.map_directory_roles(claims)

        # Build attributes dictionary
        attributes: Dict[str, Any] = {}

        # Add groups and directory roles
        attributes["groups"] = groups
        if directory_roles:
            attributes["directory_roles"] = directory_roles

        # Extract app ID (appid for v1.0, azp for v2.0)
        app_id = claims.get("appid") or claims.get("azp")
        if app_id:
            attributes["app_id"] = app_id

        # Extract user profile claims
        upn = claims.get("upn")
        if upn:
            attributes["upn"] = upn

        email = claims.get("email")
        if email:
            attributes["email"] = email

        name = claims.get("name")
        if name:
            attributes["name"] = name

        given_name = claims.get("given_name")
        if given_name:
            attributes["given_name"] = given_name

        family_name = claims.get("family_name")
        if family_name:
            attributes["family_name"] = family_name

        # Extract additional Azure-specific claims
        if "preferred_username" in claims:
            attributes["preferred_username"] = claims["preferred_username"]

        if "unique_name" in claims:
            attributes["unique_name"] = claims["unique_name"]

        # Extract token version info
        if "ver" in claims:
            attributes["token_version"] = claims["ver"]

        # Extract authentication context
        if "acr" in claims:
            attributes["acr"] = claims["acr"]

        if "amr" in claims:
            attributes["amr"] = claims["amr"]

        # Extract audience for reference
        if "aud" in claims:
            attributes["aud"] = claims["aud"]

        # Extract issued/expiration for reference
        if "iat" in claims:
            attributes["iat"] = claims["iat"]

        if "exp" in claims:
            attributes["exp"] = claims["exp"]

        # Build identity dictionary
        identity_dict: Dict[str, Any] = {
            "user_id": user_id,
            "tenant_id": tenant_id,
            "provider_user_id": provider_user_id,
            "roles": roles,
            "permissions": permissions,
            "attributes": attributes,
            "provider": "azure",
            "issuer": issuer,
        }

        logger.debug(
            f"Mapped Azure identity: user_id='{user_id}', tenant_id='{tenant_id}', "
            f"roles_count={len(roles)}, permissions_count={len(permissions)}, "
            f"groups_count={len(groups)}, directory_roles_count={len(directory_roles)}"
        )

        return identity_dict

    # =========================================================================
    # Helper Methods
    # =========================================================================

    @auto_trace(logger)
    def _parse_claim_to_set(self, claim_value: Any, claim_name: str) -> FrozenSet[str]:
        """Parse claim value to a set of strings.

        Supports multiple claim formats:
        - Array format: ["value1", "value2"]
        - Comma-separated string: "value1,value2"
        - Space-separated string: "value1 value2"

        Args:
            claim_value: The claim value to parse (any type)
            claim_name: Name of claim for logging purposes

        Returns:
            FrozenSet of parsed strings (empty if invalid/empty)
        """
        if claim_value is None:
            return frozenset()

        if isinstance(claim_value, list):
            # Array format
            return frozenset(
                str(item).strip() for item in claim_value if str(item).strip()
            )
        elif isinstance(claim_value, str):
            # String format - try comma first, then space
            if "," in claim_value:
                return frozenset(
                    item.strip() for item in claim_value.split(",") if item.strip()
                )
            else:
                return frozenset(
                    item.strip() for item in claim_value.split() if item.strip()
                )
        else:
            logger.warning(
                f"Unexpected '{claim_name}' claim type: {type(claim_value)}, "
                f"expected list or str. Returning empty set."
            )
            return frozenset()


# =============================================================================
# Factory Function
# =============================================================================


@auto_trace(logger)
def create_azure_token_mapper(
    role_claim: Optional[str] = None,
    groups_claim: Optional[str] = None,
    include_directory_roles: Optional[bool] = None,
    directory_role_mapping: Optional[Mapping[str, str]] = None,
) -> AzureTokenMapper:
    """Factory function for AzureTokenMapper instantiation.

    Creates an AzureTokenMapper instance with configuration from parameters
    or environment variables.

    Environment variables (used if parameters not provided):
    - AZURE_ROLE_CLAIM: Custom role claim name (default: "roles")
    - AZURE_GROUPS_CLAIM: Custom groups claim name (default: "groups")
    - AZURE_INCLUDE_DIRECTORY_ROLES: Include wids mapping (default: "true")

    Args:
        role_claim: Name of claim containing app roles.
                   Default: "roles" or AZURE_ROLE_CLAIM env var.
        groups_claim: Name of claim containing group IDs.
                     Default: "groups" or AZURE_GROUPS_CLAIM env var.
        include_directory_roles: Whether to map wids to role names.
                                Default: True or AZURE_INCLUDE_DIRECTORY_ROLES env var.
        directory_role_mapping: Optional custom GUID-to-name mapping.
                               Default: uses built-in DIRECTORY_ROLE_MAPPINGS.

    Returns:
        AzureTokenMapper instance configured from parameters or environment

    Example:
        # Create with defaults
        mapper = create_azure_token_mapper()

        # Create with custom configuration
        mapper = create_azure_token_mapper(
            role_claim="app_roles",
            include_directory_roles=False,
        )

        # Create from environment variables
        # Set AZURE_ROLE_CLAIM=custom_roles
        # Set AZURE_INCLUDE_DIRECTORY_ROLES=false
        mapper = create_azure_token_mapper()
    """
    # Read from environment if not provided
    if role_claim is None:
        role_claim = os.getenv("AZURE_ROLE_CLAIM", "roles")

    if groups_claim is None:
        groups_claim = os.getenv("AZURE_GROUPS_CLAIM", "groups")

    if include_directory_roles is None:
        env_value = os.getenv("AZURE_INCLUDE_DIRECTORY_ROLES", "true")
        include_directory_roles = env_value.lower() in ("true", "1", "yes")

    logger.info(
        f"Creating AzureTokenMapper from factory: "
        f"role_claim='{role_claim}', groups_claim='{groups_claim}', "
        f"include_directory_roles={include_directory_roles}"
    )

    return AzureTokenMapper(
        role_claim=role_claim,
        groups_claim=groups_claim,
        include_directory_roles=include_directory_roles,
        directory_role_mapping=directory_role_mapping,
    )
