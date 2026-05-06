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

"""Audit logging for authorization framework.

Provides fail-closed audit logging for access decisions, impersonation,
and authentication failures. All audit writes are synchronous to ensure
they complete before response is returned.

GDPR Compliance: Audit logging always fails closed. Write failures raise
exceptions to prevent operations from completing without an audit trail.
This ensures complete audit coverage required by GDPR Article 30 (Records
of Processing Activities) and Article 32 (Security of Processing).

Usage:
    from neoaxios_fastapi_kit.auth.audit import AuditLogger, InMemoryAuditBackend

    backend = InMemoryAuditBackend()
    audit = AuditLogger(backend)

    await audit.log_access(
        identity=identity,
        resource_type="document",
        resource_id="doc-123",
        action="read",
        outcome="allowed",
    )
"""

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Protocol

from neoaxios_logging import get_telemetry, auto_trace

from .context import IdentityContext

# No imports from defaults needed - fail-closed is always enforced

logger = get_telemetry(__name__)


@dataclass(frozen=True)
class AuditEntry:
    """Single audit log entry.

    Records details of an access decision, impersonation event,
    or authentication failure.

    Attributes:
        timestamp: When the event occurred
        event_type: Type of event ("access" | "impersonation" | "auth_failure")
        user_id: User who triggered the event
        tenant_id: Tenant context for the event
        outcome: Result of the event ("allowed" | "denied" | "failed")
        resource_type: Type of resource being accessed (optional)
        resource_id: Identifier of resource being accessed (optional)
        action: Action being performed (optional)
        trace_id: Trace identifier for correlation (optional)
        source_ip: Source IP address (optional)
        impersonator_id: Admin user performing impersonation (optional)
        failure_type: Type of authentication failure (optional)
        details: Additional event-specific details (optional)
    """

    timestamp: datetime
    event_type: str  # "access" | "impersonation" | "auth_failure"
    user_id: str
    tenant_id: str
    outcome: str  # "allowed" | "denied" | "failed"
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    action: Optional[str] = None
    trace_id: Optional[str] = None
    source_ip: Optional[str] = None
    impersonator_id: Optional[str] = None
    failure_type: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class AuditBackend(Protocol):
    """Protocol for audit log storage backends.

    Implementations must handle synchronous writes and raise
    exceptions on failure (always fail-closed for GDPR compliance).
    """

    async def write(self, entry: AuditEntry) -> None:
        """Write audit entry to storage.

        Args:
            entry: Audit entry to write

        Raises:
            Exception: On write failure (implementation-specific)
        """
        ...


class InMemoryAuditBackend:
    """In-memory audit backend for testing.

    Stores audit entries in a list. Not suitable for production.
    Async-safe audit logging using asyncio.Lock for concurrent writes.

    Attributes:
        entries: List of all audit entries
    """

    @auto_trace(logger)
    def __init__(self) -> None:
        """Initialize in-memory backend."""
        self._entries: List[AuditEntry] = []
        self._entries_lock = asyncio.Lock()
        logger.info("Initialized InMemoryAuditBackend")

    @auto_trace(logger)
    async def write(self, entry: AuditEntry) -> None:
        """Write audit entry to in-memory list.

        Thread-safe operation protected by asyncio.Lock to prevent
        concurrent modifications to entries list.

        Args:
            entry: Audit entry to write
        """
        try:
            async with self._entries_lock:
                self._entries.append(entry)
            logger.debug(
                f"Wrote audit entry: event_type={entry.event_type}, "
                f"user_id={entry.user_id}, outcome={entry.outcome}"
            )
        except Exception as e:
            logger.log_error(e)
            raise

    @auto_trace(logger)
    async def get_entries(self) -> List[AuditEntry]:
        """Get all stored audit entries.

        Thread-safe operation that returns a copy of the entries list
        to prevent external modifications while holding the lock.

        Returns:
            List of all audit entries
        """
        try:
            async with self._entries_lock:
                return self._entries.copy()
        except Exception as e:
            logger.log_error(e)
            raise

    @auto_trace(logger)
    async def clear(self) -> None:
        """Clear all stored audit entries.

        Thread-safe operation protected by asyncio.Lock to prevent
        concurrent modifications during clear operation.
        """
        try:
            async with self._entries_lock:
                self._entries.clear()
            logger.debug("Cleared all audit entries")
        except Exception as e:
            logger.log_error(e)
            raise


class AuditLogger:
    """Audit logger for authorization events.

    Provides fail-closed audit logging with synchronous writes.
    All audit operations complete before returning to ensure
    audit trail integrity.

    Attributes:
        backend: Storage backend for audit entries
    """

    @auto_trace(logger)
    def __init__(
        self,
        backend: AuditBackend,
    ) -> None:
        """Initialize audit logger.

        GDPR Compliance: Always fails closed. Audit write failures raise
        exceptions to ensure complete audit trail required by GDPR.

        Args:
            backend: Storage backend for audit entries

        Raises:
            Exception: On audit write failure (fail-closed, no exceptions)
        """
        self._backend = backend

        logger.info("Initialized AuditLogger (fail-closed for GDPR compliance)")

    @auto_trace(logger)
    async def log_access(
        self,
        identity: IdentityContext,
        resource_type: str,
        resource_id: str,
        action: str,
        outcome: str,
        reason: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> None:
        """Log an access decision.

        Records identity, resource, action, and outcome of an
        access control decision.

        Args:
            identity: Identity context of user making request
            resource_type: Type of resource being accessed
            resource_id: Identifier of resource being accessed
            action: Action being performed (e.g., "read", "write", "delete")
            outcome: Result of access check ("allowed" | "denied")
            reason: Optional reason for the outcome (e.g., why access was denied)
            trace_id: Optional trace identifier for correlation

        Raises:
            Exception: On write failure (always fail-closed for GDPR compliance)
        """
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc),
            event_type="access",
            user_id=identity.user_id,
            tenant_id=identity.tenant_id,
            outcome=outcome,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            trace_id=trace_id,
            details={"reason": reason} if reason else None,
        )

        try:
            await self._backend.write(entry)
            logger.info(
                f"Logged access: user={identity.user_id}, "
                f"resource={resource_type}:{resource_id}, "
                f"action={action}, outcome={outcome}"
            )
        except Exception as e:
            error_msg = (
                f"Failed to write audit entry for access: "
                f"user={identity.user_id}, resource={resource_type}:{resource_id}. "
                f"GDPR compliance requires complete audit trail - operation blocked."
            )
            logger.log_error(e)
            logger.error(error_msg)
            raise  # Always fail-closed for GDPR compliance

    @auto_trace(logger)
    async def log_impersonation(
        self,
        admin_id: str,
        target_user_id: str,
        tenant_id: str,
        action: str,
        trace_id: Optional[str] = None,
    ) -> None:
        """Log an impersonation event.

        Records when an admin starts or ends impersonating another user.

        Args:
            admin_id: User ID of admin performing impersonation
            target_user_id: User ID being impersonated
            tenant_id: Tenant context
            action: Action being performed ("start" | "end")
            trace_id: Optional trace identifier for correlation

        Raises:
            Exception: On write failure (always fail-closed for GDPR compliance)
        """
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc),
            event_type="impersonation",
            user_id=target_user_id,
            tenant_id=tenant_id,
            outcome="allowed",  # Impersonation is always allowed at this point
            impersonator_id=admin_id,
            action=action,
            trace_id=trace_id,
        )

        try:
            await self._backend.write(entry)
            logger.info(
                f"Logged impersonation: admin={admin_id}, "
                f"target={target_user_id}, action={action}"
            )
        except Exception as e:
            error_msg = (
                f"Failed to write audit entry for impersonation: "
                f"admin={admin_id}, target={target_user_id}. "
                f"GDPR compliance requires complete audit trail - operation blocked."
            )
            logger.log_error(e)
            logger.error(error_msg)
            raise  # Always fail-closed for GDPR compliance

    @auto_trace(logger)
    async def log_auth_failure(
        self,
        user_id: str,
        tenant_id: str,
        failure_type: str,
        source_ip: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> None:
        """Log an authentication failure.

        Records failed authentication attempts for security monitoring
        and rate limiting.

        Args:
            user_id: User ID that failed authentication
            tenant_id: Tenant context
            failure_type: Type of failure (e.g., "invalid_token",
                         "expired_token", "revoked_token")
            source_ip: Optional source IP address of request
            trace_id: Optional trace identifier for correlation

        Raises:
            Exception: On write failure (always fail-closed for GDPR compliance)
        """
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc),
            event_type="auth_failure",
            user_id=user_id,
            tenant_id=tenant_id,
            outcome="failed",
            failure_type=failure_type,
            source_ip=source_ip,
            trace_id=trace_id,
        )

        try:
            await self._backend.write(entry)
            logger.info(
                f"Logged auth failure: user={user_id}, "
                f"type={failure_type}, source_ip={source_ip}"
            )
        except Exception as e:
            error_msg = (
                f"Failed to write audit entry for auth failure: "
                f"user={user_id}, type={failure_type}. "
                f"GDPR compliance requires complete audit trail - operation blocked."
            )
            logger.log_error(e)
            logger.error(error_msg)
            raise  # Always fail-closed for GDPR compliance
