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

"""ABAC policy implementation for attribute-based access control.

Provides simple policy evaluation based on resource type, actions, and attribute conditions.
Follows fail-closed security model where no matching policy = deny.

Usage:
    from neoaxios_fastapi_kit.auth.policy import Policy, PolicyDecision, SimplePolicyEvaluator

    policies = [
        Policy(
            id="doc-read-eng",
            name="Engineering Read Access",
            resource_type="document",
            actions=frozenset({"read"}),
            conditions={"department": "engineering"},
            effect="allow",
        ),
    ]

    evaluator = SimplePolicyEvaluator(policies=policies)
    decision = await evaluator.evaluate(
        identity=identity_ctx,
        resource={"type": "document", "owner": "user123"},
        action="read",
    )
"""

from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, List, Optional

from neoaxios_logging import auto_trace, get_telemetry

from neoaxios_fastapi_kit.auth.context import IdentityContext

logger = get_telemetry(__name__)


@dataclass(frozen=True)
class Policy:
    """ABAC policy definition.

    Attributes:
        id: Unique policy identifier
        name: Human-readable policy name
        description: Detailed description of what this policy does
        resource_type: Type of resource this policy applies to
        actions: Set of actions this policy covers (e.g., {"read", "write"})
        conditions: Attribute conditions that must match for policy to apply
        effect: "allow" or "deny" - what happens when policy matches
        priority: Policy evaluation priority (lower = evaluated first, default 100)
    """

    id: str
    name: str
    resource_type: str
    actions: FrozenSet[str]
    conditions: Dict[str, Any]
    effect: str
    description: str = ""
    priority: int = 100

    def __post_init__(self):
        """Validate policy after initialization."""
        if self.effect not in ("allow", "deny"):
            raise ValueError(f"Policy effect must be 'allow' or 'deny', got '{self.effect}'")


@dataclass(frozen=True)
class PolicyDecision:
    """Result of policy evaluation.

    Attributes:
        allowed: Whether access is allowed
        reason: Human-readable explanation of the decision
        matched_policy: ID of the policy that matched (if any)
    """

    allowed: bool
    reason: str
    matched_policy: Optional[str] = None


class SimplePolicyEvaluator:
    """Simple policy evaluator for ABAC.

    Evaluates policies based on resource type, actions, and attribute conditions.
    Uses first-match wins strategy with fail-closed default (deny if no match).

    Supports condition operators:
    - equals: Direct value comparison
    - in: Value in list
    - not_in: Value not in list
    - gt: Greater than
    - lt: Less than
    - gte: Greater than or equal
    - lte: Less than or equal

    Attributes:
        policies: List of policies to evaluate
    """

    @auto_trace(logger)
    def __init__(self, policies: List[Policy]):
        """Initialize policy evaluator.

        Args:
            policies: List of Policy objects to evaluate
        """
        self.policies = policies
        logger.info(f"Initialized SimplePolicyEvaluator with {len(policies)} policies")

    @auto_trace(logger)
    async def get_applicable_policies(
        self,
        resource_type: str,
        action: str,
    ) -> List[Policy]:
        """Get policies applicable to resource type and action.

        Args:
            resource_type: Type of resource being accessed
            action: Action being performed

        Returns:
            List of policies that match resource_type and action
        """
        applicable = [
            p for p in self.policies
            if p.resource_type == resource_type and action in p.actions
        ]

        logger.debug(
            f"Found {len(applicable)} applicable policies for "
            f"resource_type='{resource_type}', action='{action}'"
        )

        return applicable

    @auto_trace(logger)  # Evaluates single condition operator
    def _evaluate_condition_operator(
        self,
        operator: str,
        condition_value: Any,
        actual_value: Any,
    ) -> bool:
        """Evaluate a single condition operator.

        Args:
            operator: Operator name (equals, in, not_in, gt, lt, gte, lte)
            condition_value: Expected value from policy condition
            actual_value: Actual value from identity/resource

        Returns:
            True if condition matches, False otherwise
        """
        if operator == "equals":
            return actual_value == condition_value
        elif operator == "in":
            if not isinstance(condition_value, (list, tuple, set, frozenset)):
                logger.warning(f"Operator 'in' requires list/set value, got {type(condition_value)}")
                return False
            return actual_value in condition_value
        elif operator == "not_in":
            if not isinstance(condition_value, (list, tuple, set, frozenset)):
                logger.warning(f"Operator 'not_in' requires list/set value, got {type(condition_value)}")
                return False
            return actual_value not in condition_value
        elif operator == "gt":
            try:
                return actual_value > condition_value
            except TypeError:
                logger.warning(f"Cannot compare {type(actual_value)} > {type(condition_value)}")
                return False
        elif operator == "lt":
            try:
                return actual_value < condition_value
            except TypeError:
                logger.warning(f"Cannot compare {type(actual_value)} < {type(condition_value)}")
                return False
        elif operator == "gte":
            try:
                return actual_value >= condition_value
            except TypeError:
                logger.warning(f"Cannot compare {type(actual_value)} >= {type(condition_value)}")
                return False
        elif operator == "lte":
            try:
                return actual_value <= condition_value
            except TypeError:
                logger.warning(f"Cannot compare {type(actual_value)} <= {type(condition_value)}")
                return False
        else:
            logger.warning(f"Unknown operator '{operator}'")
            return False

    @auto_trace(logger)  # Evaluates condition against identity/resource
    def _evaluate_condition(
        self,
        condition_key: str,
        condition_value: Any,
        identity: IdentityContext,
        resource: Dict[str, Any],
    ) -> bool:
        """Evaluate a single condition against identity and resource.

        Args:
            condition_key: Attribute key to check
            condition_value: Expected value or operator dict
            identity: Identity context with user attributes
            resource: Resource attributes

        Returns:
            True if condition matches, False otherwise
        """
        # Get actual value from identity attributes or resource
        actual_value = None

        # Check identity attributes first
        if condition_key in identity.attributes:
            actual_value = identity.attributes[condition_key]
        # Then check resource
        elif condition_key in resource:
            actual_value = resource[condition_key]
        else:
            logger.debug(f"Condition key '{condition_key}' not found in identity or resource")
            return False

        # Handle operator-based conditions (dict with operator keys)
        if isinstance(condition_value, dict):
            # Check for operator keys
            for op_key, op_value in condition_value.items():
                if not self._evaluate_condition_operator(op_key, op_value, actual_value):
                    return False
            return True
        else:
            # Simple equality check
            return actual_value == condition_value

    @auto_trace(logger)
    async def evaluate(
        self,
        identity: IdentityContext,
        resource: Dict[str, Any],
        action: str,
    ) -> PolicyDecision:
        """Evaluate policies for access decision.

        Finds policies matching resource type and action, then evaluates conditions.
        First matching policy wins. No match = deny (fail-closed).

        Args:
            identity: Identity context with user information
            resource: Resource attributes (must include 'type' key for resource_type)
            action: Action being performed

        Returns:
            PolicyDecision with allowed status, reason, and matched_policy
        """
        # Extract resource type from resource dict
        resource_type = resource.get("type")
        if not resource_type:
            logger.warning("Resource dict missing 'type' key, denying access")
            return PolicyDecision(
                allowed=False,
                reason="Resource type not specified",
                matched_policy=None,
            )

        # Get applicable policies
        applicable_policies = await self.get_applicable_policies(resource_type, action)

        if not applicable_policies:
            logger.info(
                f"No applicable policies for resource_type='{resource_type}', "
                f"action='{action}', denying access (fail-closed)"
            )
            return PolicyDecision(
                allowed=False,
                reason=f"No policy found for {resource_type}:{action}",
                matched_policy=None,
            )

        # Evaluate conditions for each applicable policy
        for policy in applicable_policies:
            # Check if all conditions match
            all_conditions_match = True

            for condition_key, condition_value in policy.conditions.items():
                if not self._evaluate_condition(
                    condition_key,
                    condition_value,
                    identity,
                    resource,
                ):
                    all_conditions_match = False
                    break

            # If all conditions match, this policy applies
            if all_conditions_match:
                allowed = policy.effect == "allow"

                logger.info(
                    f"Policy '{policy.id}' matched for user '{identity.user_id}', "
                    f"effect='{policy.effect}'"
                )

                return PolicyDecision(
                    allowed=allowed,
                    reason=f"Policy '{policy.name}' matched with effect '{policy.effect}'",
                    matched_policy=policy.id,
                )

        # No policy matched, deny by default (fail-closed)
        logger.info(
            f"No policy matched for user '{identity.user_id}' on "
            f"resource_type='{resource_type}', action='{action}', denying access"
        )

        return PolicyDecision(
            allowed=False,
            reason="No matching policy found (fail-closed)",
            matched_policy=None,
        )

    @auto_trace(logger)
    def add_policy(self, policy: Policy) -> None:
        """Add a policy at runtime.

        Policies are sorted by priority after addition (lower priority = first).

        Args:
            policy: Policy to add
        """
        self.policies.append(policy)
        # Sort by priority (lower number = evaluated first)
        self.policies.sort(key=lambda p: p.priority)
        logger.info(f"Added policy '{policy.id}' with priority {policy.priority}")

    @auto_trace(logger)
    def remove_policy(self, policy_id: str) -> bool:
        """Remove a policy by ID.

        Args:
            policy_id: ID of policy to remove

        Returns:
            True if policy was found and removed, False otherwise
        """
        original_len = len(self.policies)
        self.policies = [p for p in self.policies if p.id != policy_id]
        removed = len(self.policies) < original_len

        if removed:
            logger.info(f"Removed policy '{policy_id}'")
        else:
            logger.warning(f"Policy '{policy_id}' not found for removal")

        return removed
