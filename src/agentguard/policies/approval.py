"""Human-in-the-loop approval workflow.

Provides an approval-based policy where high-risk actions are held
pending human approval instead of immediately denied.

Usage::

    from agentguard.policies.approval import ApprovalManager, ApprovalPolicy
    from agentguard.policies.guard import Guard

    manager = ApprovalManager()
    policy = ApprovalPolicy(
        name="deploy-guard",
        action_kind="deploy",
        manager=manager,
        reason="Production deployments require approval",
    )
    guard = Guard(policies=[policy])

    # Agent tries an action — gets denied with pending approval
    decision = guard.check("deploy", target="production")
    # decision.denied is True, approval request queued

    # Human reviews and approves
    pending = manager.list_pending()
    manager.approve(pending[0].request_id, approved_by="admin")

YAML format::

    name: deploy-guard
    type: approval
    action: deploy
    reason: Production deployments require human approval
    timeout: 300  # seconds, optional
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum

from agentguard.policies.models import Action, Context, Decision, Policy, Severity

logger = logging.getLogger(__name__)


class ApprovalStatus(Enum):
    """Status of an approval request."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    TIMED_OUT = "timed_out"


@dataclass
class ApprovalRequest:
    """A pending action awaiting human approval.

    Attributes:
        request_id: Unique identifier for this request.
        action: The action awaiting approval.
        policy_name: Name of the policy that triggered the request.
        status: Current approval status.
        reason: Why approval is required.
        created_at: Unix timestamp of when the request was created.
        resolved_by: Who approved/rejected the request.
        rejection_reason: Reason for rejection (if rejected).
    """

    request_id: str
    action: Action
    policy_name: str
    status: ApprovalStatus = ApprovalStatus.PENDING
    reason: str | None = None
    created_at: float = field(default_factory=time.time)
    resolved_by: str | None = None
    rejection_reason: str | None = None

    @property
    def is_pending(self) -> bool:
        """True if the request is still awaiting a decision."""
        return self.status == ApprovalStatus.PENDING

    @property
    def is_resolved(self) -> bool:
        """True if the request has been approved, rejected, or timed out."""
        return self.status != ApprovalStatus.PENDING


#: Type alias for approval callbacks.
ApprovalCallback = Callable[[ApprovalRequest], None]


class ApprovalManager:
    """Manages a queue of actions pending human approval.

    Thread-safe. Supports timeout-based auto-deny and notification
    callbacks.

    Args:
        default_timeout: Default timeout in seconds for pending
            requests. ``None`` means no timeout.
        on_submit: Callback invoked when a new request is submitted.
        on_resolve: Callback invoked when a request is resolved
            (approved, rejected, or timed out).
    """

    def __init__(
        self,
        default_timeout: float | None = None,
        on_submit: ApprovalCallback | None = None,
        on_resolve: ApprovalCallback | None = None,
    ) -> None:
        self._requests: dict[str, ApprovalRequest] = {}
        self._lock = threading.Lock()
        self._default_timeout = default_timeout
        self._on_submit = on_submit
        self._on_resolve = on_resolve

    def submit(
        self,
        action: Action,
        policy_name: str,
        reason: str | None = None,
    ) -> ApprovalRequest:
        """Submit an action for approval.

        Args:
            action: The action requiring approval.
            policy_name: Name of the policy that triggered this.
            reason: Why approval is required.

        Returns:
            The created approval request.
        """
        request_id = str(uuid.uuid4())
        req = ApprovalRequest(
            request_id=request_id,
            action=action,
            policy_name=policy_name,
            reason=reason,
        )
        with self._lock:
            self._requests[request_id] = req

        if self._on_submit is not None:
            try:
                self._on_submit(req)
            except Exception:
                logger.exception("on_submit callback failed for %s", request_id)

        return req

    def approve(
        self,
        request_id: str,
        approved_by: str | None = None,
    ) -> ApprovalRequest:
        """Approve a pending request.

        Args:
            request_id: ID of the request to approve.
            approved_by: Who approved the request.

        Returns:
            The updated request.

        Raises:
            KeyError: If the request ID is not found.
            ValueError: If the request is already resolved.
        """
        with self._lock:
            req = self._get_or_raise(request_id)
            self._ensure_pending(req)
            req.status = ApprovalStatus.APPROVED
            req.resolved_by = approved_by

        if self._on_resolve is not None:
            try:
                self._on_resolve(req)
            except Exception:
                logger.exception("on_resolve callback failed for %s", request_id)

        return req

    def reject(
        self,
        request_id: str,
        rejected_by: str | None = None,
        reason: str | None = None,
    ) -> ApprovalRequest:
        """Reject a pending request.

        Args:
            request_id: ID of the request to reject.
            rejected_by: Who rejected the request.
            reason: Reason for rejection.

        Returns:
            The updated request.

        Raises:
            KeyError: If the request ID is not found.
            ValueError: If the request is already resolved.
        """
        with self._lock:
            req = self._get_or_raise(request_id)
            self._ensure_pending(req)
            req.status = ApprovalStatus.REJECTED
            req.resolved_by = rejected_by
            req.rejection_reason = reason

        if self._on_resolve is not None:
            try:
                self._on_resolve(req)
            except Exception:
                logger.exception("on_resolve callback failed for %s", request_id)

        return req

    def get(self, request_id: str) -> ApprovalRequest | None:
        """Get a request by ID.

        Args:
            request_id: The request ID.

        Returns:
            The request, or None if not found.
        """
        with self._lock:
            return self._requests.get(request_id)

    def list_pending(self) -> list[ApprovalRequest]:
        """List all pending (unresolved) requests.

        Returns:
            List of pending approval requests.
        """
        with self._lock:
            return [r for r in self._requests.values() if r.is_pending]

    def check_timeouts(self) -> list[ApprovalRequest]:
        """Check for and expire timed-out requests.

        Uses the manager's ``default_timeout``. Requests that have
        been pending longer than the timeout are marked as timed out.

        Returns:
            List of requests that were timed out.
        """
        if self._default_timeout is None:
            return []

        now = time.time()
        timed_out: list[ApprovalRequest] = []

        with self._lock:
            for req in self._requests.values():
                if req.is_pending and now - req.created_at >= self._default_timeout:
                    req.status = ApprovalStatus.TIMED_OUT
                    timed_out.append(req)

        for req in timed_out:
            if self._on_resolve is not None:
                try:
                    self._on_resolve(req)
                except Exception:
                    logger.exception(
                        "on_resolve callback failed for %s",
                        req.request_id,
                    )

        return timed_out

    def _get_or_raise(self, request_id: str) -> ApprovalRequest:
        """Get a request or raise KeyError."""
        req = self._requests.get(request_id)
        if req is None:
            msg = f"Unknown request ID: {request_id!r}"
            raise KeyError(msg)
        return req

    @staticmethod
    def _ensure_pending(req: ApprovalRequest) -> None:
        """Raise ValueError if the request is already resolved."""
        if req.is_resolved:
            msg = (
                f"Request {req.request_id!r} is already resolved "
                f"(status: {req.status.value})"
            )
            raise ValueError(msg)


class ApprovalPolicy(Policy):
    """Policy that requires human approval for matching actions.

    When an action matches the configured ``action_kind``, it is
    submitted to the ``ApprovalManager`` and a deny decision is
    returned indicating the action is pending approval.

    Args:
        name: Policy name.
        action_kind: The action kind this policy applies to.
        manager: The approval manager to submit requests to.
        reason: Why approval is required.
        description: Optional description.
    """

    def __init__(
        self,
        name: str,
        action_kind: str,
        manager: ApprovalManager | None = None,
        reason: str | None = None,
        description: str | None = None,
    ) -> None:
        self._action_kind = action_kind
        self._manager = manager if manager is not None else ApprovalManager()
        self._reason = reason

        super().__init__(
            name=name,
            rules=[],
            description=description,
        )

    @property
    def manager(self) -> ApprovalManager:
        """The approval manager for this policy."""
        return self._manager

    def evaluate(
        self,
        action: Action,
        context: Context | None = None,
    ) -> Decision:
        """Evaluate an action, submitting it for approval if matching.

        Non-matching actions are allowed. Matching actions are
        submitted to the approval manager and denied with a
        reason indicating pending approval.

        Args:
            action: The action to check.
            context: Unused (present for API compatibility).

        Returns:
            Allow if action doesn't match, deny (pending approval)
            if it does.
        """
        if action.kind != self._action_kind:
            return Decision(allowed=True)

        # Submit for approval
        req = self._manager.submit(
            action=action,
            policy_name=self.name,
            reason=self._reason,
        )

        return Decision(
            allowed=False,
            denied_by=self.name,
            reason=(
                f"Action pending approval (request: {req.request_id}, "
                f"policy: {self.name})"
            ),
            severity=Severity.HIGH,
        )
