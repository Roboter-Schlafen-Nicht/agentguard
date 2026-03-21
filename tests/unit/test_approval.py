"""Tests for human-in-the-loop approval workflow (M12).

Covers:
- ApprovalRequest creation and states
- ApprovalManager queue operations
- Approve/reject actions
- Timeout auto-deny
- Callback notifications
- Thread safety
- ApprovalPolicy integration with Guard
- YAML loading of approval policies
"""

from __future__ import annotations

import threading
import time
from unittest.mock import MagicMock

import pytest

from agentguard.policies.approval import (
    ApprovalManager,
    ApprovalPolicy,
    ApprovalRequest,
    ApprovalStatus,
)
from agentguard.policies.guard import Guard
from agentguard.policies.loader import load_policy_from_string
from agentguard.policies.models import Action

# --- ApprovalRequest ---


class TestApprovalRequest:
    """Tests for ApprovalRequest dataclass."""

    def test_create_request(self) -> None:
        action = Action(kind="deploy", params={"target": "production"})
        req = ApprovalRequest(
            request_id="req-001",
            action=action,
            policy_name="deploy-guard",
        )
        assert req.request_id == "req-001"
        assert req.status == ApprovalStatus.PENDING
        assert req.action is action

    def test_request_pending_by_default(self) -> None:
        action = Action(kind="deploy", params={})
        req = ApprovalRequest(
            request_id="req-002",
            action=action,
            policy_name="test",
        )
        assert req.is_pending is True
        assert req.is_resolved is False

    def test_request_reason_optional(self) -> None:
        action = Action(kind="deploy", params={})
        req = ApprovalRequest(
            request_id="req-003",
            action=action,
            policy_name="test",
            reason="High-risk deployment",
        )
        assert req.reason == "High-risk deployment"


# --- ApprovalStatus ---


class TestApprovalStatus:
    """Tests for ApprovalStatus enum."""

    def test_status_values(self) -> None:
        assert ApprovalStatus.PENDING.value == "pending"
        assert ApprovalStatus.APPROVED.value == "approved"
        assert ApprovalStatus.REJECTED.value == "rejected"
        assert ApprovalStatus.TIMED_OUT.value == "timed_out"


# --- ApprovalManager ---


class TestApprovalManager:
    """Tests for ApprovalManager queue operations."""

    def test_submit_request(self) -> None:
        manager = ApprovalManager()
        action = Action(kind="deploy", params={})
        req = manager.submit(action, policy_name="deploy-guard")
        assert req.status == ApprovalStatus.PENDING
        assert req.request_id is not None

    def test_list_pending(self) -> None:
        manager = ApprovalManager()
        action1 = Action(kind="deploy", params={"v": "1"})
        action2 = Action(kind="deploy", params={"v": "2"})
        manager.submit(action1, policy_name="test")
        manager.submit(action2, policy_name="test")
        pending = manager.list_pending()
        assert len(pending) == 2

    def test_approve_request(self) -> None:
        manager = ApprovalManager()
        action = Action(kind="deploy", params={})
        req = manager.submit(action, policy_name="test")
        result = manager.approve(req.request_id, approved_by="admin")
        assert result.status == ApprovalStatus.APPROVED
        assert result.resolved_by == "admin"
        assert result.is_resolved is True
        assert result.is_pending is False

    def test_reject_request(self) -> None:
        manager = ApprovalManager()
        action = Action(kind="deploy", params={})
        req = manager.submit(action, policy_name="test")
        result = manager.reject(
            req.request_id,
            rejected_by="admin",
            reason="Too risky",
        )
        assert result.status == ApprovalStatus.REJECTED
        assert result.resolved_by == "admin"
        assert result.rejection_reason == "Too risky"

    def test_approve_unknown_id_raises(self) -> None:
        manager = ApprovalManager()
        with pytest.raises(KeyError, match="nonexistent"):
            manager.approve("nonexistent")

    def test_reject_unknown_id_raises(self) -> None:
        manager = ApprovalManager()
        with pytest.raises(KeyError, match="nonexistent"):
            manager.reject("nonexistent")

    def test_approve_already_resolved_raises(self) -> None:
        manager = ApprovalManager()
        action = Action(kind="deploy", params={})
        req = manager.submit(action, policy_name="test")
        manager.approve(req.request_id)
        with pytest.raises(ValueError, match="already resolved"):
            manager.approve(req.request_id)

    def test_reject_already_resolved_raises(self) -> None:
        manager = ApprovalManager()
        action = Action(kind="deploy", params={})
        req = manager.submit(action, policy_name="test")
        manager.reject(req.request_id)
        with pytest.raises(ValueError, match="already resolved"):
            manager.reject(req.request_id)

    def test_get_request(self) -> None:
        manager = ApprovalManager()
        action = Action(kind="deploy", params={})
        req = manager.submit(action, policy_name="test")
        fetched = manager.get(req.request_id)
        assert fetched is req

    def test_get_unknown_returns_none(self) -> None:
        manager = ApprovalManager()
        assert manager.get("nonexistent") is None

    def test_list_pending_excludes_resolved(self) -> None:
        manager = ApprovalManager()
        action1 = Action(kind="deploy", params={"v": "1"})
        action2 = Action(kind="deploy", params={"v": "2"})
        req1 = manager.submit(action1, policy_name="test")
        manager.submit(action2, policy_name="test")
        manager.approve(req1.request_id)
        pending = manager.list_pending()
        assert len(pending) == 1


# --- Timeout ---


class TestApprovalTimeout:
    """Tests for approval request timeout."""

    def test_timeout_auto_deny(self) -> None:
        manager = ApprovalManager(default_timeout=0.1)
        action = Action(kind="deploy", params={})
        req = manager.submit(action, policy_name="test")
        time.sleep(0.2)
        manager.check_timeouts()
        updated = manager.get(req.request_id)
        assert updated is not None
        assert updated.status == ApprovalStatus.TIMED_OUT

    def test_no_timeout_when_approved_in_time(self) -> None:
        manager = ApprovalManager(default_timeout=10.0)
        action = Action(kind="deploy", params={})
        req = manager.submit(action, policy_name="test")
        manager.approve(req.request_id)
        manager.check_timeouts()
        assert req.status == ApprovalStatus.APPROVED


# --- Callbacks ---


class TestApprovalCallbacks:
    """Tests for approval notification callbacks."""

    def test_on_submit_callback(self) -> None:
        callback = MagicMock()
        manager = ApprovalManager(on_submit=callback)
        action = Action(kind="deploy", params={})
        req = manager.submit(action, policy_name="test")
        callback.assert_called_once_with(req)

    def test_on_resolve_callback_approve(self) -> None:
        callback = MagicMock()
        manager = ApprovalManager(on_resolve=callback)
        action = Action(kind="deploy", params={})
        req = manager.submit(action, policy_name="test")
        manager.approve(req.request_id)
        callback.assert_called_once_with(req)

    def test_on_resolve_callback_reject(self) -> None:
        callback = MagicMock()
        manager = ApprovalManager(on_resolve=callback)
        action = Action(kind="deploy", params={})
        req = manager.submit(action, policy_name="test")
        manager.reject(req.request_id)
        callback.assert_called_once_with(req)

    def test_on_resolve_callback_timeout(self) -> None:
        callback = MagicMock()
        manager = ApprovalManager(
            default_timeout=0.1,
            on_resolve=callback,
        )
        action = Action(kind="deploy", params={})
        manager.submit(action, policy_name="test")
        time.sleep(0.2)
        manager.check_timeouts()
        callback.assert_called_once()


# --- Thread safety ---


class TestApprovalThreadSafety:
    """Tests for thread-safe approval operations."""

    def test_concurrent_submits(self) -> None:
        manager = ApprovalManager()
        results: list[ApprovalRequest] = []
        lock = threading.Lock()

        def submit_one(idx: int) -> None:
            action = Action(kind="deploy", params={"idx": str(idx)})
            req = manager.submit(action, policy_name="test")
            with lock:
                results.append(req)

        threads = [threading.Thread(target=submit_one, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 10
        ids = {r.request_id for r in results}
        assert len(ids) == 10  # All unique IDs

    def test_concurrent_approve_reject(self) -> None:
        manager = ApprovalManager()
        actions = [Action(kind="deploy", params={"idx": str(i)}) for i in range(10)]
        reqs = [manager.submit(a, policy_name="test") for a in actions]

        def resolve(req: ApprovalRequest, approve: bool) -> None:
            if approve:
                manager.approve(req.request_id)
            else:
                manager.reject(req.request_id)

        threads = [
            threading.Thread(
                target=resolve,
                args=(reqs[i], i % 2 == 0),
            )
            for i in range(10)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(manager.list_pending()) == 0


# --- ApprovalPolicy + Guard integration ---


class TestApprovalPolicyGuardIntegration:
    """Tests for ApprovalPolicy as a Policy in Guard."""

    def test_approval_policy_returns_pending_decision(self) -> None:
        manager = ApprovalManager()
        policy = ApprovalPolicy(
            name="deploy-approval",
            action_kind="deploy",
            manager=manager,
        )
        guard = Guard(policies=[policy])
        decision = guard.check("deploy", target="production")
        assert decision.denied is True
        assert decision.reason is not None
        assert "pending approval" in decision.reason.lower()
        assert len(manager.list_pending()) == 1

    def test_non_matching_action_passes(self) -> None:
        manager = ApprovalManager()
        policy = ApprovalPolicy(
            name="deploy-approval",
            action_kind="deploy",
            manager=manager,
        )
        guard = Guard(policies=[policy])
        decision = guard.check("shell_command", command="echo hello")
        assert decision.allowed is True
        assert len(manager.list_pending()) == 0

    def test_approval_creates_request_with_action_details(self) -> None:
        manager = ApprovalManager()
        policy = ApprovalPolicy(
            name="deploy-approval",
            action_kind="deploy",
            manager=manager,
            reason="Production deployment requires approval",
        )
        guard = Guard(policies=[policy])
        guard.check("deploy", target="production", version="2.0")
        pending = manager.list_pending()
        assert len(pending) == 1
        req = pending[0]
        assert req.action.kind == "deploy"
        assert req.action.params["target"] == "production"
        assert req.reason == "Production deployment requires approval"


# --- YAML loading ---


class TestApprovalYAMLLoading:
    """Tests for loading approval policies from YAML."""

    def test_load_approval_policy_from_yaml(self) -> None:
        yaml_str = """
name: deploy-guard
type: approval
action: deploy
reason: Production deployments require human approval
"""
        policy = load_policy_from_string(yaml_str)
        assert isinstance(policy, ApprovalPolicy)
        assert policy.name == "deploy-guard"

    def test_yaml_approval_policy_has_manager(self) -> None:
        yaml_str = """
name: deploy-guard
type: approval
action: deploy
"""
        policy = load_policy_from_string(yaml_str)
        assert isinstance(policy, ApprovalPolicy)
        # Should have a default manager
        assert policy.manager is not None

    def test_yaml_approval_in_guard(self) -> None:
        yaml_str = """
name: deploy-guard
type: approval
action: deploy
reason: Needs human sign-off
"""
        guard = Guard()
        guard.load_policy_string(yaml_str)
        decision = guard.check("deploy", target="production")
        assert decision.denied is True
