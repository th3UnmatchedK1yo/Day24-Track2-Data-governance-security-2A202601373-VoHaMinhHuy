"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc Guide.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input đúng slide §3.3 (đã định nghĩa sẵn, đừng đổi field):

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool


def check(context: PolicyContext) -> tuple[bool, str]:
    """Policy Enforcement Point — đánh giá request dựa trên context.

    Trả về (allow: bool, reason: str). reason KHÔNG BAO GIỜ rỗng.
    """
    # Rule 1 (BẮT BUỘC): restricted data + egress enabled → DENY
    # Đây là rule tối thiểu theo đề bài — ngăn PII bị gửi ra ngoài.
    if context.data_classification == "restricted" and context.egress_enabled:
        return (
            False,
            f"DENY: restricted data with egress enabled is forbidden "
            f"(owner={context.agent_owner}, purpose={context.request_purpose})",
        )

    # Rule 2: restricted data ở delegation depth > 1 → cảnh giác
    # (agent gọi agent gọi agent — quá sâu, có thể bị lợi dụng)
    if context.data_classification == "restricted" and context.delegation_depth > 1:
        return (
            False,
            f"DENY: restricted data at delegation depth {context.delegation_depth} "
            f"exceeds maximum (owner={context.agent_owner})",
        )

    # Default: ALLOW (với reason mô tả đầy đủ)
    return (
        True,
        f"ALLOW: classification={context.data_classification}, "
        f"egress={'enabled' if context.egress_enabled else 'disabled'}, "
        f"depth={context.delegation_depth}, "
        f"purpose={context.request_purpose}, owner={context.agent_owner}",
    )
