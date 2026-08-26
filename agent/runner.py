"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc Guide.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được biến thể 5 (không dấu / lookalike): filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng biến
thể 5, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None) -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from agent import ledger, tools
from agent.policy import PolicyContext, check as policy_check

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"


def _make_entry(
    agent_id: str,
    run_id: str,
    tool_name: str,
    args_summary: str,
    classification: str,
    decision: str,
    reason: str,
) -> dict:
    """Tạo entry dict chuẩn cho ledger."""
    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "agent_id": agent_id,
        "run_id": run_id,
        "tool": tool_name,
        "args_hash": hashlib.sha256(args_summary.encode("utf-8")).hexdigest()[:16],
        "classification": classification,
        "decision": decision,
        "reason": reason,
    }


def _extract_ticket_id(filename: str) -> int | None:
    """Trích ticket_id từ tên file (vd 'ticket-007.md' -> 7).

    Chỉ lấy file dạng ticket-NNN.md (không lấy ticket-904b.md).
    Cả ticket phụ (904b) cũng được tính theo ticket chính (904).
    """
    m = re.search(r"ticket-(\d+)", filename)
    if m:
        return int(m.group(1))
    return None


def _build_ticket_to_customer_map() -> dict[int, list[str]]:
    """Xây map ticket_id -> list[customer_id] từ NGUỒN TIN CẬY (customers.json)."""
    customers = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))
    mapping: dict[int, list[str]] = {}
    for cust in customers:
        for tid in cust.get("related_tickets", []):
            mapping.setdefault(tid, []).append(cust["customer_id"])
    return mapping


def handle(message: str, llm, log_dir: Path | None = None) -> str:
    """Trifecta-split runner: tách untrusted content khỏi private data.

    Run A: đọc corpus (untrusted), trích ticket_id typed từ tên file.
    Run B: tra customer qua related_tickets (trusted), đọc private data.
    Không run nào cầm cả 3 chân cùng lúc.
    """
    ledger_dir = log_dir or REPORTS_DIR
    ledger_path = ledger_dir / "ledger.jsonl"
    agent_id = "lab24-agent"
    run_a_id = f"run-a-{uuid.uuid4().hex[:8]}"
    run_b_id = f"run-b-{uuid.uuid4().hex[:8]}"

    # ════════════════════════════════════════════════════════════════════
    # RUN A — untrusted content only (search_docs)
    #   KHÔNG có quyền: read_customer, http_post
    #   egress_enabled = False
    # ════════════════════════════════════════════════════════════════════

    # Policy check cho search_docs
    ctx_search = PolicyContext(
        data_classification="public",
        request_purpose="search-corpus",
        agent_owner=run_a_id,
        delegation_depth=0,
        egress_enabled=False,
    )
    allow_search, reason_search = policy_check(ctx_search)
    ledger.append(
        _make_entry(
            agent_id, run_a_id, "search_docs", message,
            "public", "allow" if allow_search else "deny", reason_search,
        ),
        ledger_path,
    )

    if not allow_search:
        return "Policy denied search_docs."

    # Gọi search_docs
    docs = tools.search_docs(message)

    # Trích ticket_id typed từ TÊN FILE (sanitized, không từ content)
    ticket_ids: list[int] = []
    for d in docs:
        tid = _extract_ticket_id(d["id"])
        if tid is not None:
            ticket_ids.append(tid)

    # Phát hiện injection (chỉ để log, KHÔNG dùng customer_id từ đây)
    combined_text = "\n\n".join(d["text"] for d in docs)
    injected = llm.find_injection(combined_text)

    if injected is not None:
        # Log deny cho http_post vì phát hiện injection attempt
        ctx_exfil = PolicyContext(
            data_classification="restricted",
            request_purpose="exfil-attempt-blocked",
            agent_owner=run_a_id,
            delegation_depth=0,
            egress_enabled=True,
        )
        _, reason_exfil = policy_check(ctx_exfil)
        ledger.append(
            _make_entry(
                agent_id, run_a_id, "http_post",
                injected.target_url,
                "restricted", "deny", reason_exfil,
            ),
            ledger_path,
        )

    # ════════════════════════════════════════════════════════════════════
    # RUN B — private data only (read_customer)
    #   KHÔNG đọc free text, CHỈ nhận typed ticket_ids từ Run A
    #   Tra customer qua related_tickets (nguồn tin cậy)
    #   egress_enabled = False
    # ════════════════════════════════════════════════════════════════════

    ticket_to_customers = _build_ticket_to_customer_map()

    # Map ticket_id → customer_id qua NGUỒN TIN CẬY
    customer_ids_to_read: set[str] = set()
    for tid in ticket_ids:
        for cid in ticket_to_customers.get(tid, []):
            customer_ids_to_read.add(cid)

    for cid in sorted(customer_ids_to_read):
        ctx_read = PolicyContext(
            data_classification="restricted",
            request_purpose="customer-lookup-for-ticket",
            agent_owner=run_b_id,
            delegation_depth=1,
            egress_enabled=False,
        )
        allow_read, reason_read = policy_check(ctx_read)
        ledger.append(
            _make_entry(
                agent_id, run_b_id, "read_customer", cid,
                "restricted", "allow" if allow_read else "deny", reason_read,
            ),
            ledger_path,
        )

        if allow_read:
            try:
                tools.read_customer(cid)
            except tools.ToolError:
                pass

    # ════════════════════════════════════════════════════════════════════
    # Trả về kết quả — hành vi quan sát từ ngoài không đổi
    # ════════════════════════════════════════════════════════════════════
    return llm.summarize(docs)
