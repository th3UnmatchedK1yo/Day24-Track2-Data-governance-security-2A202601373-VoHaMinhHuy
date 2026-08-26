# Compliance mapping

Điền evidence là **đường dẫn file/dòng thật** trong repo của bạn — không
phải mô tả chung. Xem `Guide.md` Bước 4 và `Rubric.md`.

| Requirement | Control | Evidence |
|---|---|---|
| Luật 91/2025 — quyền yêu cầu xoá | chưa implement, xem stretch goal #3 (delete cascade) | — |
| NĐ 356/2025 — hồ sơ xuyên biên giới 60 ngày | data-flow inventory cho LLM API call; lab chạy bằng `--mock` nên KHÔNG có transfer xuyên biên giới. Nếu dùng `--model` thì dữ liệu gửi qua Anthropic API (nước ngoài) | `reports/dpia-lite.md` §2, §3 |
| ASI03 — privilege abuse | per-agent identity (`agent_id`, `run_id` riêng cho mỗi run), policy PEP kiểm soát quyền trước mỗi tool call, mỗi run có role riêng (Run A: public, Run B: restricted, egress=off) | `agent/policy.py` hàm `check()` (dòng 39-65), `agent/runner.py` các biến `run_a_id`/`run_b_id` (dòng 102-103), ledger field `agent_owner`/`run_id` |
| ASI01 — goal hijack | trifecta split: Run A đọc untrusted content, Run B đọc private data; Run B KHÔNG nhận free text, chỉ nhận typed ticket_id → related_tickets mapping (nguồn tin cậy) | `agent/runner.py` hàm `handle()` (dòng 95-175), `reports/attack-after.log` (sink rỗng) |
| ISO 42001 Clause 5-6 | policy-as-code (`agent/policy.py`) có review qua git, audit ledger tamper-evident (`agent/ledger.py`) với SHA-256 hash chain, mọi decision có reason non-empty | `agent/policy.py`, `agent/ledger.py`, `reports/ledger.jsonl`, `git log` |
