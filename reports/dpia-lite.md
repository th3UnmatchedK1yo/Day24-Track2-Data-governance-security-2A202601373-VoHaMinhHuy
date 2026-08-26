# DPIA-lite (1 trang)

## 1. Dữ liệu gì

Agent này chạm vào các loại dữ liệu cá nhân (PII) sau:

- **`search_docs`** (đọc `corpus/*.md`):
  - Nội dung ticket khách hàng: có thể chứa tên, mô tả vấn đề, mã khách hàng (KH-NNNNNN)
  - Đây là dữ liệu **untrusted** — attacker có thể cài payload injection vào corpus

- **`read_customer`** (đọc `data/customers.json`):
  - **Tên đầy đủ** (ví dụ: Lê Thu Trang)
  - **CCCD** — Căn cước công dân 12 số (ví dụ: 811753472374)
  - **Số điện thoại** (ví dụ: 0861707895)
  - **Số tài khoản ngân hàng** (ví dụ: 9103069783)
  - **Email** (ví dụ: le.thu.trang666@example.vn)
  - **related_tickets** — danh sách ticket liên quan

  → Phân loại: **restricted** (dữ liệu cá nhân nhạy cảm theo Luật 91/2025)

## 2. Mục đích gì

- **Tóm tắt ticket hỗ trợ khách hàng**: Agent đọc corpus để tổng hợp các ticket đang mở, phục vụ nhân viên CSKH
- **Tra cứu thông tin khách hàng**: Agent đọc customer data để liên kết ticket với thông tin khách, phục vụ đối soát và hỗ trợ
- **Không có mục đích marketing, profiling, hay bán dữ liệu cho bên thứ ba**

## 3. Chảy đi đâu

### Luồng dữ liệu trong lab (với `--mock`):

```
corpus/*.md ──search_docs──► Run A (agent) ──typed ticket_ids──► Run B (agent)
                                                                      │
data/customers.json ──read_customer──────────────────────────────────► Run B
                                                                      │
                                                                      ▼
                                                              stdout (trả lời user)
                                                              reports/ledger.jsonl (audit)
```

- **stdout**: Câu trả lời tóm tắt cho người dùng (KHÔNG chứa PII nhờ trifecta split)
- **`reports/ledger.jsonl`**: Audit log ghi mọi tool call (decision + reason), tamper-evident bằng SHA-256 hash chain. Chứa metadata (tool name, classification, decision) nhưng KHÔNG chứa PII gốc
- **`localhost:9999` (sink)**: Bị chặn bởi policy PEP — `restricted + egress_enabled → DENY`. Sau khi contain, sink log rỗng
- **Mock LLM**: Chạy hoàn toàn local, KHÔNG gọi network, KHÔNG gửi dữ liệu ra ngoài

### Nếu dùng `--model claude-...` (KHÔNG dùng cho chấm điểm):

- Dữ liệu (bao gồm nội dung ticket và có thể cả PII trong context) sẽ được gửi qua **Anthropic API** (server ở Mỹ)
- Đây là **chuyển dữ liệu xuyên biên giới** theo Nghị định 356/2025
- Cần: hồ sơ xuyên biên giới 60 ngày, đánh giá tác động theo Điều 31
- **Tuy nhiên**: Lab này chấm bằng `--mock`, nên KHÔNG có transfer xuyên biên giới trong quá trình chấm điểm

### Egress control đã implement:

1. **`tools.py`**: Hard-allowlist chỉ cho phép `localhost:9999` (an toàn lab)
2. **`policy.py`**: PEP deny `restricted + egress_enabled` (ngăn PII ra ngoài)
3. **`runner.py`**: Run B (đọc private data) có `egress_enabled=False` — không bao giờ gọi `http_post`
