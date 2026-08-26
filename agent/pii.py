"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc Guide.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re


# ── Regex patterns ──
# Thứ tự quan trọng: EMAIL trước (tránh bị digit-pattern nuốt nhầm),
# rồi BANK_ACCOUNT (context-based, ưu tiên hơn CCCD khi có "STK"),
# rồi CCCD (12 digits), rồi PHONE (10 digits bắt đầu bằng 0).

_EMAIL_RE = re.compile(
    r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
)

# STK / số tài khoản + 8-16 chữ số
_BANK_ACCOUNT_RE = re.compile(
    r"(?:STK|[Ss]ố tài khoản|[Ss]o tai khoan|[Ss]TK)"
    r"\s*:?\s*"
    r"(\d{8,16})"
)

# CCCD: đúng 12 chữ số liên tiếp, word boundary
_CCCD_RE = re.compile(r"\b(\d{12})\b")

# SĐT: bắt đầu bằng 0, tổng cộng 10 chữ số (VN standard)
_PHONE_RE = re.compile(r"\b(0\d{9})\b")


def detect(text: str) -> list[dict]:
    """Phát hiện PII trong text tiếng Việt bằng regex.

    Trả về list[{"type": str, "start": int, "end": int}] không overlap.
    """
    entities: list[dict] = []
    used_spans: list[tuple[int, int]] = []

    def _is_overlapping(start: int, end: int) -> bool:
        for s, e in used_spans:
            if start < e and s < end:
                return True
        return False

    def _add(entity_type: str, start: int, end: int) -> None:
        if not _is_overlapping(start, end):
            entities.append({"type": entity_type, "start": start, "end": end})
            used_spans.append((start, end))

    # 1. EMAIL — ưu tiên cao nhất
    for m in _EMAIL_RE.finditer(text):
        _add("EMAIL", m.start(), m.end())

    # 2. BANK_ACCOUNT — context-based (có "STK" phía trước)
    for m in _BANK_ACCOUNT_RE.finditer(text):
        # group(1) là phần digits, ta chỉ đánh dấu phần số
        _add("VN_BANK_ACCOUNT", m.start(1), m.end(1))

    # 3. CCCD — 12 chữ số (sau khi đã loại BANK_ACCOUNT)
    for m in _CCCD_RE.finditer(text):
        _add("VN_CCCD", m.start(1), m.end(1))

    # 4. PHONE — 10 chữ số bắt đầu bằng 0 (sau khi đã loại CCCD)
    for m in _PHONE_RE.finditer(text):
        _add("VN_PHONE", m.start(1), m.end(1))

    # Sắp xếp theo vị trí xuất hiện
    entities.sort(key=lambda e: e["start"])
    return entities


def redact(text: str) -> str:
    """Thay tất cả PII detected bằng [REDACTED_<TYPE>].

    Thay từ cuối văn bản về đầu để offset không bị lệch.
    """
    entities = detect(text)
    # Sắp xếp ngược theo start để thay từ cuối
    for entity in sorted(entities, key=lambda e: e["start"], reverse=True):
        placeholder = f"[REDACTED_{entity['type']}]"
        text = text[: entity["start"]] + placeholder + text[entity["end"] :]
    return text
