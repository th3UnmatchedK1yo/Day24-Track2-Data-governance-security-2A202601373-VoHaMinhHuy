"""BƯỚC 3d — audit ledger append-only, tamper-evident (10').

JSONL, mỗi tool call một dòng. Đọc Guide.md (§3d).

Interface bắt buộc (tests/test_ledger.py và agent/runner.py gọi trực tiếp):

    append(entry: dict, path: pathlib.Path) -> dict
        `entry` phải có tối thiểu các field:
            ts, agent_id, run_id, tool, args_hash, classification,
            decision, reason
        Hàm tự thêm 2 field:
            prev_hash  = hash của dòng ngay trước trong file này, hoặc
                         "0" * 64 nếu là dòng đầu tiên
            hash       = sha256 tính từ nội dung dòng NÀY (bao gồm cả
                         prev_hash, KHÔNG bao gồm field hash) — dùng
                         json.dumps(..., sort_keys=True) trước khi hash
                         để thứ tự field không ảnh hưởng kết quả.
        Append 1 dòng JSON (utf-8, ensure_ascii=False) vào cuối `path`,
        tạo file/thư mục cha nếu chưa có. Trả về dict đầy đủ đã ghi
        (bao gồm prev_hash/hash).

    verify(path: pathlib.Path) -> bool
        Đọc toàn bộ file, trả về True nếu TẤT CẢ đều đúng:
          - mọi dòng có `reason` non-empty
          - prev_hash của dòng n == hash đã lưu của dòng n-1 (dòng đầu so
            với "0" * 64)
          - hash lưu trong dòng n khớp lại khi tính lại từ nội dung dòng đó
        Trả về False nếu bất kỳ dòng nào bị sửa/xoá/chèn giữa file, hoặc
        thiếu reason.

Sinh viên phải tự tay chứng minh được: sửa 1 ký tự trong 1 dòng giữa file
rồi gọi verify() phải trả về False.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def _compute_hash(entry: dict) -> str:
    """Tính SHA-256 từ nội dung entry (KHÔNG bao gồm field 'hash')."""
    to_hash = {k: v for k, v in entry.items() if k != "hash"}
    canonical = json.dumps(to_hash, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _get_last_hash(path: Path) -> str:
    """Lấy hash của dòng cuối cùng trong file, hoặc '0'*64 nếu file rỗng."""
    if not path.exists():
        return "0" * 64
    content = path.read_text(encoding="utf-8").strip()
    if not content:
        return "0" * 64
    last_line = content.splitlines()[-1]
    last_entry = json.loads(last_line)
    return last_entry["hash"]


def append(entry: dict, path: Path) -> dict:
    """Ghi 1 dòng audit vào ledger, tự thêm prev_hash + hash."""
    path.parent.mkdir(parents=True, exist_ok=True)

    # Lấy prev_hash từ dòng cuối
    entry["prev_hash"] = _get_last_hash(path)

    # Tính hash (không bao gồm field "hash" trong input)
    entry.pop("hash", None)  # xoá nếu caller vô tình truyền vào
    entry["hash"] = _compute_hash(entry)

    # Append dòng JSON
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    return entry


def verify(path: Path) -> bool:
    """Kiểm tra toàn bộ hash chain + reason non-empty."""
    if not path.exists():
        return False

    content = path.read_text(encoding="utf-8").strip()
    if not content:
        return False

    lines = content.splitlines()
    prev_hash = "0" * 64

    for line in lines:
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            return False

        # Kiểm tra reason non-empty
        if not entry.get("reason"):
            return False

        # Kiểm tra prev_hash liên kết đúng
        if entry.get("prev_hash") != prev_hash:
            return False

        # Tính lại hash và so sánh
        stored_hash = entry.get("hash")
        computed_hash = _compute_hash(entry)
        if computed_hash != stored_hash:
            return False

        prev_hash = stored_hash

    return True
