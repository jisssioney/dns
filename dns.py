"""DNS 查询报文解码器：仅用标准库、离线运行。

公开接口：
- MessageError(ValueError)：报文非法时抛出。
- decode_query(data: bytes) -> dict：解码 DNS 查询报文。

命令行：
    python dns.py decode HEX
"""

import json
import struct
import sys

__all__ = ["MessageError", "decode_query"]


class MessageError(ValueError):
    """DNS 报文格式非法。"""


_MIN_MESSAGE_LEN = 12
_MAX_MESSAGE_LEN = 512
_MAX_QUESTIONS = 64
_MAX_LABEL_LEN = 63
_MAX_NAME_WIRE_LEN = 255
_MAX_POINTER_JUMPS = 16

_LABEL_BYTES = frozenset(
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
)
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def _read_name(data, offset, boundaries):
    """在 offset 处解析（可压缩的）域名。

    boundaries 记录报文中所有已知的标签起始位置，用于校验压缩指针。
    返回 (name, next_offset)，name 为小写 ASCII 绝对域名。
    """
    labels = []
    wire_len = 1  # 根结束符占 1 字节
    pos = offset
    next_offset = None
    jumps = 0
    while True:
        if pos >= len(data):
            raise MessageError("truncated name")
        length = data[pos]
        kind = length & 0xC0
        if kind == 0xC0:
            if pos + 1 >= len(data):
                raise MessageError("truncated compression pointer")
            target = ((length & 0x3F) << 8) | data[pos + 1]
            if target >= pos:
                raise MessageError("compression pointer must point backward")
            if target not in boundaries:
                raise MessageError("compression pointer target is not a label boundary")
            boundaries.add(pos)
            if next_offset is None:
                next_offset = pos + 2
            jumps += 1
            if jumps > _MAX_POINTER_JUMPS:
                raise MessageError("too many compression pointer jumps")
            pos = target
            continue
        if kind != 0x00:
            raise MessageError("reserved label type")
        if length == 0:
            if next_offset is None:
                next_offset = pos + 1
            break
        if length > _MAX_LABEL_LEN:
            raise MessageError("label too long")
        end = pos + 1 + length
        if end > len(data):
            raise MessageError("truncated label")
        label = data[pos + 1:end]
        if any(byte not in _LABEL_BYTES for byte in label):
            raise MessageError("invalid label characters")
        wire_len += 1 + length
        if wire_len > _MAX_NAME_WIRE_LEN:
            raise MessageError("expanded name too long")
        boundaries.add(pos)
        labels.append(label.decode("ascii").lower())
        pos = end
    name = ".".join(labels) + "." if labels else "."
    return name, next_offset


def decode_query(data):
    """解码 DNS 查询报文，返回 {"id", "flags", "questions"} 字典。"""
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not _MIN_MESSAGE_LEN <= len(data) <= _MAX_MESSAGE_LEN:
        raise MessageError("message length out of range")
    msg_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(
        "!6H", data[:12]
    )
    if ancount or nscount or arcount:
        raise MessageError("answer/authority/additional sections must be empty")
    if not 1 <= qdcount <= _MAX_QUESTIONS:
        raise MessageError("question count out of range")
    boundaries = set()
    questions = []
    offset = 12
    for _ in range(qdcount):
        name, offset = _read_name(data, offset, boundaries)
        if offset + 4 > len(data):
            raise MessageError("truncated question")
        qtype, qclass = struct.unpack("!2H", data[offset:offset + 4])
        offset += 4
        questions.append({"name": name, "type": qtype, "class": qclass})
    if offset != len(data):
        raise MessageError("trailing bytes after questions")
    return {"id": msg_id, "flags": flags, "questions": questions}


def main(argv):
    if len(argv) != 3 or argv[1] != "decode":
        sys.stderr.write("ArgumentError\n")
        return 2
    hextext = argv[2]
    if len(hextext) % 2 or any(c not in _HEX_DIGITS for c in hextext):
        sys.stderr.write("ArgumentError\n")
        return 2
    data = bytes.fromhex(hextext)
    try:
        result = decode_query(data)
    except MessageError:
        sys.stderr.write("MessageError\n")
        return 3
    sys.stdout.write(
        json.dumps(result, ensure_ascii=True, separators=(",", ":")) + "\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
