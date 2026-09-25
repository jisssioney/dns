"""DNS 问题报文解码与确定性权威应答编码（仅标准库、离线）。

公开接口：
- MessageError: 报文格式错误（ValueError 子类）。
- decode_query(data: bytes) -> dict: 解码 DNS 查询报文。
- RecordError: 应答模型或资源记录不合规（ValueError 子类）。
- EncodeError: 查询或长度限制使应答无法编码（ValueError 子类）。
- encode_response(query: bytes, model: dict) -> bytes: 编码权威应答报文。

命令行：python dns.py decode HEX
"""

import json
import sys


class MessageError(ValueError):
    """DNS 报文无法解码。"""


class RecordError(ValueError):
    """应答模型或资源记录不合规。"""


class EncodeError(ValueError):
    """查询或长度限制使应答无法编码。"""


_MIN_MESSAGE_LEN = 12
_MAX_MESSAGE_LEN = 512
_MAX_QUESTIONS = 64
_MAX_NAME_WIRE_LEN = 255
_MAX_POINTER_JUMPS = 16
_LABEL_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
)
_HEXDIGITS = frozenset("0123456789abcdefABCDEF")
_MAX_LABEL_WIRE_LEN = 63
_MAX_RDATA_LEN = 65535
_MAX_TTL = 4294967295
_FLAG_QR = 0x8000
_FLAG_TC = 0x0200
_FLAGS_RESPONSE_BASE = 0x8400
_FLAGS_PRESERVED = 0x7910
_MODEL_KEYS = ["an", "ns", "ar", "limit"]
_RR_KEYS = ["name", "type", "class", "ttl", "rdata"]


def _read_name(data, offset, boundaries):
    """解码 offset 处的域名，返回 (name, 主流程下一个偏移)。

    boundaries 为已知标签边界偏移集合，随解析就地补充；
    压缩指针目标必须是其中向后的边界。
    """
    labels = []
    pos = offset
    end = None
    jumps = 0
    visited = set()
    wire_len = 1  # 根终止符占 1 字节
    while True:
        if pos >= len(data):
            raise MessageError("name truncated")
        if pos in visited:
            raise MessageError("compression pointer loop")
        visited.add(pos)
        boundaries.add(pos)
        length = data[pos]
        kind = length & 0xC0
        if kind == 0xC0:
            if pos + 1 >= len(data):
                raise MessageError("pointer truncated")
            target = ((length & 0x3F) << 8) | data[pos + 1]
            if target >= len(data):
                raise MessageError("pointer target out of bounds")
            if target >= pos:
                raise MessageError("pointer target not backward")
            if target not in boundaries:
                raise MessageError("pointer target not a label boundary")
            jumps += 1
            if jumps > _MAX_POINTER_JUMPS:
                raise MessageError("too many pointer jumps")
            if end is None:
                end = pos + 2
            pos = target
            continue
        if kind != 0x00:
            raise MessageError("reserved label type")
        pos += 1
        if length == 0:
            if end is None:
                end = pos
            break
        if pos + length > len(data):
            raise MessageError("label truncated")
        try:
            label = data[pos:pos + length].decode("ascii")
        except UnicodeDecodeError:
            raise MessageError("label not ascii") from None
        if any(ch not in _LABEL_CHARS for ch in label):
            raise MessageError("invalid label character")
        labels.append(label.lower())
        wire_len += length + 1
        if wire_len > _MAX_NAME_WIRE_LEN:
            raise MessageError("name too long")
        pos += length
    name = ".".join(labels) + "." if labels else "."
    return name, end


def decode_query(data: bytes) -> dict:
    """解码 DNS 查询报文，返回 {"id", "flags", "questions"}。"""
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not _MIN_MESSAGE_LEN <= len(data) <= _MAX_MESSAGE_LEN:
        raise MessageError("bad message length")
    msg_id = int.from_bytes(data[0:2], "big")
    flags = int.from_bytes(data[2:4], "big")
    qdcount = int.from_bytes(data[4:6], "big")
    ancount = int.from_bytes(data[6:8], "big")
    nscount = int.from_bytes(data[8:10], "big")
    arcount = int.from_bytes(data[10:12], "big")
    if not 1 <= qdcount <= _MAX_QUESTIONS:
        raise MessageError("bad question count")
    if ancount or nscount or arcount:
        raise MessageError("response sections must be empty")
    boundaries = set()
    questions = []
    pos = _MIN_MESSAGE_LEN
    for _ in range(qdcount):
        name, pos = _read_name(data, pos, boundaries)
        if pos + 4 > len(data):
            raise MessageError("question truncated")
        qtype = int.from_bytes(data[pos:pos + 2], "big")
        qclass = int.from_bytes(data[pos + 2:pos + 4], "big")
        pos += 4
        questions.append({"name": name, "type": qtype, "class": qclass})
    if pos != len(data):
        raise MessageError("trailing bytes")
    return {"id": msg_id, "flags": flags, "questions": questions}


def _normalize_name(name):
    """规范为小写绝对名，返回标签列表（根为 []）。"""
    if not isinstance(name, str):
        raise TypeError("name must be str")
    if name == ".":
        return []
    if not name.endswith("."):
        raise RecordError("name not absolute")
    labels = name[:-1].split(".")
    wire_len = 1  # 根终止符占 1 字节
    for label in labels:
        if not 1 <= len(label) <= _MAX_LABEL_WIRE_LEN:
            raise RecordError("bad label length")
        if any(ch not in _LABEL_CHARS for ch in label):
            raise RecordError("invalid label character")
        wire_len += len(label) + 1
        if wire_len > _MAX_NAME_WIRE_LEN:
            raise RecordError("name too long")
    return [label.lower() for label in labels]


def _check_uint(value, field, limit):
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(field + " must be int")
    if not 0 <= value <= limit:
        raise RecordError(field + " out of range")


def _validate_rr(rr):
    """校验单条资源记录，返回 (labels, type, class, ttl, rdata)。"""
    if not isinstance(rr, dict):
        raise TypeError("rr must be dict")
    if list(rr.keys()) != _RR_KEYS:
        raise RecordError("bad rr keys")
    labels = _normalize_name(rr["name"])
    _check_uint(rr["type"], "type", 65535)
    _check_uint(rr["class"], "class", 65535)
    _check_uint(rr["ttl"], "ttl", _MAX_TTL)
    rdata = rr["rdata"]
    if not isinstance(rdata, bytes):
        raise TypeError("rdata must be bytes")
    if len(rdata) > _MAX_RDATA_LEN:
        raise RecordError("rdata too long")
    return labels, rr["type"], rr["class"], rr["ttl"], rdata


def _validate_model(model):
    """校验应答模型，返回 (an, ns, ar, limit)，各段为规范化 RR 元组列表。"""
    if not isinstance(model, dict):
        raise TypeError("model must be dict")
    if list(model.keys()) != _MODEL_KEYS:
        raise RecordError("bad model keys")
    sections = []
    for key in _MODEL_KEYS[:3]:
        records = model[key]
        if not isinstance(records, list):
            raise TypeError(key + " must be list")
        sections.append([_validate_rr(rr) for rr in records])
    limit = model["limit"]
    if not isinstance(limit, int) or isinstance(limit, bool):
        raise TypeError("limit must be int")
    return sections[0], sections[1], sections[2], limit


def _encode_name(out, table, labels):
    """编码域名：登记标签边界，取最长既有后缀，同长取最小偏移。"""
    if not labels:
        out.append(0)
        return
    names = [tuple(labels[i:]) for i in range(len(labels))]
    match = None
    for i in range(len(names)):
        if names[i] in table:
            match = i
            break
    stop = match if match is not None else len(labels)
    for i in range(stop):
        table.setdefault(names[i], len(out))
        label = labels[i]
        out.append(len(label))
        out.extend(label.encode("ascii"))
    if match is not None:
        out.extend((0xC000 | table[names[match]]).to_bytes(2, "big"))
    else:
        out.append(0)


def _build_message(msg_id, flags, questions, sections):
    """按 an、ns、ar 顺序编码报文；每次调用重建压缩表。"""
    table = {}
    out = bytearray()
    out.extend(msg_id.to_bytes(2, "big"))
    out.extend(flags.to_bytes(2, "big"))
    out.extend(len(questions).to_bytes(2, "big"))
    for records in sections:
        out.extend(len(records).to_bytes(2, "big"))
    for labels, qtype, qclass in questions:
        _encode_name(out, table, labels)
        out.extend(qtype.to_bytes(2, "big"))
        out.extend(qclass.to_bytes(2, "big"))
    for records in sections:
        for labels, rrtype, rrclass, ttl, rdata in records:
            _encode_name(out, table, labels)
            out.extend(rrtype.to_bytes(2, "big"))
            out.extend(rrclass.to_bytes(2, "big"))
            out.extend(ttl.to_bytes(4, "big"))
            out.extend(len(rdata).to_bytes(2, "big"))
            out.extend(rdata)
    return bytes(out)


def encode_response(query: bytes, model: dict) -> bytes:
    """将查询报文与应答模型编码为确定性权威应答报文。"""
    decoded = decode_query(query)
    an, ns, ar, limit = _validate_model(model)
    if decoded["flags"] & _FLAG_QR:
        raise EncodeError("query must not be a response")
    if not _MIN_MESSAGE_LEN <= limit <= _MAX_RDATA_LEN:
        raise EncodeError("limit out of range")
    flags = _FLAGS_RESPONSE_BASE | (decoded["flags"] & _FLAGS_PRESERVED)
    questions = [
        (_normalize_name(q["name"]), q["type"], q["class"])
        for q in decoded["questions"]
    ]
    base = _build_message(decoded["id"], flags, questions, ([], [], []))
    if len(base) > limit:
        raise EncodeError("header and questions exceed limit")
    message = _build_message(decoded["id"], flags, questions, (an, ns, ar))
    if len(message) <= limit:
        return message
    an, ns, ar = list(an), list(ns), list(ar)
    while True:
        if ar:
            ar.pop()
        elif ns:
            ns.pop()
        else:
            an.pop()
        message = _build_message(
            decoded["id"], flags | _FLAG_TC, questions, (an, ns, ar)
        )
        if len(message) <= limit:
            return message


def main(argv):
    if len(argv) != 3 or argv[1] != "decode":
        sys.stderr.write("ArgumentError\n")
        return 2
    hextext = argv[2]
    if len(hextext) % 2 or any(c not in _HEXDIGITS for c in hextext):
        sys.stderr.write("ArgumentError\n")
        return 2
    try:
        result = decode_query(bytes.fromhex(hextext))
    except MessageError:
        sys.stderr.write("MessageError\n")
        return 3
    sys.stdout.write(
        json.dumps(result, ensure_ascii=True, separators=(",", ":")) + "\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
