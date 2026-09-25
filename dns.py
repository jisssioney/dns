"""DNS 问题报文解码与确定性权威应答编码（仅标准库、离线）。

公开接口：
- MessageError: 报文格式错误（ValueError 子类）。
- ZoneError(ValueError): 区域模型不合法（ValueError 子类）。
- RecordError: 记录模型不符合编码要求（ValueError 子类）。
- EncodeError: 应答无法在给定限制内编码（ValueError 子类）。
- decode_query(data: bytes) -> dict: 解码 DNS 查询报文。
- answer(query: bytes, zone: dict, limit: int = 512) -> bytes: 权威应答入口。
- encode_response(query: bytes, model: dict) -> bytes: 编码权威应答报文。

命令行：python dns.py decode HEX
"""

import json
import sys


class MessageError(ValueError):
    """DNS 报文无法解码。"""


class ZoneError(ValueError):
    """区域模型不合法。"""


class RecordError(ValueError):
    """记录模型不符合应答编码要求。"""


class EncodeError(ValueError):
    """应答无法在给定限制内编码。"""


_MIN_MESSAGE_LEN = 12
_MAX_MESSAGE_LEN = 512
_MAX_QUESTIONS = 64
_MAX_NAME_WIRE_LEN = 255
_MAX_POINTER_JUMPS = 16
_LABEL_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
)
_HEXDIGITS = frozenset("0123456789abcdefABCDEF")

_MODEL_KEYS = ["an", "ns", "ar", "limit"]
_RR_KEYS = ["name", "type", "class", "ttl", "rdata"]
_ZONE_KEYS = ["origin", "records"]
_TYPE_SOA = 6
_MAX_LABEL_LEN = 63
_MAX_RDATA_LEN = 65535
_MAX_TTL = 4294967295
_MIN_LIMIT = 12
_MAX_LIMIT = 65535
_MAX_SECTION_COUNT = 65535
_MAX_POINTER_TARGET = 0x3FFF
_FLAGS_RESPONSE = 0x8400  # QR | AA
_FLAGS_KEPT = 0x7910  # opcode | RD | CD
_FLAG_TC = 0x0200
_FLAG_QR = 0x8000
_RCODE_MASK = 0x000F
_RCODE_NOERROR = 0
_RCODE_NXDOMAIN = 3
_RCODE_REFUSED = 5
_MIN_ANSWER_QUESTIONS = 2


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
    """按解码规则把 name 规范为小写绝对名，返回标签列表（根为 []）。"""
    if not isinstance(name, str):
        raise TypeError("name must be str")
    if not name.endswith("."):
        raise RecordError("name not absolute")
    parts = name[:-1].split(".") if name != "." else []
    labels = []
    wire_len = 1  # 根终止符占 1 字节
    for part in parts:
        label = part.lower()
        if not 1 <= len(label) <= _MAX_LABEL_LEN:
            raise RecordError("bad label length")
        if any(ch not in _LABEL_CHARS for ch in label):
            raise RecordError("invalid label character")
        labels.append(label)
        wire_len += len(label) + 1
        if wire_len > _MAX_NAME_WIRE_LEN:
            raise RecordError("name too long")
    return labels


def _canonical_name(labels):
    """标签列表 -> 小写绝对名字符串（根为 "."）。"""
    return ".".join(labels) + "." if labels else "."


def _check_int(value, field):
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(field + " must be int")


def _validate_rr(rr):
    """校验单条 RR，返回 (labels, type, class, ttl, rdata)。"""
    if not isinstance(rr, dict):
        raise TypeError("rr must be dict")
    if list(rr.keys()) != _RR_KEYS:
        raise RecordError("rr keys must be name,type,class,ttl,rdata")
    labels = _normalize_name(rr["name"])
    rrtype = rr["type"]
    rrclass = rr["class"]
    ttl = rr["ttl"]
    rdata = rr["rdata"]
    _check_int(rrtype, "type")
    _check_int(rrclass, "class")
    _check_int(ttl, "ttl")
    if not isinstance(rdata, bytes):
        raise TypeError("rdata must be bytes")
    if not 0 <= rrtype <= 0xFFFF:
        raise RecordError("type out of range")
    if not 0 <= rrclass <= 0xFFFF:
        raise RecordError("class out of range")
    if not 0 <= ttl <= _MAX_TTL:
        raise RecordError("ttl out of range")
    if len(rdata) > _MAX_RDATA_LEN:
        raise RecordError("rdata too long")
    return labels, rrtype, rrclass, ttl, rdata


def _rr_dict(labels, rrtype, rrclass, ttl, rdata):
    """规范化后的 RR 模型字典（键序 name,type,class,ttl,rdata）。"""
    return {
        "name": _canonical_name(labels),
        "type": rrtype,
        "class": rrclass,
        "ttl": ttl,
        "rdata": rdata,
    }


def _validate_model(model):
    """校验应答模型，返回 (an, ns, ar, limit)，RR 已规范化。"""
    if not isinstance(model, dict):
        raise TypeError("model must be dict")
    if list(model.keys()) != _MODEL_KEYS:
        raise RecordError("model keys must be an,ns,ar,limit")
    sections = []
    for key in ("an", "ns", "ar"):
        rrs = model[key]
        if not isinstance(rrs, list):
            raise TypeError(key + " must be list")
        sections.append([_validate_rr(rr) for rr in rrs])
    limit = model["limit"]
    _check_int(limit, "limit")
    return sections[0], sections[1], sections[2], limit


def _validate_zone(zone):
    """校验区域，返回 (origin 标签列表, 规范化 RR 字典列表, apex SOA 字典)。"""
    if not isinstance(zone, dict):
        raise TypeError("zone must be dict")
    if list(zone.keys()) != _ZONE_KEYS:
        raise ZoneError("zone keys must be origin,records")
    origin_raw = zone["origin"]
    if not isinstance(origin_raw, str):
        raise TypeError("origin must be str")
    try:
        origin_labels = _normalize_name(origin_raw)
    except RecordError:
        raise ZoneError("invalid origin") from None
    raw_records = zone["records"]
    if not isinstance(raw_records, list):
        raise TypeError("records must be list")
    records = []
    origin_len = len(origin_labels)
    for rr in raw_records:
        labels, rrtype, rrclass, ttl, rdata = _validate_rr(rr)
        if origin_len and labels[-origin_len:] != origin_labels:
            raise ZoneError("owner not within origin")
        records.append(_rr_dict(labels, rrtype, rrclass, ttl, rdata))
    origin_name = _canonical_name(origin_labels)
    soa = [rr for rr in records
           if rr["name"] == origin_name and rr["type"] == _TYPE_SOA]
    if len(soa) != 1:
        raise ZoneError("origin must have exactly one SOA")
    apex = soa[0]
    zone_class = apex["class"]
    if any(rr["class"] != zone_class for rr in records):
        raise ZoneError("record classes not uniform")
    return origin_labels, records, apex


def answer(query: bytes, zone: dict, limit: int = 512) -> bytes:
    """根据 zone 回答 query，返回编码后的确定性权威应答报文。"""
    msg = decode_query(query)
    questions = msg["questions"]
    if not _MIN_ANSWER_QUESTIONS <= len(questions) <= _MAX_QUESTIONS:
        raise EncodeError("bad question count")
    if msg["flags"] & _FLAG_QR:
        raise EncodeError("query has QR set")
    _check_int(limit, "limit")
    if not _MIN_LIMIT <= limit <= _MAX_LIMIT:
        raise EncodeError("limit out of range")
    _origin_labels, records, apex = _validate_zone(zone)
    rcode = _RCODE_NOERROR
    an = []
    ns = []
    ar = []
    classes = {q["class"] for q in questions}
    if len(classes) != 1:
        rcode = _RCODE_REFUSED
    else:
        qname = questions[0]["name"]
        qtype = questions[0]["type"]
        matched = [rr for rr in records
                   if rr["name"] == qname and rr["type"] == qtype]
        if matched:
            an = matched
        else:
            if not any(rr["name"] == qname for rr in records):
                rcode = _RCODE_NXDOMAIN
            # NODATA（名称存在、type 未命中）保持 RCODE=0；
            # NODATA 与 NXDOMAIN 都仅把 apex SOA 放入 ns。
            ns = [apex]
    model = {"an": an, "ns": ns, "ar": ar, "limit": limit}
    return _encode_response(query, model, rcode)


def _write_name(out, labels, offsets):
    """把域名写入 out；offsets 记录已出现的标签边界（后缀 -> 最小偏移）。"""
    match = 0
    target = None
    for i in range(len(labels)):
        suffix = tuple(labels[i:])
        if suffix in offsets:
            match = len(labels) - i
            target = offsets[suffix]
            break
    stop = len(labels) - match
    for i, label in enumerate(labels):
        if i >= stop:
            break
        if len(out) <= _MAX_POINTER_TARGET:
            offsets.setdefault(tuple(labels[i:]), len(out))
        out.append(len(label))
        out.extend(label.encode("ascii"))
    if target is not None:
        out.extend((0xC000 | target).to_bytes(2, "big"))
    else:
        out.append(0)


def _encode_message(msg, an, ns, ar, rcode, truncated):
    """编码报文，同时返回 an/ns/ar 每条 RR 的线上字节跨度。

    跨度只依赖该记录之前的字节（域名压缩仅指向后方），因此尾删记录后，
    保留前缀逐字节不变，可直接用跨度做算术裁剪而无需反复重编码。
    """
    flags = _FLAGS_RESPONSE | (msg["flags"] & _FLAGS_KEPT) | (rcode & _RCODE_MASK)
    if truncated:
        flags |= _FLAG_TC
    out = bytearray()
    out += msg["id"].to_bytes(2, "big")
    out += flags.to_bytes(2, "big")
    out += len(msg["questions"]).to_bytes(2, "big")
    out += len(an).to_bytes(2, "big")
    out += len(ns).to_bytes(2, "big")
    out += len(ar).to_bytes(2, "big")
    offsets = {}
    for question in msg["questions"]:
        _write_name(out, _normalize_name(question["name"]), offsets)
        out += question["type"].to_bytes(2, "big")
        out += question["class"].to_bytes(2, "big")
    spans = []
    for section in (an, ns, ar):
        section_spans = []
        for rr in section:
            labels, rrtype, rrclass, ttl, rdata = rr
            start = len(out)
            _write_name(out, labels, offsets)
            out += rrtype.to_bytes(2, "big")
            out += rrclass.to_bytes(2, "big")
            out += ttl.to_bytes(4, "big")
            out += len(rdata).to_bytes(2, "big")
            out += rdata
            section_spans.append(len(out) - start)
        spans.append(section_spans)
    return bytes(out), spans


def _encode_response(query, model, rcode):
    """encode_response 的实现：rcode 由 answer 给定，公开入口恒为 0。

    区段超过 65535 条或整体超过 limit 时，按 ar、ns、an 顺序尾删整条并
    置 TC；区段清空后仍超长则抛 EncodeError，头部计数永不溢出。

    每轮用一次实际编码取得各 RR 的字节跨度（域名压缩只指向后方，区段内
    尾删对保留前缀无影响），据此批量算术裁剪；被删的 ns/an 记录若曾是
    后续记录唯一的压缩目标，实际重编码会略长，故重编码验证后按需再来
    一轮——每轮至少删除一条，必然终止。
    """
    if not isinstance(query, bytes):
        raise TypeError("query must be bytes")
    an, ns, ar, limit = _validate_model(model)
    msg = decode_query(query)
    if msg["flags"] & _FLAG_QR:
        raise EncodeError("query has QR set")
    if not _MIN_LIMIT <= limit <= _MAX_LIMIT:
        raise EncodeError("limit out of range")
    # 计数上限：先把每段裁到至多 65535 条（尾删），头部计数才不会溢出。
    truncated = (
        len(an) > _MAX_SECTION_COUNT
        or len(ns) > _MAX_SECTION_COUNT
        or len(ar) > _MAX_SECTION_COUNT
    )
    an = an[:_MAX_SECTION_COUNT]
    ns = ns[:_MAX_SECTION_COUNT]
    ar = ar[:_MAX_SECTION_COUNT]
    while True:
        out, spans = _encode_message(msg, an, ns, ar, rcode, truncated)
        if len(out) <= limit:
            return out
        an_spans, ns_spans, ar_spans = spans
        keep = [len(an), len(ns), len(ar)]
        total = len(out)
        # 按 ar、ns、an 优先级尾删整条（跨度稳定，算术批量裁剪）。
        for idx in (2, 1, 0):
            section_spans = (an_spans, ns_spans, ar_spans)[idx]
            while total > limit and keep[idx] > 0:
                total -= section_spans[keep[idx] - 1]
                keep[idx] -= 1
        if keep == [0, 0, 0]:
            raise EncodeError("header and question exceed limit")
        an = an[:keep[0]]
        ns = ns[:keep[1]]
        ar = ar[:keep[2]]
        truncated = True


def encode_response(query: bytes, model: dict) -> bytes:
    """把查询报文与应答模型编码为确定性权威应答报文（RCODE=0）。"""
    return _encode_response(query, model, _RCODE_NOERROR)


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
