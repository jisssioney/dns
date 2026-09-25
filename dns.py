"""DNS 问题报文解码与确定性权威应答编码（仅标准库、离线）。

公开接口：
- MessageError: 报文格式错误（ValueError 子类）。
- ZoneError: zone 模型非法（ValueError 子类）。
- RecordError: 记录模型不符合编码要求（ValueError 子类）。
- EncodeError: 应答无法在给定限制内编码（ValueError 子类）。
- decode_query(data: bytes) -> dict: 解码 DNS 查询报文。
- encode_response(query: bytes, model: dict) -> bytes: 编码权威应答报文。
- answer(query: bytes, zone: dict, limit: int = 512) -> bytes: 按 zone 应答查询。

命令行：python dns.py decode HEX
"""

from bisect import bisect_right
import json
import sys


class MessageError(ValueError):
    """DNS 报文无法解码。"""


class ZoneError(ValueError):
    """zone 模型非法。"""


class RecordError(ValueError):
    """记录模型不符合应答编码要求。"""


class EncodeError(ValueError):
    """应答报文无法在给定限制内编码。"""


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
_ZONE_KEYS = ["origin", "records"]
_RR_KEYS = ["name", "type", "class", "ttl", "rdata"]
_MAX_LABEL_LEN = 63
_MAX_RDATA_LEN = 65535
_MAX_TTL = 4294967295
_MIN_LIMIT = 12
_MAX_LIMIT = 65535
_MAX_POINTER_TARGET = 0x3FFF
_MAX_SECTION_RECORDS = 65535
_FLAGS_RESPONSE = 0x8400  # QR | AA
_FLAGS_KEPT = 0x7910  # opcode | RD | CD
_FLAG_TC = 0x0200
_TYPE_SOA = 6
_RCODE_REFUSED = 5
_RCODE_NXDOMAIN = 3


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


def _normalize_name(name, wildcard=False):
    """按解码规则把 name 规范为小写绝对名，返回标签列表（根为 []）。

    wildcard 为真时仅允许最左标签为 "*"（zone 记录 owner 用）。
    """
    if not isinstance(name, str):
        raise TypeError("name must be str")
    if not name.endswith("."):
        raise RecordError("name not absolute")
    parts = name[:-1].split(".") if name != "." else []
    labels = []
    wire_len = 1  # 根终止符占 1 字节
    for index, part in enumerate(parts):
        if wildcard and index == 0 and part == "*":
            label = "*"
        else:
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


def _check_int(value, field):
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(field + " must be int")


def _validate_rr(rr, wildcard=False):
    """校验单条 RR，返回 (labels, type, class, ttl, rdata)。

    wildcard 为真时允许 owner 最左标签为 "*"（仅 zone 记录）。
    """
    if not isinstance(rr, dict):
        raise TypeError("rr must be dict")
    if list(rr.keys()) != _RR_KEYS:
        raise RecordError("rr keys must be name,type,class,ttl,rdata")
    labels = _normalize_name(rr["name"], wildcard)
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
    """校验 zone，返回 (origin 标签列表, 规范化 RR 列表, 统一 class)。"""
    if not isinstance(zone, dict):
        raise TypeError("zone must be dict")
    if list(zone.keys()) != _ZONE_KEYS:
        raise ZoneError("zone keys must be origin,records")
    try:
        origin = _normalize_name(zone["origin"])
    except RecordError as exc:
        raise ZoneError(str(exc)) from None
    records = zone["records"]
    if not isinstance(records, list):
        raise TypeError("records must be list")
    rrs = [_validate_rr(rr, wildcard=True) for rr in records]
    if not rrs:
        raise ZoneError("zone must contain a SOA record")
    rrclass = rrs[0][2]
    if any(rr[2] != rrclass for rr in rrs):
        raise ZoneError("record class not uniform")
    origin_soa = [rr for rr in rrs if rr[0] == origin and rr[1] == _TYPE_SOA]
    if len(origin_soa) != 1:
        raise ZoneError("origin must have exactly one SOA record")
    for labels, _rrtype, _cls, _ttl, _rdata in rrs:
        if labels and labels[0] == "*":
            # 通配 owner：后缀须在 origin 内（含等于 origin）。
            suffix = labels[1:]
            if (len(suffix) < len(origin)
                    or suffix[len(suffix) - len(origin):] != origin):
                raise RecordError("wildcard suffix not within origin")
        elif (len(labels) < len(origin)
                or labels[len(labels) - len(origin):] != origin):
            raise ZoneError("owner not within origin")
    return origin, rrs, rrclass


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


def _build_message(msg, an, ns, ar, rcode):
    """一次性编码完整报文，返回 (out, body_base, 各区段 RR 结束偏移, flags)。

    尾删只保留报文前缀：压缩指针只指向更早写入的名字，保留的前缀
    自身即合法报文，故按结束偏移切片即可，无需反复重新编码。
    """
    flags = _FLAGS_RESPONSE | (msg["flags"] & _FLAGS_KEPT) | rcode
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
    body_base = len(out)
    section_ends = []
    for section in (an, ns, ar):
        ends = []
        for labels, rrtype, rrclass, ttl, rdata in section:
            _write_name(out, labels, offsets)
            out += rrtype.to_bytes(2, "big")
            out += rrclass.to_bytes(2, "big")
            out += ttl.to_bytes(4, "big")
            out += len(rdata).to_bytes(2, "big")
            out += rdata
            ends.append(len(out))
        section_ends.append(ends)
    return out, body_base, section_ends, flags


def encode_response(query: bytes, model: dict) -> bytes:
    """把查询报文与应答模型编码为确定性权威应答报文（RCODE 恒为 0）。"""
    return _encode_response(query, model, 0)


def _encode_response(query, model, rcode):
    """按给定 RCODE 把查询报文与应答模型编码为确定性权威应答报文。"""
    if not isinstance(query, bytes):
        raise TypeError("query must be bytes")
    _check_int(rcode, "rcode")
    if not 0 <= rcode <= 0xF:
        raise EncodeError("rcode out of range")
    an, ns, ar, limit = _validate_model(model)
    msg = decode_query(query)
    if msg["flags"] & 0x8000:
        raise EncodeError("query has QR set")
    if not _MIN_LIMIT <= limit <= _MAX_LIMIT:
        raise EncodeError("limit out of range")
    truncated = False
    # 区段计数为 16 位：超过 65535 条时按 ar、ns、an 尾删整条并置 TC，
    # 不得让计数溢出。
    for section in (ar, ns, an):
        if len(section) > _MAX_SECTION_RECORDS:
            del section[_MAX_SECTION_RECORDS:]
            truncated = True
    out, body_base, (an_ends, ns_ends, ar_ends), flags = _build_message(
        msg, an, ns, ar, rcode)
    na, nn, nr = len(an), len(ns), len(ar)
    total_end = ar_ends[-1] if ar_ends else (
        ns_ends[-1] if ns_ends else (an_ends[-1] if an_ends else body_base))
    if total_end > limit:
        # 超长：先尾删 ar，ar 清空仍超长再尾删 ns，最后尾删 an。
        truncated = True
        nr = bisect_right(ar_ends, limit)
        if nr == 0:
            nn = bisect_right(ns_ends, limit)
            if nn == 0:
                na = bisect_right(an_ends, limit)
                if na == 0 and body_base > limit:
                    raise EncodeError("header and question exceed limit")
    if nr:
        end = ar_ends[nr - 1]
    elif nn:
        end = ns_ends[nn - 1]
    elif na:
        end = an_ends[na - 1]
    else:
        end = body_base
    result = bytearray(out[:end])
    result[6:8] = na.to_bytes(2, "big")
    result[8:10] = nn.to_bytes(2, "big")
    result[10:12] = nr.to_bytes(2, "big")
    if truncated:
        result[2:4] = (flags | _FLAG_TC).to_bytes(2, "big")
    return bytes(result)


def _rr_to_model(rr):
    """把规范化 RR 元组还原为键序固定的模型 dict。"""
    labels, rrtype, rrclass, ttl, rdata = rr
    name = ".".join(labels) + "." if labels else "."
    return {"name": name, "type": rrtype, "class": rrclass,
            "ttl": ttl, "rdata": rdata}


def answer(query: bytes, zone: dict, limit: int = 512) -> bytes:
    """按 zone 对查询报文给出确定性权威应答（含最左标签 "*" 通配）。"""
    msg = decode_query(query)  # MessageError/TypeError 原样传播
    _check_int(limit, "limit")
    questions = msg["questions"]
    if (msg["flags"] & 0x8000 or len(questions) != 1
            or not _MIN_LIMIT <= limit <= _MAX_LIMIT):
        raise EncodeError("query or limit not answerable")
    origin, records, zone_class = _validate_zone(zone)
    question = questions[0]
    qlabels = _normalize_name(question["name"])
    qtype = question["type"]
    origin_soa = [rr for rr in records
                  if rr[0] == origin and rr[1] == _TYPE_SOA]
    an = []
    ns = []
    if question["class"] != zone_class:
        rcode = _RCODE_REFUSED  # 问题 class 与 zone 不同：三段为空
    elif (len(qlabels) < len(origin)
          or qlabels[len(qlabels) - len(origin):] != origin):
        rcode = _RCODE_NXDOMAIN  # 查询名在 origin 之外
        ns = origin_soa
    else:
        # 节点集合：origin、各记录 owner 及其间空非终端。
        nodes = {tuple(origin)}
        for labels, _t, _c, _ttl, _rd in records:
            for i in range(len(labels) - len(origin) + 1):
                nodes.add(tuple(labels[i:]))
        if tuple(qlabels) in nodes:
            matched = [rr for rr in records
                       if rr[0] == qlabels and rr[1] == qtype]
            if matched:
                rcode = 0  # 名称与 type 精确命中：应答入 an，ns 为空
                an = matched
            else:
                rcode = 0  # NODATA：节点存在但无该 TYPE，不回退通配
                ns = origin_soa
        else:
            # 取最长既存后缀，只检查 "*."+该后缀。
            i = 1
            while tuple(qlabels[i:]) not in nodes:
                i += 1
            wlabels = ["*"] + qlabels[i:]
            if tuple(wlabels) in nodes:
                matched = [rr for rr in records
                           if rr[0] == wlabels and rr[1] == qtype]
                if matched:
                    rcode = 0  # 通配命中：owner 换成查询名，其余字段不变
                    an = [(qlabels, rr[1], rr[2], rr[3], rr[4])
                          for rr in matched]
                else:
                    rcode = 0  # 通配节点存在但无该 TYPE：NODATA
                    ns = origin_soa
            else:
                rcode = _RCODE_NXDOMAIN
                ns = origin_soa
    model = {
        "an": [_rr_to_model(rr) for rr in an],
        "ns": [_rr_to_model(rr) for rr in ns],
        "ar": [],
        "limit": limit,
    }
    return _encode_response(query, model, rcode)


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
