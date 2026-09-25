"""DNS 问题报文解码与确定性权威应答编码（仅标准库、离线）。

公开接口：
- MessageError: 报文格式错误（ValueError 子类）。
- ZoneError: zone 模型非法（ValueError 子类）。
- RecordError: 记录模型不符合编码要求（ValueError 子类）。
- EncodeError: 应答无法在给定限制内编码（ValueError 子类）。
- CNAMEError: CNAME 链出现名称重复或超过 16 跳（ValueError 子类）。
- CacheError: 缓存时钟非法（now 为负或早于上次成功值，ValueError 子类）。
- decode_query(data: bytes) -> dict: 解码 DNS 查询报文。
- encode_response(query: bytes, model: dict) -> bytes: 编码权威应答报文。
- answer(query: bytes, zone: dict, limit: int = 512) -> bytes: 按 zone 应答查询。
- PositiveCache(zone: dict): 容量 256 的正缓存，
  resolve(query: bytes, now: int, limit: int = 512) -> (bytes, bool)。

命令行：python dns.py decode HEX
"""

from bisect import bisect_right
import copy
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


class CNAMEError(ValueError):
    """CNAME 链无法确定：有效名称重复或需加入第 17 条 CNAME。"""


class CacheError(ValueError):
    """缓存时钟非法：now 为负或早于上次成功解析的时刻。"""


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
_TYPE_CNAME = 5
_MAX_CNAME_CHAIN = 16
_RCODE_REFUSED = 5
_RCODE_NXDOMAIN = 3
_CACHE_CAPACITY = 256


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


def _normalize_owner_name(name):
    """规范 zone 记录 owner，允许最左标签恰为 "*" 的通配名。

    返回标签列表；通配与否可由 labels[0] == "*" 判别。
    """
    if not isinstance(name, str):
        raise TypeError("name must be str")
    if not name.endswith("."):
        raise RecordError("name not absolute")
    parts = name[:-1].split(".") if name != "." else []
    labels = []
    wire_len = 1  # 根终止符占 1 字节
    for index, part in enumerate(parts):
        label = part.lower()
        if not 1 <= len(label) <= _MAX_LABEL_LEN:
            raise RecordError("bad label length")
        if index == 0 and label == "*":
            pass  # 唯一合法的通配形态：最左标签为单字符 "*"
        elif "*" in label or any(ch not in _LABEL_CHARS for ch in label):
            raise RecordError("invalid label character")
        labels.append(label)
        wire_len += len(label) + 1
        if wire_len > _MAX_NAME_WIRE_LEN:
            raise RecordError("name too long")
    return labels


def _check_int(value, field):
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(field + " must be int")


def _validate_rr(rr, allow_wildcard=False):
    """校验单条 RR，返回 (labels, type, class, ttl, rdata)。"""
    if not isinstance(rr, dict):
        raise TypeError("rr must be dict")
    if list(rr.keys()) != _RR_KEYS:
        raise RecordError("rr keys must be name,type,class,ttl,rdata")
    if allow_wildcard:
        labels = _normalize_owner_name(rr["name"])
    else:
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


def _decode_cname_target(rdata):
    """把 CNAME rdata 按未压缩绝对名线格式解码为小写标签列表。

    标签 1–63 字节、0 结尾、总长 ≤255；禁止压缩指针、尾随内容与非法字符。
    """
    if len(rdata) > _MAX_NAME_WIRE_LEN:
        raise RecordError("cname rdata too long")
    labels = []
    pos = 0
    while True:
        if pos >= len(rdata):
            raise RecordError("cname rdata not terminated")
        length = rdata[pos]
        if length == 0:
            pos += 1
            break
        if length > _MAX_LABEL_LEN:
            raise RecordError("cname rdata bad label length")
        pos += 1
        if pos + length > len(rdata):
            raise RecordError("cname rdata truncated")
        try:
            label = rdata[pos:pos + length].decode("ascii")
        except UnicodeDecodeError:
            raise RecordError("cname rdata label not ascii") from None
        if any(ch not in _LABEL_CHARS for ch in label):
            raise RecordError("cname rdata invalid label character")
        labels.append(label.lower())
        pos += length
    if pos != len(rdata):
        raise RecordError("cname rdata trailing bytes")
    return labels


def _encode_cname_target(labels):
    """把标签列表重编码为未压缩绝对名线格式。"""
    out = bytearray()
    for label in labels:
        out.append(len(label))
        out.extend(label.encode("ascii"))
    out.append(0)
    return bytes(out)


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
    rrs = []
    for rr in records:
        labels, rrtype, rrclass, ttl, rdata = _validate_rr(
            rr, allow_wildcard=True)
        if rrtype == _TYPE_CNAME:
            # 目标规范成小写绝对名，rdata 据此重编码。
            rdata = _encode_cname_target(_decode_cname_target(rdata))
        rrs.append((labels, rrtype, rrclass, ttl, rdata))
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
            suffix = labels[1:]
            if (len(suffix) < len(origin)
                    or suffix[len(suffix) - len(origin):] != origin):
                raise RecordError("wildcard suffix not within origin")
        elif (len(labels) < len(origin)
                or labels[len(labels) - len(origin):] != origin):
            raise ZoneError("owner not within origin")
    owner_types = {}
    for labels, rrtype, _cls, _ttl, _rdata in rrs:
        owner_types.setdefault(tuple(labels), []).append(rrtype)
    for types in owner_types.values():
        if _TYPE_CNAME in types and len(types) != 1:
            raise ZoneError("cname owner must hold exactly one cname record")
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


def _encode_response(query, model, rcode):
    """把查询报文与应答模型编码为确定性权威应答报文（rcode 由内部指定）。"""
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


def encode_response(query: bytes, model: dict) -> bytes:
    """把查询报文与应答模型编码为确定性权威应答报文（RCODE 恒为 0）。"""
    return _encode_response(query, model, 0)


def _rr_to_model(rr):
    """把规范化 RR 元组还原为键序固定的模型 dict。"""
    labels, rrtype, rrclass, ttl, rdata = rr
    name = ".".join(labels) + "." if labels else "."
    return {"name": name, "type": rrtype, "class": rrclass,
            "ttl": ttl, "rdata": rdata}


def _hop(records, nodes, origin, current, qtype):
    """单跳查找 current 的 qtype 记录，返回 (kind, rrs)。

    kind 为 "answer"（rrs 为命中记录，通配 owner 已合成为 current）、
    "cname"（rrs 为合成后的单条 CNAME，仅 qtype≠5 时出现）、
    "nodata"（节点或通配存在但无该类型）或 "nxdomain"。
    """
    if tuple(current) in nodes:
        # 同名节点存在（含空非终端）：不回退通配。
        if qtype != _TYPE_CNAME:
            for rr in records:
                if rr[0] == current and rr[1] == _TYPE_CNAME:
                    return "cname", rr
        matched = [rr for rr in records
                   if rr[0] == current and rr[1] == qtype]
        if matched:
            return "answer", matched[:1] if qtype == _TYPE_CNAME else matched
        return "nodata", None
    # 节点不存在：取最长既存后缀，只检查 "*."+该后缀。
    encloser = None
    for i in range(1, len(current) - len(origin) + 1):
        if tuple(current[i:]) in nodes:
            encloser = current[i:]
            break
    wildcard = ["*"] + encloser
    if qtype != _TYPE_CNAME:
        for rr in records:
            if rr[0] == wildcard and rr[1] == _TYPE_CNAME:
                return "cname", (list(current), rr[1], rr[2], rr[3], rr[4])
    matched = [rr for rr in records
               if rr[0] == wildcard and rr[1] == qtype]
    if matched:
        if qtype == _TYPE_CNAME:
            matched = matched[:1]
        return "answer", [(list(current), rr[1], rr[2], rr[3], rr[4])
                          for rr in matched]
    if any(rr[0] == wildcard for rr in records):
        return "nodata", None
    return "nxdomain", None


def _resolve_chain(records, nodes, origin, qlabels, qtype):
    """在 origin 内解析（qtype≠5 时跟随 CNAME 链），返回 (rcode, an, ns)。"""
    soa = [rr for rr in records if rr[0] == origin and rr[1] == _TYPE_SOA]
    if qtype == _TYPE_CNAME:
        kind, rrs = _hop(records, nodes, origin, qlabels, qtype)
        if kind == "answer":
            return 0, rrs, []
        if kind == "nodata":
            return 0, [], soa
        return _RCODE_NXDOMAIN, [], soa
    an = []
    seen = {tuple(qlabels)}
    current = list(qlabels)
    while True:
        kind, rrs = _hop(records, nodes, origin, current, qtype)
        if kind == "answer":
            return 0, an + rrs, []
        if kind == "nodata":
            return 0, an, soa
        if kind == "nxdomain":
            return _RCODE_NXDOMAIN, an, soa
        # 命中 CNAME：先入链，再查目标；第 17 条或名称重复即失败。
        if len(an) >= _MAX_CNAME_CHAIN:
            raise CNAMEError("cname chain too long")
        an.append(rrs)
        target = _decode_cname_target(rrs[4])
        if tuple(target) in seen:
            raise CNAMEError("cname chain loop")
        seen.add(tuple(target))
        if (len(target) < len(origin)
                or target[len(target) - len(origin):] != origin):
            return 0, an, []  # 目标在 origin 外：返回积累链，ns 为空
        current = target


def _zone_nodes(records, origin):
    """节点集：origin、各记录 owner（含通配 owner）及其间的空非终端。"""
    nodes = {tuple(origin)}
    for labels, _rrtype, _cls, _ttl, _rdata in records:
        for i in range(len(labels) - len(origin)):
            nodes.add(tuple(labels[i:]))
    return nodes


def _resolve_question(records, nodes, origin, zone_class, question):
    """按 zone 对单个问题求 (rcode, an, ns)，an/ns 为规范化 RR 元组列表。"""
    qlabels = _normalize_name(question["name"])
    qtype = question["type"]
    if question["class"] != zone_class:
        return _RCODE_REFUSED, [], []  # 问题 class 与 zone 不同：三段为空
    if (len(qlabels) < len(origin)
            or qlabels[len(qlabels) - len(origin):] != origin):
        # 查询名在 origin 之外
        ns = [rr for rr in records
              if rr[0] == origin and rr[1] == _TYPE_SOA]
        return _RCODE_NXDOMAIN, [], ns
    return _resolve_chain(records, nodes, origin, qlabels, qtype)


def answer(query: bytes, zone: dict, limit: int = 512) -> bytes:
    """按 zone 对查询报文给出确定性权威应答（支持最左 "*" 通配与 CNAME 链）。"""
    msg = decode_query(query)  # MessageError/TypeError 原样传播
    _check_int(limit, "limit")
    questions = msg["questions"]
    if (msg["flags"] & 0x8000 or len(questions) != 1
            or not _MIN_LIMIT <= limit <= _MAX_LIMIT):
        raise EncodeError("query or limit not answerable")
    origin, records, zone_class = _validate_zone(zone)
    rcode, an, ns = _resolve_question(
        records, _zone_nodes(records, origin), origin, zone_class,
        questions[0])
    model = {
        "an": [_rr_to_model(rr) for rr in an],
        "ns": [_rr_to_model(rr) for rr in ns],
        "ar": [],
        "limit": limit,
    }
    return _encode_response(query, model, rcode)


class PositiveCache:
    """容量 256 的正缓存：仅缓存 RCODE=0、ns 为空、an 非空且 TTL 均正的应答。

    键为 (小写绝对 qname, qtype, qclass) 三元组，不含 ID、flags、limit。
    命中时按经过时间递减各 RR 的 TTL 并以本次 query、limit 重编码；
    到期删除后按未命中刷新；满时淘汰最早插入者，命中不重排。
    时钟由调用方显式驱动：同状态、输入、now 的应答逐字节一致。
    """

    def __init__(self, zone: dict):
        self._zone = copy.deepcopy(zone)  # 校验异常与 answer 一致
        origin, records, zone_class = _validate_zone(self._zone)
        self._origin = origin
        self._records = records
        self._zone_class = zone_class
        self._nodes = _zone_nodes(records, origin)
        self._entries = {}  # key -> (inserted, rrs)，dict 保持插入序
        self._last_now = None

    def resolve(self, query: bytes, now: int, limit: int = 512):
        """解析查询，返回 (应答报文, 是否命中缓存)；失败不改变条目与时间状态。"""
        msg = decode_query(query)  # query、limit 的异常沿用 answer
        _check_int(limit, "limit")
        questions = msg["questions"]
        if (msg["flags"] & 0x8000 or len(questions) != 1
                or not _MIN_LIMIT <= limit <= _MAX_LIMIT):
            raise EncodeError("query or limit not answerable")
        _check_int(now, "now")
        if now < 0:
            raise CacheError("now must be non-negative")
        if self._last_now is not None and now < self._last_now:
            raise CacheError("now earlier than last successful resolve")
        question = questions[0]
        key = (question["name"], question["type"], question["class"])
        entry = self._entries.get(key)
        if entry is not None:
            inserted, rrs = entry
            elapsed = now - inserted
            if elapsed < min(rr[3] for rr in rrs):
                an = [(labels, rrtype, rrclass, ttl - elapsed, rdata)
                      for labels, rrtype, rrclass, ttl, rdata in rrs]
                response = _encode_response(query, {
                    "an": [_rr_to_model(rr) for rr in an],
                    "ns": [],
                    "ar": [],
                    "limit": limit,
                }, 0)
                self._last_now = now
                return response, True
            del self._entries[key]  # 到期删除后按未命中刷新
        rcode, an, ns = _resolve_question(
            self._records, self._nodes, self._origin, self._zone_class,
            question)
        if rcode == 0 and not ns and an and all(rr[3] > 0 for rr in an):
            if len(self._entries) >= _CACHE_CAPACITY:
                del self._entries[next(iter(self._entries))]
            self._entries[key] = (now, list(an))
        response = _encode_response(query, {
            "an": [_rr_to_model(rr) for rr in an],
            "ns": [_rr_to_model(rr) for rr in ns],
            "ar": [],
            "limit": limit,
        }, rcode)
        self._last_now = now
        return response, False


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
