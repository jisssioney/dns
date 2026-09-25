"""DNS 问题报文解码与确定性权威应答编码（仅标准库、离线）。

公开接口：
- MessageError: 报文格式错误（ValueError 子类）。
- ZoneError: zone 模型非法（ValueError 子类）。
- RecordError: 记录模型不符合编码要求（ValueError 子类）。
- EncodeError: 应答无法在给定限制内编码（ValueError 子类）。
- CNAMEError: CNAME 链出现名称重复或超过 16 跳（ValueError 子类）。
- CacheError: 缓存时钟非单调等缓存语义错误（ValueError 子类）。
- decode_query(data: bytes) -> dict: 解码 DNS 查询报文。
- encode_response(query: bytes, model: dict) -> bytes: 编码权威应答报文。
- answer(query: bytes, zone: dict, limit: int = 512) -> bytes: 按 zone 应答查询。
- PositiveCache(zone): 容量 256 的正/负答案缓存，resolve(query, now, limit=512)
  返回 (应答报文, 是否命中)。
- UpstreamError: 上游转发未获得可用应答（RuntimeError 子类）。
- UpstreamTimeout: 上游转发全部超时（UpstreamError 子类）。
- forward(query, plan, now, timeout=5): 按 plan 顺序模拟上游转发，
  成功返回 (应答报文, 上游名, 结束时刻)。
- Resolver(zone, plan, timeout=5): 权威缓存与上游转发组合的解析器，
  resolve(query, now, limit=512) 返回 (应答报文, 来源, 结束时刻, 是否命中缓存)；
  resolve_recursive(query, levels, now, limit=512) 按 1–16 层转介计划
  递归解析域外查询，返回 (应答报文, 来源, 结束时刻, 是否命中递归缓存)；
  stats() 返回只读的键序 h,m,x,u,c,l 紧凑 ASCII JSON 串（末尾换行）。

命令行：python dns.py decode HEX
"""

from bisect import bisect_right
from collections import deque
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
    """缓存时钟非单调或缓存语义不满足。"""


class UpstreamError(RuntimeError):
    """上游转发未获得可用应答。"""


class UpstreamTimeout(UpstreamError):
    """上游转发全部尝试均超时。"""


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
_MAX_PLAN_ITEMS = 16
_PLAN_EVENTS_USED = 2
_MIN_TIMEOUT = 1
_MAX_TIMEOUT = 60
_MAX_REPLY_LEN = 65535
_FLAG_QR = 0x8000
_MAX_RECURSION_LEVELS = 16
_RECURSIVE_RCODES = {0: 0, 1: 0, 2: _RCODE_NXDOMAIN, 3: 0}


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


def _read_soa_name(rdata, pos):
    """按 CNAME 目标规范解码 rdata pos 处的未压缩绝对名，返回下一偏移。

    任何格式问题都返回 None，不抛异常。
    """
    wire_len = 1  # 根终止符占 1 字节
    while True:
        if pos >= len(rdata):
            return None
        length = rdata[pos]
        if length == 0:
            return pos + 1
        if length > _MAX_LABEL_LEN:  # 含压缩指针形态
            return None
        pos += 1
        if pos + length > len(rdata):
            return None
        try:
            label = rdata[pos:pos + length].decode("ascii")
        except UnicodeDecodeError:
            return None
        if any(ch not in _LABEL_CHARS for ch in label):
            return None
        wire_len += length + 1
        if wire_len > _MAX_NAME_WIRE_LEN:
            return None
        pos += length


def _parse_soa_minimum(rdata):
    """解析 SOA rdata 的 minimum 字段（第五个网络序 uint32）。

    rdata 须完整为两个未压缩绝对域名及五个网络序 uint32；
    格式不符返回 None，不抛异常。
    """
    pos = 0
    for _ in range(2):
        pos = _read_soa_name(rdata, pos)
        if pos is None:
            return None
    if len(rdata) - pos != 20:
        return None
    return int.from_bytes(rdata[pos + 16:pos + 20], "big")


def _negative_cache_entry(key, rcode, an, ns, now):
    """完整计划可负缓存时返回 (负缓存键, 条目)，否则返回 None。

    规则与 PositiveCache 相同，但 ns 中唯一 SOA 的 owner 不受本地 origin
    约束（递归终态的 SOA 可能属于域外权威区）；键仍按本次查询构造。
    """
    if an or rcode not in (0, _RCODE_NXDOMAIN):
        return None
    if len(ns) != 1 or ns[0][1] != _TYPE_SOA:
        return None
    soa = ns[0]
    minimum = _parse_soa_minimum(soa[4])
    if minimum is None:
        return None
    neg_ttl = min(soa[3], minimum)
    if neg_ttl == 0:
        return None
    if rcode == _RCODE_NXDOMAIN:
        neg_key = ("nxdomain", key[0], key[2])  # 匹配任意 qtype
    else:
        neg_key = ("nodata",) + key
    return neg_key, (now, rcode, soa, neg_ttl)


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


def _answer_plan(msg, origin, records, zone_class):
    """answer 的完整（未截断）应答计划，返回 (rcode, an, ns)。

    msg 为已解码且通过可应答性检查的单问题查询；zone 已校验，
    RR 均为规范化元组。
    """
    question = msg["questions"][0]
    qlabels = _normalize_name(question["name"])
    qtype = question["type"]
    an = []
    ns = []
    if question["class"] != zone_class:
        rcode = _RCODE_REFUSED  # 问题 class 与 zone 不同：三段为空
    elif (len(qlabels) < len(origin)
            or qlabels[len(qlabels) - len(origin):] != origin):
        rcode = _RCODE_NXDOMAIN  # 查询名在 origin 之外
        ns = [rr for rr in records
              if rr[0] == origin and rr[1] == _TYPE_SOA]
    else:
        # 节点集：origin、各记录 owner（含通配 owner）及其间的空非终端。
        nodes = {tuple(origin)}
        for labels, _rrtype, _cls, _ttl, _rdata in records:
            for i in range(len(labels) - len(origin)):
                nodes.add(tuple(labels[i:]))
        rcode, an, ns = _resolve_chain(records, nodes, origin, qlabels, qtype)
    return rcode, an, ns


def _encode_plan(query, rcode, an, ns, limit):
    """把完整应答计划编码为权威应答报文。"""
    model = {
        "an": [_rr_to_model(rr) for rr in an],
        "ns": [_rr_to_model(rr) for rr in ns],
        "ar": [],
        "limit": limit,
    }
    return _encode_response(query, model, rcode)


def answer(query: bytes, zone: dict, limit: int = 512) -> bytes:
    """按 zone 对查询报文给出确定性权威应答（支持最左 "*" 通配与 CNAME 链）。"""
    msg = decode_query(query)  # MessageError/TypeError 原样传播
    _check_int(limit, "limit")
    questions = msg["questions"]
    if (msg["flags"] & 0x8000 or len(questions) != 1
            or not _MIN_LIMIT <= limit <= _MAX_LIMIT):
        raise EncodeError("query or limit not answerable")
    origin, records, zone_class = _validate_zone(zone)
    rcode, an, ns = _answer_plan(msg, origin, records, zone_class)
    return _encode_plan(query, rcode, an, ns, limit)


class PositiveCache:
    """容量 256 的正/负答案缓存（FIFO 淘汰，命中不重排）。

    正缓存键为 (小写绝对 qname, qtype, qclass)，与 ID、flags、limit 无关。
    仅缓存 RCODE=0、ns 空、an 非空且各原始 TTL 均为正的完整有序应答；
    条目保存插入时刻与原始 RR，输出 TTL 随经过时间递减，到期即删除。

    负缓存仅收完整计划所得且 an 为空的 NXDOMAIN（RCODE=3，键为小写绝对
    (qname, qclass)，匹配任意 qtype）与 NODATA（RCODE=0，键为
    (qname, qtype, qclass)），且 ns 恰为 origin 唯一 SOA；SOA rdata 须
    完整为两个未压缩绝对域名及五个网络序 uint32，负 TTL 为
    min(SOA ttl, 第五个 uint32)，格式错或负 TTL 为 0 则不缓存。
    负命中时 RCODE 不变，an/ar 为空，ns 仅该 SOA 且 ttl 随经过时间递减。

    查找顺序为正缓存、NODATA、NXDOMAIN；正负条目共用容量与同一 FIFO。
    任何失败（含编码失败）都不改变条目与时钟状态。
    """

    def __init__(self, zone: dict):
        # 深拷贝后按 answer 规则校验：外部对 zone 的后续改动与缓存隔离，
        # 校验异常与 answer 完全一致。
        zone = copy.deepcopy(zone)
        self._origin, self._records, self._zone_class = _validate_zone(zone)
        self._entries = {}  # 正缓存键 -> (插入时刻, 规范化 an)
        self._neg_entries = {}  # 负缓存键 -> (插入时刻, rcode, 规范化 SOA, 负 TTL)
        self._order = deque()  # (类别, 键) 插入次序；与两个字典的键集合始终一致
        self._last_now = None  # 上次成功 resolve 的时钟值

    def _negative_entry(self, key, rcode, an, ns, now):
        """完整计划可负缓存时返回 (负缓存键, 条目)，否则返回 None。"""
        if an or rcode not in (0, _RCODE_NXDOMAIN):
            return None
        if (len(ns) != 1 or ns[0][0] != self._origin
                or ns[0][1] != _TYPE_SOA):
            return None
        soa = ns[0]
        minimum = _parse_soa_minimum(soa[4])
        if minimum is None:
            return None
        neg_ttl = min(soa[3], minimum)
        if neg_ttl == 0:
            return None
        if rcode == _RCODE_NXDOMAIN:
            neg_key = ("nxdomain", key[0], key[2])  # 匹配任意 qtype
        else:
            neg_key = ("nodata",) + key
        return neg_key, (now, rcode, soa, neg_ttl)

    def resolve(self, query: bytes, now: int,
                limit: int = 512) -> tuple[bytes, bool]:
        if not isinstance(now, int) or isinstance(now, bool):
            raise TypeError("now must be int")
        if now < 0 or (self._last_now is not None and now < self._last_now):
            raise CacheError("now must be non-negative and monotonic")
        # query、limit 的异常沿用 answer。
        msg = decode_query(query)
        _check_int(limit, "limit")
        if (msg["flags"] & 0x8000 or len(msg["questions"]) != 1
                or not _MIN_LIMIT <= limit <= _MAX_LIMIT):
            raise EncodeError("query or limit not answerable")
        question = msg["questions"][0]
        key = (question["name"], question["type"], question["class"])
        expired = None  # 到期条目在 _order 中的标记键，待编码成功后清理
        entry = self._entries.get(key)
        if entry is not None:
            inserted, an = entry
            elapsed = now - inserted
            min_ttl = min(rr[3] for rr in an)
            if elapsed < min_ttl:
                aged = [(labels, rrtype, rrclass, ttl - elapsed, rdata)
                        for labels, rrtype, rrclass, ttl, rdata in an]
                # 用本次 ID、flags、问题段、limit 重编码；截断不改条目，
                # 命中也不改变插入次序。
                response = _encode_plan(query, 0, aged, [], limit)
                self._last_now = now
                return response, True
            # 到期：先记下，待新应答编码成功后再清理，保证失败不改状态。
            expired = ("pos", key)
        else:
            # 正缓存未中：NODATA 先于 NXDOMAIN 查找。
            neg_key = ("nodata",) + key
            neg = self._neg_entries.get(neg_key)
            if neg is None:
                neg_key = ("nxdomain", key[0], key[2])
                neg = self._neg_entries.get(neg_key)
            if neg is not None:
                inserted, rcode, soa, neg_ttl = neg
                elapsed = now - inserted
                if elapsed < neg_ttl:
                    aged_soa = (soa[0], soa[1], soa[2],
                                neg_ttl - elapsed, soa[4])
                    # 用本次 ID、flags、问题段、limit 重编码；RCODE 不变，
                    # an/ar 为空，ns 仅 SOA；截断不改条目与插入次序。
                    response = _encode_plan(query, rcode, [], [aged_soa], limit)
                    self._last_now = now
                    return response, True
                expired = ("neg", neg_key)
        # 未命中（含到期）：先按 answer 语义生成未截断的完整有序应答。
        rcode, an, ns = _answer_plan(
            msg, self._origin, self._records, self._zone_class)
        # 先编码成功再落条目，保证编码失败不改变任何状态。
        response = _encode_plan(query, rcode, an, ns, limit)
        if expired is not None:
            tag, ekey = expired
            del (self._entries if tag == "pos" else self._neg_entries)[ekey]
            self._order.remove(expired)  # 到期删除后按未命中刷新
        if rcode == 0 and not ns and an and all(rr[3] > 0 for rr in an):
            self._entries[key] = (now, an)
            self._order.append(("pos", key))
        else:
            negative = self._negative_entry(key, rcode, an, ns, now)
            if negative is not None:
                neg_key, neg_entry = negative
                self._neg_entries[neg_key] = neg_entry
                self._order.append(("neg", neg_key))
        if len(self._order) > _CACHE_CAPACITY:
            tag, oldest = self._order.popleft()  # 满时淘汰最早插入者
            del (self._entries if tag == "pos" else self._neg_entries)[oldest]
        self._last_now = now
        return response, False


def _check_non_negative_int(value, field):
    _check_int(value, field)
    if value < 0:
        raise ValueError(field + " must be non-negative")


def _validate_plan(plan):
    """校验转发计划，返回规范化后的 [(name, [(delay, reply), ...]), ...]。"""
    if not isinstance(plan, list):
        raise TypeError("plan must be list")
    if not 1 <= len(plan) <= _MAX_PLAN_ITEMS:
        raise ValueError("plan must contain 1..16 items")
    items = []
    for item in plan:
        if not isinstance(item, tuple):
            raise TypeError("plan item must be tuple")
        if len(item) != 2:
            raise ValueError("plan item must be (name, events)")
        name, events = item
        if not isinstance(name, str):
            raise TypeError("name must be str")
        if not name:
            raise ValueError("name must be non-empty")
        if not isinstance(events, list):
            raise TypeError("events must be list")
        checked = []
        for event in events:
            if not isinstance(event, tuple):
                raise TypeError("event must be tuple")
            if len(event) != 2:
                raise ValueError("event must be (delay, reply)")
            delay, reply = event
            _check_non_negative_int(delay, "delay")
            if reply is not None and not isinstance(reply, bytes):
                raise TypeError("reply must be bytes or None")
            checked.append((delay, reply))
        items.append((name, checked))
    return items


def _reply_question_end(reply, qdcount):
    """按 qdcount 从偏移 12 起界定问题段结束位置；无法界定返回 None。"""
    pos = _MIN_MESSAGE_LEN
    for _ in range(qdcount):
        while True:
            if pos >= len(reply):
                return None
            length = reply[pos]
            kind = length & 0xC0
            if kind == 0xC0:
                if pos + 1 >= len(reply):
                    return None
                pos += 2
                break
            if kind != 0x00:
                return None
            pos += 1
            if length == 0:
                break
            if pos + length > len(reply):
                return None
            pos += length
        if pos + 4 > len(reply):
            return None
        pos += 4
    return pos


def _matching_reply(query, reply):
    """reply 是否为 query 的合格上游应答；任何不符均为普通失败。"""
    if not _MIN_MESSAGE_LEN <= len(reply) <= _MAX_REPLY_LEN:
        return False
    if not int.from_bytes(reply[2:4], "big") & _FLAG_QR:
        return False
    if reply[0:2] != query[0:2] or reply[4:6] != query[4:6]:
        return False
    qdcount = int.from_bytes(query[4:6], "big")
    end = _reply_question_end(reply, qdcount)
    if end is None:
        return False
    return reply[_MIN_MESSAGE_LEN:end] == query[_MIN_MESSAGE_LEN:]


def _forward_events(query, items, now, timeout):
    """forward 的模拟主体：items 已校验。

    成功返回 (reply, name, 结束时刻)；耗尽抛 UpstreamTimeout/UpstreamError，
    异常附带 _clock 属性记录耗尽时的模拟时钟，供统计分桶。
    """
    clock = now
    saw_timeout = False
    saw_other = False
    for name, events in items:
        for delay, reply in events[:_PLAN_EVENTS_USED]:
            if delay > timeout:
                saw_timeout = True
                clock += timeout
                continue
            clock += delay
            if reply is not None and _matching_reply(query, reply):
                return reply, name, clock
            saw_other = True
    if saw_timeout and not saw_other:
        exc = UpstreamTimeout("all upstream attempts timed out")
    else:
        exc = UpstreamError("no usable upstream reply")
    exc._clock = clock
    raise exc


def forward(query, plan, now, timeout=5):
    """按 plan 顺序模拟向上游转发 query。

    每项上游仅取前 2 个事件；时钟自 now 累计：delay > timeout 记超时并
    推进 timeout，否则推进 delay 后检查应答（None 或不合格记失败）。
    成功返回 (reply, name, 结束时刻)；全部超时抛 UpstreamTimeout，
    其余耗尽情形（含无事件）抛 UpstreamError。
    """
    msg = decode_query(query)  # TypeError/MessageError 原样传播
    if msg["flags"] & _FLAG_QR:
        raise EncodeError("query has QR set")
    _check_non_negative_int(now, "now")
    _check_int(timeout, "timeout")
    if not _MIN_TIMEOUT <= timeout <= _MAX_TIMEOUT:
        raise ValueError("timeout out of range")
    items = _validate_plan(plan)
    return _forward_events(query, items, now, timeout)


def _check_resolve_inputs(query, now, limit, last_end):
    """resolve/resolve_recursive 共用的 query、now、limit 校验。

    异常与 PositiveCache.resolve 一致；时钟单调性以 last_end 为准。
    返回解码后的单问题报文。
    """
    if not isinstance(now, int) or isinstance(now, bool):
        raise TypeError("now must be int")
    if now < 0 or (last_end is not None and now < last_end):
        raise CacheError("now must be non-negative and monotonic")
    msg = decode_query(query)
    _check_int(limit, "limit")
    if (msg["flags"] & 0x8000 or len(msg["questions"]) != 1
            or not _MIN_LIMIT <= limit <= _MAX_LIMIT):
        raise EncodeError("query or limit not answerable")
    return msg


def _name_in_origin(question, origin, zone_class):
    """qclass 等于 zone 类且规范化 qname 在 origin 内（含 origin 自身）。"""
    qlabels = _normalize_name(question["name"])
    return (question["class"] == zone_class
            and len(qlabels) >= len(origin)
            and qlabels[len(qlabels) - len(origin):] == origin)


def _validate_recursive_reply(reply):
    """校验单层 reply，返回 (kind, rcode, an, ns)。

    None 表示该事件无应答；否则须为 (kind, an, ns)：
    kind 0 转介（an 空、ns 非空，rcode 0）、kind 1 答案（an 非空、
    ns 空，rcode 0）、kind 2 NXDOMAIN（an 空、ns 恰一条 SOA，rcode 3）、
    kind 3 NODATA（同结构，rcode 0）。类型错抛 TypeError，结构或组合错
    抛 ValueError，RR 错抛 RecordError。返回 (kind, rcode, an, ns)。
    """
    if reply is not None and not isinstance(reply, tuple):
        raise TypeError("reply must be None or tuple")
    if reply is None:
        return None
    if len(reply) != 3:
        raise ValueError("reply must be (kind, an, ns)")
    kind, an, ns = reply
    _check_int(kind, "kind")
    if kind not in _RECURSIVE_RCODES:
        raise ValueError("kind must be 0..3")
    if not isinstance(an, list):
        raise TypeError("an must be list")
    if not isinstance(ns, list):
        raise TypeError("ns must be list")
    an = [_validate_rr(rr) for rr in an]
    ns = [_validate_rr(rr) for rr in ns]
    if kind == 0:
        if an or not ns:
            raise ValueError("referral requires empty an and non-empty ns")
    elif kind == 1:
        if not an or ns:
            raise ValueError("answer requires non-empty an and empty ns")
    elif an or len(ns) != 1 or ns[0][1] != _TYPE_SOA:
        raise ValueError("nxdomain/nodata require empty an and one SOA in ns")
    return kind, _RECURSIVE_RCODES[kind], an, ns


def _validate_levels(levels):
    """校验 1–16 层递归计划，返回逐层规范化结果。

    每层结构沿用 forward 的 plan 校验（顺序、1–16 个上游、前 2 事件、
    delay 规则），仅 reply 可为 None 或递归 (kind, an, ns) 三元组；
    所有事件在调用前一次性校验，异常优先级同结构校验顺序。
    """
    if not isinstance(levels, list):
        raise TypeError("levels must be list")
    if not 1 <= len(levels) <= _MAX_RECURSION_LEVELS:
        raise ValueError("levels must contain 1..16 plans")
    plans = []
    for level in levels:
        if not isinstance(level, list):
            raise TypeError("plan must be list")
        if not 1 <= len(level) <= _MAX_PLAN_ITEMS:
            raise ValueError("plan must contain 1..16 items")
        items = []
        for item in level:
            if not isinstance(item, tuple):
                raise TypeError("plan item must be tuple")
            if len(item) != 2:
                raise ValueError("plan item must be (name, events)")
            name, events = item
            if not isinstance(name, str):
                raise TypeError("name must be str")
            if not name:
                raise ValueError("name must be non-empty")
            if not isinstance(events, list):
                raise TypeError("events must be list")
            checked = []
            for event in events:
                if not isinstance(event, tuple):
                    raise TypeError("event must be tuple")
                if len(event) != 2:
                    raise ValueError("event must be (delay, reply)")
                delay, reply = event
                _check_non_negative_int(delay, "delay")
                checked.append((delay, _validate_recursive_reply(reply)))
            items.append((name, checked))
        plans.append(items)
    return plans


class Resolver:
    """权威缓存与上游转发组合的解析器。

    构造先按 forward 规则校验 timeout 与 plan（plan 先在入参上校验再深
    拷贝），最后以 PositiveCache(zone) 建缓存；校验异常类型及优先级与
    forward 一致。

    resolve(query, now, limit=512)：qclass 等于 zone 类且规范化 qname 在
    origin 内时仅查缓存，返回 (应答报文, "authority", now, 是否命中)，
    正负缓存、TTL 衰减、CNAME 与截断语义同 PositiveCache；否则按 plan
    调用 forward，返回 (应答报文, 上游名, 结束时刻, False)，转发结果
    不缓存。

    resolve_recursive(query, levels, now, limit=512)：域内查询沿用
    resolve；域外查询先查独立的递归缓存（键、正/负 TTL、容量 256、FIFO
    同 PositiveCache），命中返回 (应答报文, "cache", now, True)，未命中
    再按 1–16 层转介计划逐层模拟 forward（顺序、前 2 事件、时钟、
    timeout、耗尽异常均同 forward，末层转介抛 UpstreamError）。终态
    按原序与本次 query、limit 编码后写入递归缓存，返回
    (应答报文, 终态上游名, 结束时刻, False)。

    任何失败都原样传播且不改变缓存与上次成功结束时刻；成功后时钟单调性
    以该结束时刻为准。

    stats() 返回只读统计串：紧凑 ASCII JSON（键序 h,m,x,u,c,l，末尾
    换行），重复调用逐字节相同且不改变任何状态。
    h=[权威正负缓存命中, 递归正命中, 递归 NXDOMAIN 命中, 递归 NODATA 命中]；
    m 计缓存未中（resolve 域内权威未中、resolve_recursive 域内权威或
    域外递归未中各加 1；resolve 域外直转不计）；x 仅计上述未中中
    匹配条目因 TTL 到期者（到期令 m、x 各加 1，无条目仅 m 加 1）；
    u=[上游成功, UpstreamTimeout, 其余 UpstreamError]；
    c=[权威条目数, 递归条目数, 256]（正负均计）；
    l 按需上游的两方法成功或耗尽的模拟总时长（结束时刻减开始时刻）
    分桶：0、1..timeout、timeout+1..2*timeout、>2*timeout；
    r=sum(h)/(sum(h)+m)，分母 0 写 0.000000，否则半偶舍入为六位。
    仅成功返回或上游耗尽时原子更新统计；参数/计划/编码/时钟异常不更新，
    耗尽不改缓存与最后时刻。
    """

    def __init__(self, zone: dict, plan: list, timeout: int = 5):
        # 校验次序严格同 forward：先校验 timeout 与 plan，最后才建缓存
        # （PositiveCache 深拷贝校验 zone），异常类型及优先级与 forward 一致。
        _check_int(timeout, "timeout")
        if not _MIN_TIMEOUT <= timeout <= _MAX_TIMEOUT:
            raise ValueError("timeout out of range")
        plan = _validate_plan(plan)  # 先按 forward 规则在入参上校验
        self._plan = copy.deepcopy(plan)  # 再深拷贝，与外部改动隔离
        self._cache = PositiveCache(zone)
        self._timeout = timeout
        self._last_end = None  # 上次成功 resolve 的结束时刻
        # 域外递归结果缓存：与权威正/负缓存独立，共用键与正/负 TTL 规则，
        # 同一容量 256、同一 FIFO 淘汰。
        self._rec_pos = {}  # 正缓存键 -> (插入时刻, 规范化 an)
        self._rec_neg = {}  # 负缓存键 -> (插入时刻, rcode, 规范化 SOA, 负 TTL)
        self._rec_order = deque()
        # stats 计数器；仅成功返回或上游耗尽时与缓存/时钟一同原子更新。
        self._h = [0, 0, 0, 0]  # 权威命中, 递归正命中, 递归 NXDOMAIN, 递归 NODATA
        self._m = 0  # 缓存未中
        self._x = 0  # 未中中因 TTL 到期者
        self._u = [0, 0, 0]  # 上游成功, UpstreamTimeout, 其余 UpstreamError
        self._l = [0, 0, 0, 0]  # 上游模拟总时长分桶

    def _latency_bucket(self, duration):
        """按模拟总时长分桶：0、1..timeout、timeout+1..2*timeout、>2*timeout。"""
        if duration <= 0:
            return 0
        if duration <= self._timeout:
            return 1
        if duration <= 2 * self._timeout:
            return 2
        return 3

    def _authoritative_resolve(self, question, query, now, limit):
        """域内解析：调权威缓存并统计命中/未中/到期。

        返回 (应答报文, 是否命中)；缓存内部编码失败原样传播，不改统计。
        """
        key = (question["name"], question["type"], question["class"])
        expired = self._authoritative_expired(key, now)
        response, hit = self._cache.resolve(query, now, limit)
        if hit:
            self._h[0] += 1
        else:
            self._m += 1
            if expired:
                self._x += 1
        return response, hit

    def _authoritative_expired(self, key, now):
        """权威缓存中该键（正、NODATA、NXDOMAIN 顺序）是否有条目已到期。"""
        entry = self._cache._entries.get(key)
        if entry is not None:
            inserted, an = entry
            return now - inserted >= min(rr[3] for rr in an)
        neg_key = ("nodata",) + key
        neg = self._cache._neg_entries.get(neg_key)
        if neg is None:
            neg_key = ("nxdomain", key[0], key[2])
            neg = self._cache._neg_entries.get(neg_key)
        if neg is None:
            return False
        inserted, _rcode, _soa, neg_ttl = neg
        return now - inserted >= neg_ttl

    def resolve(self, query: bytes, now: int,
                limit: int = 512) -> tuple[bytes, str, int, bool]:
        # query、now、limit 的校验与 PositiveCache.resolve 一致，
        # 单调性以上次成功结束时刻为准。
        msg = _check_resolve_inputs(query, now, limit, self._last_end)
        question = msg["questions"][0]
        origin = self._cache._origin
        if _name_in_origin(question, origin, self._cache._zone_class):
            response, hit = self._authoritative_resolve(
                question, query, now, limit)
            self._last_end = now
            return response, "authority", now, hit
        # 域外直转：不计缓存未中；仅成功或耗尽时更新统计与时钟。
        try:
            reply, name, end = _forward_events(
                query, self._plan, now, self._timeout)
        except UpstreamError as exc:
            self._u[1 if isinstance(exc, UpstreamTimeout) else 2] += 1
            self._l[self._latency_bucket(exc._clock - now)] += 1
            raise
        self._u[0] += 1
        self._l[self._latency_bucket(end - now)] += 1
        self._last_end = end
        return reply, name, end, False

    def _recursive_cache_lookup(self, query, question, now, limit):
        """域外递归结果查找，返回 (应答报文或 None, 命中类别, 到期标记)。

        命中类别为 "pos"（递归正）、"nxdomain" 或 "nodata"；未命中为 None。
        键、正/负 TTL、查找顺序同 PositiveCache；到期条目标记为
        ("pos"/"neg", 键) 但不立即删除，由调用方在新终态编码成功后清理，
        保证失败不改状态。
        """
        key = (question["name"], question["type"], question["class"])
        entry = self._rec_pos.get(key)
        if entry is not None:
            inserted, an = entry
            elapsed = now - inserted
            if elapsed < min(rr[3] for rr in an):
                aged = [(labels, rrtype, rrclass, ttl - elapsed, rdata)
                        for labels, rrtype, rrclass, ttl, rdata in an]
                return _encode_plan(query, 0, aged, [], limit), "pos", None
            return None, None, ("pos", key)
        neg_key = ("nodata",) + key
        neg = self._rec_neg.get(neg_key)
        kind = "nodata"
        if neg is None:
            neg_key = ("nxdomain", key[0], key[2])
            neg = self._rec_neg.get(neg_key)
            kind = "nxdomain"
        if neg is None:
            return None, None, None
        inserted, rcode, soa, neg_ttl = neg
        elapsed = now - inserted
        if elapsed >= neg_ttl:
            return None, None, ("neg", neg_key)
        aged_soa = (soa[0], soa[1], soa[2], neg_ttl - elapsed, soa[4])
        return _encode_plan(query, rcode, [], [aged_soa], limit), kind, None

    def _store_recursive_terminal(self, question, now, rcode, an, ns, expired):
        """终态按 PositiveCache 规则写入递归缓存（容量 256、FIFO）。

        先清理到期旧条目（编码已成功），再按正/负规则写入并按需淘汰。
        """
        if expired is not None:
            tag, ekey = expired
            del (self._rec_pos if tag == "pos" else self._rec_neg)[ekey]
            self._rec_order.remove(expired)
        key = (question["name"], question["type"], question["class"])
        if rcode == 0 and not ns and an and all(rr[3] > 0 for rr in an):
            self._rec_pos[key] = (now, an)
            self._rec_order.append(("pos", key))
        else:
            negative = _negative_cache_entry(key, rcode, an, ns, now)
            if negative is None:
                return
            neg_key, neg_entry = negative
            self._rec_neg[neg_key] = neg_entry
            self._rec_order.append(("neg", neg_key))
        if len(self._rec_order) > _CACHE_CAPACITY:
            tag, oldest = self._rec_order.popleft()
            del (self._rec_pos if tag == "pos" else self._rec_neg)[oldest]

    def resolve_recursive(self, query: bytes, levels, now: int,
                          limit: int = 512) -> tuple[bytes, str, int, bool]:
        """按 1–16 层转介计划递归解析域外查询。

        query/now/limit 的异常沿用 resolve；levels 为逐层 forward 式
        plan（1–16 层，每层 1–16 个上游，仅前 2 事件），reply 为 None
        或 (kind, an, ns)：0 转介、1 答案、2 NXDOMAIN、3 NODATA。
        时钟、timeout 与耗尽异常（全超时 UpstreamTimeout，其余
        UpstreamError）沿用 forward；末层仍为转介（kind 0）抛 UpstreamError。
        终态（kind 1/2/3）按原序与本次 query、limit 编码并按
        PositiveCache 键与正/负 TTL 规则缓存（256 项 FIFO，source 取
        上游名、hit=False）；递归缓存命中返回 (应答, "cache", now, True)。
        任何失败都不改变缓存与上次成功结束时刻。
        """
        msg = _check_resolve_inputs(query, now, limit, self._last_end)
        question = msg["questions"][0]
        origin = self._cache._origin
        if _name_in_origin(question, origin, self._cache._zone_class):
            # 域内沿用 resolve：经权威正/负缓存应答，source 为 "authority"。
            response, hit = self._authoritative_resolve(
                question, query, now, limit)
            self._last_end = now
            return response, "authority", now, hit
        # levels 整体校验（含全部 reply）在任何缓存查找之前完成：
        # 入参非法不得呈现为命中，也不得改变任何状态。
        plans = _validate_levels(levels)
        cached, hit_kind, expired = self._recursive_cache_lookup(
            query, question, now, limit)
        if cached is not None:
            self._h[{"pos": 1, "nxdomain": 2, "nodata": 3}[hit_kind]] += 1
            self._last_end = now
            return cached, "cache", now, True
        # 域外递归未中（无条目或到期均计 m，到期另计 x）；计数挂起，
        # 待上游耗尽或终态编码成功后原子提交，编码异常不更新。
        clock = now
        terminal = None
        try:
            for depth, plan in enumerate(plans):
                result, clock = self._attempt_recursive_level(
                    plan, clock, depth == len(plans) - 1)
                if result[0] == "referral":
                    continue  # 转介：clock 已推进，进入下一层
                _tag, rcode, an, ns, name, end = result
                terminal = (rcode, an, ns, name, end)
                break
        except UpstreamError as exc:
            # 耗尽：提交未中与 u/l 后原样抛出；缓存与最后时刻不变。
            self._m += 1
            if expired is not None:
                self._x += 1
            self._u[1 if isinstance(exc, UpstreamTimeout) else 2] += 1
            self._l[self._latency_bucket(exc._clock - now)] += 1
            raise
        rcode, an, ns, name, end = terminal
        # 先编码成功再落缓存与统计，保证编码失败不改变任何状态。
        response = _encode_plan(query, rcode, an, ns, limit)
        self._store_recursive_terminal(
            question, end, rcode, an, ns, expired)
        self._m += 1
        if expired is not None:
            self._x += 1
        self._u[0] += 1
        self._l[self._latency_bucket(end - now)] += 1
        self._last_end = end
        return response, name, end, False

    def _attempt_recursive_level(self, plan, clock, is_last):
        """模拟单层转发，返回 (result, clock)。

        result 为 ("referral",) 或
        ("terminal", rcode, an, ns, name, clock)。顺序、前 2 事件、时钟与
        timeout 推进沿用 forward；首个可用转介/终态立即结束本层。
        末层转介（kind 0）按普通失败计并继续尝试后续事件/上游；整层耗尽时
        抛带 _clock 的 UpstreamTimeout/UpstreamError（判定同 forward）。
        """
        saw_timeout = False
        saw_other = False
        for name, events in plan:
            for delay, parsed in events[:_PLAN_EVENTS_USED]:
                if delay > self._timeout:
                    saw_timeout = True
                    clock += self._timeout
                    continue
                clock += delay
                if parsed is None:
                    saw_other = True
                    continue
                kind, rcode, an, ns = parsed
                if kind == 0:  # 转介
                    if is_last:
                        saw_other = True
                        continue
                    return ("referral",), clock
                return ("terminal", rcode, an, ns, name, clock), clock
        if saw_timeout and not saw_other:
            exc = UpstreamTimeout("all upstream attempts timed out")
        else:
            exc = UpstreamError("no usable upstream reply")
        exc._clock = clock
        raise exc

    def stats(self) -> str:
        """返回只读统计串：键序 h,m,x,u,c,l,r 的紧凑 ASCII JSON，末尾换行。

        重复调用逐字节相同且不改变任何状态；比率 r 为半偶舍入的六位
        JSON 数值，分母为 0（含负零）时写 0.000000。
        """
        hits = sum(self._h)
        authority_count = len(self._cache._order)
        recursive_count = len(self._rec_order)
        return (
            '{"h":[%d,%d,%d,%d],'
            '"m":%d,"x":%d,'
            '"u":[%d,%d,%d],'
            '"c":[%d,%d,%d],'
            '"l":[%d,%d,%d,%d],'
            '"r":%s}\n'
        ) % (
            self._h[0], self._h[1], self._h[2], self._h[3],
            self._m, self._x,
            self._u[0], self._u[1], self._u[2],
            authority_count, recursive_count, _CACHE_CAPACITY,
            self._l[0], self._l[1], self._l[2], self._l[3],
            _hit_ratio_text(hits, self._m),
        )


def _hit_ratio_text(hits, misses):
    """r=hits/(hits+misses)：精确整数半偶舍入为六位小数 JSON 数值字面量。

    分母 0 写 0.000000；结果恒非负，不存在负零问题。
    """
    total = hits + misses
    if total == 0:
        return "0.000000"
    scale = 1000000
    scaled, rem = divmod(hits * scale, total)
    twice = 2 * rem
    if twice > total or (twice == total and scaled % 2 == 1):
        scaled += 1  # 距上位更近，或恰处半值且下位为奇数
    return "%d.%06d" % (scaled // scale, scaled % scale)


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
