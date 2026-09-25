"""DNS 问题报文解码与确定性权威应答编码（仅标准库、离线）。

公开接口：
- MessageError: 报文格式错误（ValueError 子类）。
- EDNSError: EDNS 查询截断、尾随、名字非法、AN/NS 非空或 AR/OPT
  非法、模型含 OPT（MessageError 子类）。
- ZoneError: zone 模型非法（ValueError 子类）。
- RecordError: 记录模型不符合编码要求（ValueError 子类）。
- EncodeError: 应答无法在给定限制内编码（ValueError 子类）。
- CNAMEError: CNAME 链出现名称重复或超过 16 跳（ValueError 子类）。
- CacheError: 缓存时钟非单调等缓存语义错误（ValueError 子类）。
- ConfigError: 配置文本解析或结构非法（ValueError 子类）。
- ReplayError: 回放操作序列非法或回放记录与期望不符（ValueError 子类）。
- PolicyError: 授权规则数量、键序或字段值非法（ValueError 子类）。
- decode_query(data: bytes) -> dict: 解码 DNS 查询报文。
- encode_response(query: bytes, model: dict) -> bytes: 编码权威应答报文。
- edns(query: bytes, model: dict, rcode: int = 0) -> bytes: 编码可含
  OPT 的查询的 EDNS 应答报文。
- answer(query: bytes, zone: dict, limit: int = 512) -> bytes: 按 zone 应答查询。
- import_zone(text: str) -> dict: 导入 v0/v1/v2 配置文本为规范化 zone。
- export_zone(zone: dict) -> str: 把 zone 导出为 v1 配置文本。
- migrate_zone(text: str) -> str: 把 v0/v1/v2 配置文本完整校验、规范化
  并迁移为 v2 配置文本（紧凑 ASCII JSON，末尾单换行）。
- PositiveCache(zone): 容量 256 的正/负答案缓存，resolve(query, now, limit=512)
  返回 (应答报文, 是否命中)；stats(reset=False) 返回键序 h,m,x,k 的
  紧凑 ASCII JSON（末尾换行），reset=True 先返回快照再清零 h,m,x。
- UpstreamError: 上游转发未获得可用应答（RuntimeError 子类）。
- UpstreamTimeout: 上游转发全部超时（UpstreamError 子类）。
- forward(query, plan, now, timeout=5): 按 plan 顺序模拟上游转发，
  成功返回 (应答报文, 上游名, 结束时刻)。
- Resolver(zone, plan, timeout=5): 权威缓存与上游转发组合的解析器，
  resolve(query, now, limit=512) 返回 (应答报文, 来源, 结束时刻, 是否命中缓存)；
  resolve_recursive(query, levels, now, limit=512) 按 1–16 层转介计划
  递归解析域外查询，返回 (应答报文, 来源, 结束时刻, 是否命中递归缓存)；
  stats() 返回只读统计的紧凑 ASCII JSON（键序 h,m,x,u,c,l,r，末尾换行）；
  reload_zone(text) 原子换区并返回从 0 递增的修订号（stats() 不变，
  c[0] 于下次解析提交时同步）；
  reload_zone_tx(text, expected) 带修订号检查的原子换区事务，返回
  键序 version,result 的紧凑 ASCII JSON 报告（末尾换行），result 为
  "applied"、"unchanged" 或 "conflict"，修订号与 reload_zone 共用。
- replay(zone, plan, ops, expected=None, timeout=5) -> str: 在 Resolver
  上依次回放 reload/reload_tx/resolve/recursive 操作并记录为紧凑
  ASCII JSON（末尾单换行）。
- authorize(query: bytes, client: str, rules: list, default: str = "deny")
  -> bool: 按 client/名称/类型规则原序匹配授权查询。
- RateLimiter(rules): 确定性固定窗查询/响应限流器，
  allow(query, client, now, kind="query") -> (是否放行, 余量或 -1)；
  stats(reset=False) -> str 返回键序 query,response,expired,evicted,
  keys 的紧凑 ASCII JSON（末尾换行），reset=True 先返回快照再清零计数。

命令行：python dns.py decode HEX
"""

from bisect import bisect_right
from collections import deque
import copy
import ipaddress
import json
import sys


class MessageError(ValueError):
    """DNS 报文无法解码。"""


class EDNSError(MessageError):
    """EDNS 报文无法解码：AR/OPT 非法、截断、尾随或模型含 OPT。"""


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


class ConfigError(ValueError):
    """配置文本无法解析或结构不符合版本格式。"""


class ReplayError(ValueError):
    """回放操作序列非法或回放记录与期望不符。"""


class PolicyError(ValueError):
    """授权规则数量、键序或字段值非法。"""


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
_LOWER_HEXDIGITS = frozenset("0123456789abcdef")

_MODEL_KEYS = ["an", "ns", "ar", "limit"]
_ZONE_KEYS = ["origin", "records"]
_RR_KEYS = ["name", "type", "class", "ttl", "rdata"]
_CONFIG_KEYS = ["version", "origin", "records"]
_CONFIG_KEYS_V2 = ["version", "origin", "class", "records"]
_CONFIG_RR_KEYS = ["name", "type", "class", "ttl", "rdata"]
_CONFIG_RR_KEYS_V0 = ["name", "type", "class", "ttl", "data"]
_CONFIG_RR_KEYS_V2 = ["name", "type", "ttl", "rdata"]
_REPLAY_RELOAD_KEYS = ["op", "text"]
_REPLAY_RELOAD_TX_KEYS = ["op", "text", "expected"]
_REPLAY_RESOLVE_KEYS = ["op", "query", "now", "limit"]
_REPLAY_RECURSIVE_KEYS = ["op", "query", "levels", "now", "limit"]
_REPLAY_LEVEL_ITEM_KEYS = ["name", "events"]
_REPLAY_EVENT_KEYS = ["delay", "reply"]
_REPLAY_REPLY_KEYS = ["kind", "an", "ns"]
_POLICY_RULE_KEYS = ["client", "name", "type", "action"]
_POLICY_ACTIONS = frozenset(("allow", "deny"))
_MAX_POLICY_RULES = 256
_RATE_RULE_KEYS = ["client", "name", "type", "window", "query", "response"]
_RATE_KINDS = ("query", "response")
_MIN_RATE_WINDOW = 1
_MAX_RATE_WINDOW = 3600
_MAX_RATE_QUOTA = 65535
_RATE_TABLE_CAPACITY = 4096
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
_TYPE_OPT = 41
_MIN_OPT_CLASS = 512
_FLAG_DO = 0x8000
_MAX_EDNS_RCODE = 0xFFF
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
# 递归缓存命中类别 -> stats 的 h 下标（正/NXDOMAIN/NODATA）
_RECURSIVE_HIT_KINDS = {"pos": 1, "nxdomain": 2, "nodata": 3}


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


def _decode_edns_query(data):
    """解码可含单个 OPT 的查询报文，返回 (msg, (opt_class, do) 或 None)。

    问题段解码契约同 decode_query，但查询截断（问题区越界）、非法名字
    （含压缩问题）、AN/NS 非空、非法 AR/OPT 与尾随字节一律抛
    EDNSError；报文长度与问题数等其余错误仍抛 MessageError。AR 限 0 或
    1 条，有则须为未压缩根 owner、TYPE41、CLASS512..65535、扩展码/
    版本 0、flags 仅 DO、RDLENGTH0 的 OPT。
    """
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
    if ancount or nscount:
        raise EDNSError("response sections must be empty")
    if arcount > 1:
        raise EDNSError("additional section must contain at most one OPT")
    boundaries = set()
    questions = []
    pos = _MIN_MESSAGE_LEN
    for _ in range(qdcount):
        try:
            name, pos = _read_name(data, pos, boundaries)
        except MessageError:
            # 查询截断或名字非法（含压缩问题）：EDNS 路径下统一为 EDNSError。
            raise EDNSError("invalid question name") from None
        if pos + 4 > len(data):
            raise EDNSError("question truncated")
        qtype = int.from_bytes(data[pos:pos + 2], "big")
        qclass = int.from_bytes(data[pos + 2:pos + 4], "big")
        pos += 4
        questions.append({"name": name, "type": qtype, "class": qclass})
    opt = None
    if arcount:
        if pos >= len(data):
            raise EDNSError("opt record truncated")
        if data[pos] != 0:
            raise EDNSError("opt owner must be uncompressed root")
        pos += 1
        if pos + 10 > len(data):
            raise EDNSError("opt record truncated")
        rrtype = int.from_bytes(data[pos:pos + 2], "big")
        rrclass = int.from_bytes(data[pos + 2:pos + 4], "big")
        ttl = int.from_bytes(data[pos + 4:pos + 8], "big")
        rdlength = int.from_bytes(data[pos + 8:pos + 10], "big")
        pos += 10
        if rrtype != _TYPE_OPT:
            raise EDNSError("additional record must be OPT")
        if rrclass < _MIN_OPT_CLASS:
            raise EDNSError("opt class out of range")
        if ttl >> 24 or (ttl >> 16) & 0xFF:
            raise EDNSError("opt extended rcode and version must be 0")
        if ttl & 0xFFFF & ~_FLAG_DO:
            raise EDNSError("opt flags must be DO only")
        if rdlength:
            raise EDNSError("opt rdlength must be 0")
        opt = (rrclass, bool(ttl & _FLAG_DO))
    if pos != len(data):
        raise EDNSError("trailing bytes")
    return {"id": msg_id, "flags": flags, "questions": questions}, opt


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


def edns(query: bytes, model: dict, rcode: int = 0) -> bytes:
    """把（可含 OPT 的）查询报文与应答模型编码为 EDNS 应答报文。

    query/model 的解码与编码契约同 decode_query/encode_response；查询
    AR 限 0 或 1 条，有则须为未压缩根 owner、TYPE41、CLASS512..65535、
    扩展码/版本 0、flags 仅 DO、RDLENGTH0 的 OPT。非法 AR/OPT、截断、
    尾随或 model 含 OPT 抛 EDNSError。rcode 须非 bool 整数（类型错
    TypeError）：有 OPT 限 0..4095、无 OPT 限 0..15，越界 EncodeError。
    无 OPT 时上限 min(model.limit, 512) 且不回 OPT；有 OPT 时上限
    min(model.limit, CLASS)，应答 ar 末项为同 CLASS 根 OPT，
    TTL=(rcode>>4)<<24|DO，头部低 4 位为 rcode&15。编码其余同
    encode_response：超限按 ar、ns、an 尾删并置 TC，OPT 不删；
    问题与 OPT 超限抛 EncodeError。
    """
    if not isinstance(query, bytes):
        raise TypeError("query must be bytes")
    _check_int(rcode, "rcode")
    an, ns, ar, limit = _validate_model(model)
    msg, opt = _decode_edns_query(query)
    for section in (an, ns, ar):
        if any(rr[1] == _TYPE_OPT for rr in section):
            raise EDNSError("model must not contain OPT records")
    if msg["flags"] & 0x8000:
        raise EncodeError("query has QR set")
    if not _MIN_LIMIT <= limit <= _MAX_LIMIT:
        raise EncodeError("limit out of range")
    opt_wire = b""
    if opt is None:
        if not 0 <= rcode <= 0xF:
            raise EncodeError("rcode out of range")
        limit = min(limit, _MAX_MESSAGE_LEN)
    else:
        if not 0 <= rcode <= _MAX_EDNS_RCODE:
            raise EncodeError("rcode out of range")
        opt_class, do = opt
        limit = min(limit, opt_class)
        ttl = ((rcode >> 4) << 24) | (_FLAG_DO if do else 0)
        opt_wire = (b"\x00" + _TYPE_OPT.to_bytes(2, "big")
                    + opt_class.to_bytes(2, "big") + ttl.to_bytes(4, "big")
                    + b"\x00\x00")
    truncated = False
    # 区段计数为 16 位：OPT 占 ar 一席且不删，model 的 ar 预算相应减一。
    max_ar = _MAX_SECTION_RECORDS - (1 if opt_wire else 0)
    if len(ar) > max_ar:
        del ar[max_ar:]
        truncated = True
    for section in (ns, an):
        if len(section) > _MAX_SECTION_RECORDS:
            del section[_MAX_SECTION_RECORDS:]
            truncated = True
    out, body_base, (an_ends, ns_ends, ar_ends), flags = _build_message(
        msg, an, ns, ar, rcode & 0xF)
    body_limit = limit - len(opt_wire)  # 为 OPT 预留，OPT 不参与尾删
    na, nn, nr = len(an), len(ns), len(ar)
    total_end = ar_ends[-1] if ar_ends else (
        ns_ends[-1] if ns_ends else (an_ends[-1] if an_ends else body_base))
    if total_end > body_limit:
        # 超长：先尾删 ar，ar 清空仍超长再尾删 ns，最后尾删 an。
        truncated = True
        nr = bisect_right(ar_ends, body_limit)
        if nr == 0:
            nn = bisect_right(ns_ends, body_limit)
            if nn == 0:
                na = bisect_right(an_ends, body_limit)
                if na == 0 and body_base > body_limit:
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
    result += opt_wire
    result[6:8] = na.to_bytes(2, "big")
    result[8:10] = nn.to_bytes(2, "big")
    result[10:12] = (nr + (1 if opt_wire else 0)).to_bytes(2, "big")
    if truncated:
        result[2:4] = (flags | _FLAG_TC).to_bytes(2, "big")
    return bytes(result)


def _labels_to_name(labels):
    """标签列表还原为小写绝对名（根为 "."）。"""
    return ".".join(labels) + "." if labels else "."


def _rr_to_model(rr):
    """把规范化 RR 元组还原为键序固定的模型 dict。"""
    labels, rrtype, rrclass, ttl, rdata = rr
    return {"name": _labels_to_name(labels), "type": rrtype,
            "class": rrclass, "ttl": ttl, "rdata": rdata}


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


def _config_pairs(pairs):
    """json object_pairs_hook：保序构造 dict，重复键抛 ConfigError。"""
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ConfigError("duplicate key")
        obj[key] = value
    return obj


def _config_int(value, field):
    if not isinstance(value, int) or isinstance(value, bool):
        raise ConfigError(field + " must be int")


def _parse_zone_config(text):
    """解析 v0/v1/v2 配置文本，返回 (zone dict, version)。

    仅做结构层校验：JSON 解析、重复键、版本、键序、字段类型、布尔整数
    与十六进制；错误统一抛 ConfigError。zone dict 键序 origin,records，
    rdata 为 bytes，名称原样保留，尚未按 zone 规则规范化。
    """
    if not isinstance(text, str):
        raise TypeError("text must be str")
    try:
        config = json.loads(text, object_pairs_hook=_config_pairs)
    except json.JSONDecodeError:
        raise ConfigError("invalid JSON") from None
    if not isinstance(config, dict):
        raise ConfigError("config must be an object")
    if list(config.keys()) not in (_CONFIG_KEYS, _CONFIG_KEYS_V2):
        raise ConfigError("invalid config key order")
    version = config["version"]
    _config_int(version, "version")
    if version not in (0, 1, 2):
        raise ConfigError("unsupported version")
    expected_keys = _CONFIG_KEYS_V2 if version == 2 else _CONFIG_KEYS
    if list(config.keys()) != expected_keys:
        raise ConfigError("config keys must match version")
    origin = config["origin"]
    if not isinstance(origin, str):
        raise ConfigError("origin must be str")
    records = config["records"]
    if not isinstance(records, list):
        raise ConfigError("records must be list")
    if version == 2:
        zone_class = config["class"]
        _config_int(zone_class, "class")
        if not 0 <= zone_class <= 0xFFFF:
            raise ConfigError("class out of range")
        rr_keys = _CONFIG_RR_KEYS_V2
        hex_key = "rdata"
    else:
        zone_class = None
        rr_keys = _CONFIG_RR_KEYS if version == 1 else _CONFIG_RR_KEYS_V0
        hex_key = "rdata" if version == 1 else "data"
    zone_records = []
    for rr in records:
        if not isinstance(rr, dict):
            raise ConfigError("record must be an object")
        if list(rr.keys()) != rr_keys:
            raise ConfigError("invalid record key order")
        name = rr["name"]
        if not isinstance(name, str):
            raise ConfigError("name must be str")
        _config_int(rr["type"], "type")
        _config_int(rr["ttl"], "ttl")
        if version == 2:
            rrclass = zone_class
        else:
            _config_int(rr["class"], "class")
            rrclass = rr["class"]
        hextext = rr[hex_key]
        if not isinstance(hextext, str):
            raise ConfigError(hex_key + " must be str")
        if (len(hextext) % 2
                or any(c not in _LOWER_HEXDIGITS for c in hextext)):
            raise ConfigError(
                hex_key + " must be even-length lowercase hex")
        zone_records.append({"name": name, "type": rr["type"],
                             "class": rrclass, "ttl": rr["ttl"],
                             "rdata": bytes.fromhex(hextext)})
    return {"origin": origin, "records": zone_records}, version


def _zone_to_v2(origin_labels, rrs, zone_class):
    """把规范化 zone 组装为 v2 配置 dict（记录保持原序）。"""
    records = []
    for rr in rrs:
        model = _rr_to_model(rr)
        records.append({"name": model["name"], "type": model["type"],
                        "ttl": model["ttl"], "rdata": model["rdata"].hex()})
    return {"version": 2, "origin": _labels_to_name(origin_labels),
            "class": zone_class, "records": records}


def migrate_zone(text: str) -> str:
    """把 v0/v1/v2 配置文本完整校验、规范化并迁移为 v2 配置文本。

    顶层键序 version,origin,class,records，version 为整数 2，class 为
    0..65535 的非 bool 整数且各记录统一沿用；记录键序
    name,type,ttl,rdata，rdata 为偶数长小写十六进制。输出为紧凑 ASCII
    JSON，整数十进制，末尾单换行；记录保持原序，名称与 CNAME rdata 按
    zone 规则规范化。等价区域输出逐字节相同，对迁移结果再次迁移不变。
    text 非 str 抛 TypeError；JSON 解析、重复键、版本、键序、字段类型
    或十六进制错误抛 ConfigError；zone 语义错误沿用 RecordError、
    ZoneError。
    """
    zone, _version = _parse_zone_config(text)
    origin_labels, rrs, zone_class = _validate_zone(zone)
    config = _zone_to_v2(origin_labels, rrs, zone_class)
    return json.dumps(config, ensure_ascii=True,
                      separators=(",", ":")) + "\n"


def import_zone(text: str) -> dict:
    """把 v0/v1/v2 配置文本导入为规范化 zone dict（键序 origin,records）。

    文本须为 JSON 对象：v0/v1 键序 version,origin,records，version 为
    整数 0 或 1，v1 记录键序 name,type,class,ttl,rdata，v0 末键为
    "data"；v2 键序 version,origin,class,records，version 为 2，class
    为顶层统一 class（0..65535 的非 bool 整数），记录键序
    name,type,ttl,rdata。各版本 rdata/data 均为偶数长小写十六进制。
    JSON 解析、重复键、键序、版本、类型、布尔整数与十六进制错误抛
    ConfigError；zone 语义错误沿用 RecordError、ZoneError。返回 zone
    的 rdata 为 bytes，名称与 CNAME rdata 已按 zone 规则规范化。
    """
    zone, _version = _parse_zone_config(text)
    origin_labels, rrs, _zone_class = _validate_zone(zone)
    return {"origin": _labels_to_name(origin_labels),
            "records": [_rr_to_model(rr) for rr in rrs]}


def export_zone(zone: dict) -> str:
    """把 zone 导出为 v1 配置文本（紧凑 ASCII JSON，末尾换行）。

    键序 version,origin,records，version 为整数 1；记录键序
    name,type,class,ttl,rdata，rdata 为偶数长小写十六进制，数字十进制。
    zone 按 zone 规则校验并规范化，语义错误沿用 RecordError、ZoneError。
    """
    if not isinstance(zone, dict):
        raise TypeError("zone must be dict")
    origin, rrs, _zone_class = _validate_zone(zone)
    records = []
    for rr in rrs:
        model = _rr_to_model(rr)
        records.append({"name": model["name"], "type": model["type"],
                        "class": model["class"], "ttl": model["ttl"],
                        "rdata": model["rdata"].hex()})
    config = {"version": 1, "origin": _labels_to_name(origin),
              "records": records}
    return json.dumps(config, ensure_ascii=True, separators=(",", ":")) + "\n"


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

    stats(reset=False) 输出键序 h,m,x,k 的紧凑 ASCII JSON（末尾单换行）：
    h 键序 p,nx,nd，按 resolve 命中正缓存、NXDOMAIN、NODATA 递增；
    m 键序 p,nx,nd,o，按成功未命中后新写正缓存、NXDOMAIN、NODATA 或
    未写条目递增；x 累计成功 resolve 实际删除的到期条目数；k 键序
    p,nx,nd,total,capacity，依次为当前三类条目数、合计与 256。统计仅在
    resolve 成功返回时原子提交，任何异常均不改变它们；检测到期后编码
    失败不计 x，截断不改分类，命中不重排 FIFO。reset 非 bool 抛
    TypeError 且无变化；False 重复读取逐字节相同；True 先返回旧快照再
    清零 h、m、x，保留缓存、FIFO、时钟与 k。
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
        # stats 计数，仅在 resolve 成功返回时随缓存一并原子提交：
        # h 为 [正命中, NXDOMAIN 命中, NODATA 命中]；m 为 [成功未中后
        # 新写正缓存, 新写 NXDOMAIN, 新写 NODATA, 未写条目]；x 为成功
        # resolve 实际删除的到期条目数。
        self._stats_h = [0, 0, 0]
        self._stats_m = [0, 0, 0, 0]
        self._stats_x = 0

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
                # 统计、时钟仅在成功返回时原子提交；命中不重排 FIFO。
                self._stats_h[0] += 1
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
                    # 统计、时钟仅在成功返回时原子提交；命中不重排 FIFO。
                    # neg_key 首项区分 NXDOMAIN（h[1]）与 NODATA（h[2]）。
                    self._stats_h[1 if neg_key[0] == "nxdomain" else 2] += 1
                    self._last_now = now
                    return response, True
                expired = ("neg", neg_key)
        # 未命中（含到期）：先按 answer 语义生成未截断的完整有序应答。
        rcode, an, ns = _answer_plan(
            msg, self._origin, self._records, self._zone_class)
        # 先编码成功再落条目，保证编码失败不改变任何状态（含统计与时钟）。
        response = _encode_plan(query, rcode, an, ns, limit)
        # 编码已成功：到期清理、新条目、统计与时钟随成功返回原子提交。
        # 分类按未截断完整计划，故截断不改变 m 的分类。
        if expired is not None:
            tag, ekey = expired
            del (self._entries if tag == "pos" else self._neg_entries)[ekey]
            self._order.remove(expired)  # 到期删除后按未命中刷新
        if rcode == 0 and not ns and an and all(rr[3] > 0 for rr in an):
            self._entries[key] = (now, an)
            self._order.append(("pos", key))
            m_index = 0  # 新写正缓存
        else:
            negative = self._negative_entry(key, rcode, an, ns, now)
            if negative is not None:
                neg_key, neg_entry = negative
                self._neg_entries[neg_key] = neg_entry
                self._order.append(("neg", neg_key))
                # 负键首项区分 NXDOMAIN（m[1]）与 NODATA（m[2]）。
                m_index = 1 if neg_key[0] == "nxdomain" else 2
            else:
                m_index = 3  # 未写条目
        if len(self._order) > _CACHE_CAPACITY:
            tag, oldest = self._order.popleft()  # 满时淘汰最早插入者
            del (self._entries if tag == "pos" else self._neg_entries)[oldest]
        if expired is not None:
            self._stats_x += 1  # 本次成功 resolve 实际删除的到期条目
        self._stats_m[m_index] += 1
        self._last_now = now
        return response, False

    def stats(self, reset: bool = False) -> str:
        """返回固定键序紧凑 ASCII JSON（末尾单换行），可选重置 h、m、x。

        顶层键序 h,m,x,k：h 键序 p,nx,nd（resolve 命中正缓存、NXDOMAIN、
        NODATA 次数）；m 键序 p,nx,nd,o（成功未命中后新写正缓存、
        NXDOMAIN、NODATA、未写条目次数）；x 为成功 resolve 实际删除的
        到期条目累计；k 键序 p,nx,nd,total,capacity，依次为当前正、
        NXDOMAIN、NODATA 条目数、合计与 256。值均为非负十进制整数。
        统计仅在 resolve 成功返回时原子提交。reset 非 bool 抛 TypeError
        且无变化；False 重复读取逐字节相同且不改状态；True 先返回旧
        快照，再清零 h、m、x，保留缓存、FIFO、时钟与 k。
        """
        if not isinstance(reset, bool):
            raise TypeError("reset must be bool")
        p_entries = len(self._entries)
        nx_entries = sum(1 for neg_key in self._neg_entries
                         if neg_key[0] == "nxdomain")
        nd_entries = len(self._neg_entries) - nx_entries
        text = (
            '{"h":{"p":' + str(self._stats_h[0])
            + ',"nx":' + str(self._stats_h[1])
            + ',"nd":' + str(self._stats_h[2]) + "}"
            + ',"m":{"p":' + str(self._stats_m[0])
            + ',"nx":' + str(self._stats_m[1])
            + ',"nd":' + str(self._stats_m[2])
            + ',"o":' + str(self._stats_m[3]) + "}"
            + ',"x":' + str(self._stats_x)
            + ',"k":{"p":' + str(p_entries)
            + ',"nx":' + str(nx_entries)
            + ',"nd":' + str(nd_entries)
            + ',"total":' + str(len(self._order))
            + ',"capacity":' + str(_CACHE_CAPACITY) + "}}\n"
        )
        if reset:
            # 先返回旧快照再清零；缓存、FIFO、时钟与 k 均保留。
            self._stats_h = [0, 0, 0]
            self._stats_m = [0, 0, 0, 0]
            self._stats_x = 0
        return text


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
        raise UpstreamTimeout("all upstream attempts timed out")
    raise UpstreamError("no usable upstream reply")


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


def _plan_total_elapsed(plan, timeout):
    """forward 耗尽时的总模拟时长（与 forward 的时钟推进一致）。"""
    elapsed = 0
    for _name, events in plan:
        for delay, _reply in events[:_PLAN_EVENTS_USED]:
            elapsed += timeout if delay > timeout else delay
    return elapsed


def _duration_bucket(elapsed, timeout):
    """模拟时长分桶下标：0、1..timeout、timeout+1..2*timeout、>2*timeout。"""
    if elapsed <= 0:
        return 0
    if elapsed <= timeout:
        return 1
    if elapsed <= 2 * timeout:
        return 2
    return 3


def _ratio_six(p, q):
    """p/q 半偶舍入到 6 位小数的 JSON 数值字符串；分母 0 写 0.000000。"""
    if q == 0:
        return "0.000000"
    quotient, remainder = divmod(p * 10**6, q)
    if 2 * remainder > q:
        quotient += 1
    elif 2 * remainder == q and quotient % 2 == 1:
        quotient += 1
    return "{}.{:06d}".format(quotient // 10**6, quotient % 10**6)


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

    stats()：只读统计，返回键序 h,m,x,u,c,l,r 的紧凑 ASCII JSON（末尾
    换行）；仅成功返回或上游耗尽时原子更新（c[0] 随提交与权威缓存
    同步），参数/计划/编码/时钟异常不更新，耗尽不改缓存与最后时刻。

    reload_zone(text)：导入 v0/v1/v2 配置文本并原子换区，返回从 0 递增的
    修订号。先 import_zone 再以新 zone 构造 PositiveCache，全部成功后
    才提交：替换权威缓存（清空缓存条目），保留时钟、plan、统计与递归
    缓存；统计不随换区提交，stats() 逐字节不变，c[0] 于下次解析提交时
    与新缓存同步；任何失败都回滚，不改变任何状态。

    reload_zone_tx(text, expected)：带修订号检查的原子换区事务，返回
    键序仅 version,result 的紧凑 ASCII JSON 报告（末尾换行）。
    expected 非 int（含 bool）或 text 非 str 抛 TypeError，expected<0
    抛 ConfigError；expected 不等于当前修订号时不解析 text，报告
    conflict 且状态不变；相等时解析并构造候选 PositiveCache，失败沿用
    ConfigError、RecordError、ZoneError。候选 export_zone 文本与当前
    区域相同报告 unchanged（版本、缓存不变），否则原子换区、清空权威
    缓存、保留递归缓存/时钟/plan/统计（stats() 提交当下不变），修订号
    加 1 报告 applied。修订号初始为 0，与 reload_zone 共用递增状态。
    """

    def __init__(self, zone: dict, plan: list, timeout: int = 5):
        # 校验次序严格同 forward：先校验 timeout 与 plan，最后才建缓存
        # （PositiveCache 深拷贝校验 zone），异常类型及优先级与 forward 一致。
        _check_int(timeout, "timeout")
        if not _MIN_TIMEOUT <= timeout <= _MAX_TIMEOUT:
            raise ValueError("timeout out of range")
        plan = _validate_plan(plan)  # 先按 forward 规则在入参上校验
        self._plan = copy.deepcopy(plan)  # 仅保存深拷贝，与外部改动隔离
        self._cache = PositiveCache(zone)
        self._timeout = timeout
        self._last_end = None  # 上次成功 resolve 的结束时刻
        # 域外递归结果缓存：与权威正/负缓存独立，共用键与正/负 TTL 规则，
        # 同一容量 256、同一 FIFO 淘汰。
        self._rec_pos = {}  # 正缓存键 -> (插入时刻, 规范化 an)
        self._rec_neg = {}  # 负缓存键 -> (插入时刻, rcode, 规范化 SOA, 负 TTL)
        self._rec_order = deque()
        # 统计计数器：h 命中细分、m 未中、x 到期未中、u 上游结果、l 时长分桶。
        self._stats_h = [0, 0, 0, 0]
        self._stats_m = 0
        self._stats_x = 0
        self._stats_u = [0, 0, 0]
        self._stats_l = [0, 0, 0, 0]
        # stats 的 c[0]（权威条目数）：仅随统计提交与缓存同步，reload_zone
        # 替换缓存不提交统计，故换区后保持旧值直至下次解析提交。
        self._stats_c0 = 0
        self._revision = 0  # 下次 reload_zone 成功时返回的修订号

    def resolve(self, query: bytes, now: int,
                limit: int = 512) -> tuple[bytes, str, int, bool]:
        # query、now、limit 的校验与 PositiveCache.resolve 一致，
        # 单调性以上次成功结束时刻为准。
        msg = _check_resolve_inputs(query, now, limit, self._last_end)
        question = msg["questions"][0]
        origin = self._cache._origin
        if _name_in_origin(question, origin, self._cache._zone_class):
            expired = self._authority_miss_expired(question, now)
            response, hit = self._cache.resolve(query, now, limit)
            if hit:
                self._stats_h[0] += 1
            else:
                self._stats_m += 1
                if expired:
                    self._stats_x += 1
            self._sync_stats_c0()
            self._last_end = now
            return response, "authority", now, hit
        try:
            reply, name, end = forward(query, self._plan, now, self._timeout)
        except UpstreamTimeout:
            self._stats_u[1] += 1
            self._stats_l[_duration_bucket(
                _plan_total_elapsed(self._plan, self._timeout),
                self._timeout)] += 1
            self._sync_stats_c0()
            raise
        except UpstreamError:
            self._stats_u[2] += 1
            self._stats_l[_duration_bucket(
                _plan_total_elapsed(self._plan, self._timeout),
                self._timeout)] += 1
            self._sync_stats_c0()
            raise
        self._stats_u[0] += 1
        self._stats_l[_duration_bucket(end - now, self._timeout)] += 1
        self._sync_stats_c0()
        self._last_end = end
        return reply, name, end, False

    def _sync_stats_c0(self):
        """统计提交点：c[0] 与当前权威缓存条目数同步。"""
        self._stats_c0 = len(self._cache._order)

    def _authority_miss_expired(self, question, now):
        """本次权威缓存查找若未中，是否源于到期条目（查找顺序同 PositiveCache）。"""
        cache = self._cache
        key = (question["name"], question["type"], question["class"])
        entry = cache._entries.get(key)
        if entry is not None:
            return now - entry[0] >= min(rr[3] for rr in entry[1])
        neg_key = ("nodata",) + key
        neg = cache._neg_entries.get(neg_key)
        if neg is None:
            neg_key = ("nxdomain", key[0], key[2])
            neg = cache._neg_entries.get(neg_key)
        if neg is None:
            return False
        return now - neg[0] >= neg[3]

    def _recursive_cache_lookup(self, query, question, now, limit):
        """域外递归结果查找，返回 (应答报文或 None, 到期标记或 None, 命中类别或 None)。

        键、正/负 TTL、查找顺序同 PositiveCache；到期条目标记为
        ("pos"/"neg", 键) 但不立即删除，由调用方在新终态编码成功后清理，
        保证失败不改状态。命中类别为 "pos"、"nxdomain"、"nodata"，供统计细分。
        """
        key = (question["name"], question["type"], question["class"])
        entry = self._rec_pos.get(key)
        if entry is not None:
            inserted, an = entry
            elapsed = now - inserted
            if elapsed < min(rr[3] for rr in an):
                aged = [(labels, rrtype, rrclass, ttl - elapsed, rdata)
                        for labels, rrtype, rrclass, ttl, rdata in an]
                return _encode_plan(query, 0, aged, [], limit), None, "pos"
            return None, ("pos", key), None
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
            return None, ("neg", neg_key), None
        aged_soa = (soa[0], soa[1], soa[2], neg_ttl - elapsed, soa[4])
        return _encode_plan(query, rcode, [], [aged_soa], limit), None, kind

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
            expired = self._authority_miss_expired(question, now)
            response, hit = self._cache.resolve(query, now, limit)
            if hit:
                self._stats_h[0] += 1
            else:
                self._stats_m += 1
                if expired:
                    self._stats_x += 1
            self._sync_stats_c0()
            self._last_end = now
            return response, "authority", now, hit
        # levels 整体校验（含全部 reply）在任何缓存查找之前完成：
        # 入参非法不得呈现为命中，也不得改变任何状态。
        plans = _validate_levels(levels)
        cached, expired, kind = self._recursive_cache_lookup(
            query, question, now, limit)
        if cached is not None:
            self._stats_h[_RECURSIVE_HIT_KINDS[kind]] += 1
            self._sync_stats_c0()
            self._last_end = now
            return cached, "cache", now, True
        # 未命中：m 与（到期时）x 暂记，待成功或耗尽时与 u、l 一并原子提交。
        m_inc = 1
        x_inc = 1 if expired is not None else 0
        # 逐层按 forward 时序模拟；终态先编码成功再记 end 与写缓存。
        clock = now
        result = None
        for depth, plan in enumerate(plans):
            result, clock, saw_timeout, saw_other = self._attempt_recursive_level(
                plan, clock, depth == len(plans) - 1)
            if result is None:
                # 该层所有上游均未给出可用应答：耗尽异常沿用 forward；
                # 统计随耗尽提交，缓存与最后时刻不变。
                self._stats_m += m_inc
                self._stats_x += x_inc
                self._sync_stats_c0()
                if saw_timeout and not saw_other:
                    self._stats_u[1] += 1
                    self._stats_l[_duration_bucket(
                        clock - now, self._timeout)] += 1
                    raise UpstreamTimeout("all upstream attempts timed out")
                self._stats_u[2] += 1
                self._stats_l[_duration_bucket(
                    clock - now, self._timeout)] += 1
                raise UpstreamError("no usable upstream reply")
            if result[0] == "referral":
                continue  # 转介：clock 已推进，进入下一层
            _tag, rcode, an, ns, name, end = result
            break
        response = _encode_plan(query, rcode, an, ns, limit)
        self._store_recursive_terminal(
            question, end, rcode, an, ns, expired)
        self._stats_m += m_inc
        self._stats_x += x_inc
        self._stats_u[0] += 1
        self._stats_l[_duration_bucket(end - now, self._timeout)] += 1
        self._sync_stats_c0()
        self._last_end = end
        return response, name, end, False

    def _attempt_recursive_level(self, plan, clock, is_last):
        """模拟单层转发，返回 (result, clock, saw_timeout, saw_other)。

        result 为 None（整层耗尽）、("referral",) 或
        ("terminal", rcode, an, ns, name, clock)。顺序、前 2 事件、时钟与
        timeout 推进沿用 forward；首个可用转介/终态立即结束本层。
        末层转介（kind 0）按普通失败计并继续尝试后续事件/上游。
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
                    return ("referral",), clock, saw_timeout, saw_other
                return (("terminal", rcode, an, ns, name, clock),
                        clock, saw_timeout, saw_other)
        return None, clock, saw_timeout, saw_other

    def reload_zone(self, text: str) -> int:
        """导入配置文本并原子换区，返回从 0 递增的修订号。

        先 import_zone 再以新 zone 构造 PositiveCache，全部成功后才
        提交：替换权威缓存（清空缓存条目），保留时钟、plan、统计与递归
        缓存；统计不随换区提交，stats() 逐字节不变，c[0] 于下次解析
        提交时与新缓存同步。任何失败（TypeError、ConfigError、
        RecordError、ZoneError）都回滚：不改变任何状态。
        """
        zone = import_zone(text)
        cache = PositiveCache(zone)
        self._cache = cache
        revision = self._revision
        self._revision += 1
        return revision

    def reload_zone_tx(self, text: str, expected: int) -> str:
        """带修订号检查的原子换区事务，返回键序 version,result 的报告。

        text 非 str 或 expected 非 int（含 bool）抛 TypeError；
        expected<0 抛 ConfigError。expected 不等于当前修订号时不解析
        text，报告 conflict（version 为当前修订号），不改变任何状态。
        相等时先由 import_zone 解析并以候选 zone 构造 PositiveCache，
        失败沿用 ConfigError、RecordError、ZoneError 且状态不变。候选
        的 export_zone 文本等于当前区域时报告 unchanged，版本与缓存
        不变；否则校验成功后原子换区（清空权威缓存，保留递归缓存、
        时钟、plan 与统计），修订号加 1 并报告 applied（version 为
        新修订号，提交当下 stats() 逐字节不变）。修订号与 reload_zone
        共用，初始为 0。报告为紧凑 ASCII JSON、十进制数字、末尾单换行，
        result 为 "applied"、"unchanged" 或 "conflict"。
        """
        if not isinstance(text, str):
            raise TypeError("text must be str")
        if not isinstance(expected, int) or isinstance(expected, bool):
            raise TypeError("expected must be int")
        if expected < 0:
            raise ConfigError("expected revision must be non-negative")
        if expected != self._revision:
            # 修订号不匹配：不得解析 text，冲突本身不改变任何状态。
            return self._tx_report(self._revision, "conflict")
        zone = import_zone(text)
        cache = PositiveCache(zone)
        candidate_text = export_zone(zone)
        current_text = export_zone(
            {"origin": _labels_to_name(self._cache._origin),
             "records": [_rr_to_model(rr) for rr in self._cache._records]})
        if candidate_text == current_text:
            # 候选与当前区域规范化后等价：不换区、不加修订号。
            return self._tx_report(self._revision, "unchanged")
        self._cache = cache
        self._revision += 1
        return self._tx_report(self._revision, "applied")

    @staticmethod
    def _tx_report(version, result):
        """构造键序 version,result 的紧凑 ASCII JSON 报告（末尾单换行）。"""
        return json.dumps({"version": version, "result": result},
                          ensure_ascii=True, separators=(",", ":")) + "\n"

    def stats(self) -> str:
        """返回当前统计的紧凑 ASCII JSON（键序 h,m,x,u,c,l,r，末尾换行）。

        h 为 [权威正负缓存命中, 递归正命中, 递归NXDOMAIN命中, 递归NODATA命中]；
        m 为缓存未中（resolve 域外直转不计）；x 为未中中因 TTL 到期者；
        u 为 [上游成功, UpstreamTimeout, 其余UpstreamError]；
        c 为 [权威条目数, 递归条目数, 256]（正负均计）；c[0] 随统计提交
        （成功返回或上游耗尽）与权威缓存同步，reload_zone 不提交统计，
        故换区后 c[0] 保持旧值直至下次解析提交；
        l 为需上游的成功或耗尽按模拟总时长分桶
        （0、1..timeout、timeout+1..2*timeout、>2*timeout）；
        r 为 sum(h)/(sum(h)+m) 半偶舍入到 6 位小数（分母 0 写 0.000000）。
        只读：不改变任何状态，重复调用逐字节相同。
        """
        h = list(self._stats_h)
        m = self._stats_m
        x = self._stats_x
        u = list(self._stats_u)
        c = [self._stats_c0, len(self._rec_order), _CACHE_CAPACITY]
        elapsed_buckets = list(self._stats_l)
        return (
            '{"h":[' + ",".join(map(str, h)) + "]"
            + ',"m":' + str(m)
            + ',"x":' + str(x)
            + ',"u":[' + ",".join(map(str, u)) + "]"
            + ',"c":[' + ",".join(map(str, c)) + "]"
            + ',"l":[' + ",".join(map(str, elapsed_buckets)) + "]"
            + ',"r":' + _ratio_six(sum(h), sum(h) + m) + "}\n"
        )


def _validate_replay_rrs(rrs, field):
    """校验回放 recursive 操作的 RR 数组，返回 rdata 转为 bytes 的 RR 列表。

    仅校验键序与 rdata 偶长小写十六进制形式，其余 RR 契约留待
    resolve_recursive 按现有规则校验。所有错误抛 ReplayError。
    """
    if not isinstance(rrs, list):
        raise ReplayError(field + " must be list")
    converted = []
    for rr in rrs:
        if not isinstance(rr, dict):
            raise ReplayError("rr must be dict")
        if list(rr.keys()) != _RR_KEYS:
            raise ReplayError("rr keys must be name,type,class,ttl,rdata")
        rdata = rr["rdata"]
        if not isinstance(rdata, str):
            raise ReplayError("rdata must be str")
        if (len(rdata) % 2
                or any(c not in _LOWER_HEXDIGITS for c in rdata)):
            raise ReplayError("rdata must be even-length lowercase hex")
        converted.append({"name": rr["name"], "type": rr["type"],
                          "class": rr["class"], "ttl": rr["ttl"],
                          "rdata": bytes.fromhex(rdata)})
    return converted


def _validate_replay_reply(reply):
    """校验回放 recursive 操作的 reply，返回 None 或 (kind, an, ns)。"""
    if reply is None:
        return None
    if not isinstance(reply, dict):
        raise ReplayError("reply must be null or dict")
    if list(reply.keys()) != _REPLAY_REPLY_KEYS:
        raise ReplayError("reply keys must be kind,an,ns")
    kind = reply["kind"]
    if not isinstance(kind, int) or isinstance(kind, bool):
        raise ReplayError("kind must be int")
    if kind not in _RECURSIVE_RCODES:
        raise ReplayError("kind must be 0..3")
    an = _validate_replay_rrs(reply["an"], "an")
    ns = _validate_replay_rrs(reply["ns"], "ns")
    return (kind, an, ns)


def _validate_replay_levels(levels):
    """校验并转换回放 recursive 操作的 levels，返回 resolve_recursive 入参形式。

    levels 为 1–16 层，每层 1–16 个键序 name,events 的对象；name 为非空
    str；events 元素键序 delay,reply，delay 为非负非 bool int，reply 为
    None 或键序 kind,an,ns 的对象（kind 0..3，an/ns 为 RR 数组）。键序、
    字段类型/范围、十六进制形式与层级组合错误均抛 ReplayError；RR 其余
    契约与 kind/an/ns 组合留待 resolve_recursive 校验。不修改入参。
    """
    if not isinstance(levels, list):
        raise ReplayError("levels must be list")
    if not 1 <= len(levels) <= _MAX_RECURSION_LEVELS:
        raise ReplayError("levels must contain 1..16 plans")
    plans = []
    for level in levels:
        if not isinstance(level, list):
            raise ReplayError("level must be list")
        if not 1 <= len(level) <= _MAX_PLAN_ITEMS:
            raise ReplayError("level must contain 1..16 items")
        items = []
        for item in level:
            if not isinstance(item, dict):
                raise ReplayError("level item must be dict")
            if list(item.keys()) != _REPLAY_LEVEL_ITEM_KEYS:
                raise ReplayError("level item keys must be name,events")
            name = item["name"]
            if not isinstance(name, str):
                raise ReplayError("name must be str")
            if not name:
                raise ReplayError("name must be non-empty")
            events = item["events"]
            if not isinstance(events, list):
                raise ReplayError("events must be list")
            checked_events = []
            for event in events:
                if not isinstance(event, dict):
                    raise ReplayError("event must be dict")
                if list(event.keys()) != _REPLAY_EVENT_KEYS:
                    raise ReplayError("event keys must be delay,reply")
                delay = event["delay"]
                if not isinstance(delay, int) or isinstance(delay, bool):
                    raise ReplayError("delay must be int")
                if delay < 0:
                    raise ReplayError("delay must be non-negative")
                checked_events.append(
                    (delay, _validate_replay_reply(event["reply"])))
            items.append((name, checked_events))
        plans.append(items)
    return plans


def _validate_ops(ops):
    """校验回放操作序列，返回 [(kind, op, converted), ...]（不执行）。

    reload 键序 op,text 且 op 为 "reload"、text 为 str；reload_tx 键序
    op,text,expected 且 op 为 "reload_tx"、text 为 str、expected 为非负
    非 bool int；resolve 键序 op,query,now,limit 且 op 为 "resolve"、
    query 为偶长小写十六进制、now/limit 为非 bool int；recursive 键序
    op,query,levels,now,limit 且 op 为 "recursive"，query/now/limit 同
    resolve，levels 按 _validate_replay_levels 校验并转换（converted
    为转换结果，其余操作 converted 为 None）。ops 非 list 抛 TypeError；
    项、键序、op 名或字段类型/内容错误均抛 ReplayError。
    """
    if not isinstance(ops, list):
        raise TypeError("ops must be list")
    checked = []
    for op in ops:
        if not isinstance(op, dict):
            raise ReplayError("op must be dict")
        keys = list(op.keys())
        if keys == _REPLAY_RELOAD_KEYS:
            kind = "reload"
        elif keys == _REPLAY_RELOAD_TX_KEYS:
            kind = "reload_tx"
        elif keys == _REPLAY_RESOLVE_KEYS:
            kind = "resolve"
        elif keys == _REPLAY_RECURSIVE_KEYS:
            kind = "recursive"
        else:
            raise ReplayError(
                "op keys must be op,text, op,text,expected"
                " or op,query,now,limit or op,query,levels,now,limit")
        if not isinstance(op["op"], str):
            raise ReplayError("op must be str")
        if op["op"] != kind:
            raise ReplayError("op name does not match op keys")
        converted = None
        if kind in ("resolve", "recursive"):
            query = op["query"]
            if not isinstance(query, str):
                raise ReplayError("query must be str")
            if (len(query) % 2
                    or any(c not in _LOWER_HEXDIGITS for c in query)):
                raise ReplayError(
                    "query must be even-length lowercase hex")
            if kind == "recursive":
                converted = _validate_replay_levels(op["levels"])
            if not isinstance(op["now"], int) or isinstance(op["now"], bool):
                raise ReplayError("now must be int")
            if not isinstance(op["limit"], int) or isinstance(op["limit"], bool):
                raise ReplayError("limit must be int")
        else:
            if not isinstance(op["text"], str):
                raise ReplayError("text must be str")
            if kind == "reload_tx":
                expected = op["expected"]
                if not isinstance(expected, int) or isinstance(expected, bool):
                    raise ReplayError("expected must be int")
                if expected < 0:
                    raise ReplayError("expected must be non-negative")
        checked.append((kind, op, converted))
    return checked


def replay(zone: dict, plan: list, ops: list, expected=None,
           timeout: int = 5) -> str:
    """在 Resolver 上依次回放 reload/reload_tx/resolve/recursive 操作。

    ops 非 list 或 expected 非 None/str 抛 TypeError；操作项、键序、
    op 名或字段类型/内容错误均抛 ReplayError；zone、plan、
    timeout 的校验与异常同 Resolver 构造。每项记录键序 in,out,stats：
    in 为操作原文，stats 为该操作后的 stats() 原文。成功 out 首键 ok
    为 true：reload 键序 ok,revision；reload_tx 键序 ok,version,result，
    result 为 "applied"/"unchanged"/"conflict"；resolve 键序
    ok,response,source,end,hit，response 为小写十六进制；recursive
    键序 op,query,levels,now,limit，levels 为 1–16 层、每层 1–16 个
    键序 name,events 的对象（name 非空 str，事件键序 delay,reply，
    delay 非负非 bool int，reply 为 null 或键序 kind,an,ns 的对象，
    kind 0..3，an/ns 为键序 name,type,class,ttl,rdata 的 RR 数组，
    rdata 偶长小写十六进制），校验转换后调用 resolve_recursive，
    成功 out 键序同 resolve。操作抛出的异常记为 out 键序 ok,error
    （false 与异常类名）并继续后续操作，状态语义沿用 Resolver（失败
    不改变任何状态）。输出为紧凑 ASCII JSON，顶层键序 version,ops，
    version 为 1，末尾单换行。expected 为 None 时仅记录；为 str 时
    与输出整体比较，不一致抛 ReplayError。
    """
    if expected is not None and not isinstance(expected, str):
        raise TypeError("expected must be str or None")
    checked = _validate_ops(ops)
    resolver = Resolver(zone, plan, timeout)
    items = []
    for kind, op, converted in checked:
        if kind == "reload":
            try:
                revision = resolver.reload_zone(op["text"])
                out = {"ok": True, "revision": revision}
            except Exception as exc:
                out = {"ok": False, "error": type(exc).__name__}
        elif kind == "reload_tx":
            try:
                report = json.loads(
                    resolver.reload_zone_tx(op["text"], op["expected"]))
                out = {"ok": True, "version": report["version"],
                       "result": report["result"]}
            except Exception as exc:
                out = {"ok": False, "error": type(exc).__name__}
        elif kind == "resolve":
            try:
                response, source, end, hit = resolver.resolve(
                    bytes.fromhex(op["query"]), op["now"], op["limit"])
                out = {"ok": True, "response": response.hex(),
                       "source": source, "end": end, "hit": hit}
            except Exception as exc:
                out = {"ok": False, "error": type(exc).__name__}
        else:
            try:
                response, source, end, hit = resolver.resolve_recursive(
                    bytes.fromhex(op["query"]), converted,
                    op["now"], op["limit"])
                out = {"ok": True, "response": response.hex(),
                       "source": source, "end": end, "hit": hit}
            except Exception as exc:
                out = {"ok": False, "error": type(exc).__name__}
        items.append({"in": op, "out": out, "stats": resolver.stats()})
    result = json.dumps({"version": 1, "ops": items},
                        ensure_ascii=True, separators=(",", ":")) + "\n"
    if expected is not None and result != expected:
        raise ReplayError("output does not match expected")
    return result


def _parse_policy_network(value):
    """把规则 client 解析为 ("*", None) 或 ("net", 网段对象)。

    "*" 匹配任意客户端；否则须为 strict 解析成功且与规范文本逐字一致的
    IPv4/IPv6 CIDR（主机位不得置位）。非法抛 PolicyError。
    """
    if value == "*":
        return "*", None
    try:
        net = ipaddress.ip_network(value, strict=True)
    except (ValueError, TypeError):
        raise PolicyError(
            "client must be * or canonical IPv4/IPv6 CIDR") from None
    if str(net) != value:
        raise PolicyError("client must be canonical IPv4/IPv6 CIDR")
    return "net", net


def _validate_policy_rules(rules):
    """完整校验授权规则，返回按原序排列的规范化列表，不修改入参。

    每项为 (网段类, 网段或 None, 名称, 类型或 None, 是否 allow)：
    网段类为 "*" 或 "net"；名称为 "*" 或已规范化的小写绝对名。
    类型错抛 TypeError；规则数、键序或字段值错抛 PolicyError。
    """
    if not isinstance(rules, list):
        raise TypeError("rules must be list")
    if not 0 <= len(rules) <= _MAX_POLICY_RULES:
        raise PolicyError("rules must contain 0..256 items")
    checked = []
    for rule in rules:
        if not isinstance(rule, dict):
            raise TypeError("rule must be dict")
        if list(rule.keys()) != _POLICY_RULE_KEYS:
            raise PolicyError("rule keys must be client,name,type,action")
        client = rule["client"]
        name = rule["name"]
        qtype = rule["type"]
        action = rule["action"]
        if not isinstance(client, str):
            raise TypeError("client must be str")
        if not isinstance(name, str):
            raise TypeError("name must be str")
        if qtype is not None:
            _check_int(qtype, "type")
        if not isinstance(action, str):
            raise TypeError("action must be str")
        net_kind, net = _parse_policy_network(client)
        if name != "*":
            try:
                normalized = _labels_to_name(_normalize_name(name))
            except RecordError as exc:
                raise PolicyError(str(exc)) from None
            if normalized != name:
                raise PolicyError("name must be a lowercase absolute name")
        if qtype is not None and not 0 <= qtype <= 0xFFFF:
            raise PolicyError("type out of range")
        if action not in _POLICY_ACTIONS:
            raise PolicyError("action must be allow or deny")
        checked.append((net_kind, net, name, qtype, action == "allow"))
    return checked


def authorize(query: bytes, client: str, rules: list,
              default: str = "deny") -> bool:
    """按规则原序判定 query 是否放行，返回是否 allow。

    query 须为 decode_query 可解码的单问题非应答报文；client 须为字面
    IP 地址。rules 为 0..256 项，项键序仅 client,name,type,action：
    client 为 "*" 或规范 IPv4/IPv6 CIDR，name 为 "*" 或小写绝对名，
    type 为 None 或 0..65535 的非 bool 整数，action/default 为
    "allow"/"deny"。按原序取首个网段、名称、类型均匹配项，无匹配取
    default。任一入参或字段类型错抛 TypeError；规则数量、键序或字段
    值错（含 client 非 IP 地址）抛 PolicyError；query 解码错误沿用
    decode_query，非单问题或 QR 置位抛 EncodeError。规则全部校验通过
    后才解码 query 并匹配；不修改任何入参。
    """
    if not isinstance(query, bytes):
        raise TypeError("query must be bytes")
    if not isinstance(client, str):
        raise TypeError("client must be str")
    if not isinstance(default, str):
        raise TypeError("default must be str")
    if default not in _POLICY_ACTIONS:
        raise PolicyError("default must be allow or deny")
    # 规则须在任何匹配（含 query 解码）之前整体校验通过。
    checked = _validate_policy_rules(rules)
    try:
        addr = ipaddress.ip_address(client)
    except (ValueError, TypeError):
        raise PolicyError("client must be an IP address") from None
    msg = decode_query(query)
    if msg["flags"] & _FLAG_QR:
        raise EncodeError("query has QR set")
    if len(msg["questions"]) != 1:
        raise EncodeError("query must contain exactly one question")
    qname = msg["questions"][0]["name"]
    qtype = msg["questions"][0]["type"]
    for net_kind, net, name, rule_type, is_allow in checked:
        if net_kind == "net" and addr not in net:
            continue
        if name != "*" and name != qname:
            continue
        if rule_type is not None and rule_type != qtype:
            continue
        return is_allow
    return default == "allow"


def _validate_rate_rules(rules):
    """完整校验限流规则，返回按原序排列的规范化列表，不修改入参。

    每项为 (网段类, 网段或 None, 名称, 类型或 None, 窗长, 查询配额,
    响应配额)；网段与名称格式同授权规则。类型错抛 TypeError；
    规则数、键序或字段值错抛 PolicyError。
    """
    if not isinstance(rules, list):
        raise TypeError("rules must be list")
    if not 0 <= len(rules) <= _MAX_POLICY_RULES:
        raise PolicyError("rules must contain 0..256 items")
    checked = []
    for rule in rules:
        if not isinstance(rule, dict):
            raise TypeError("rule must be dict")
        if list(rule.keys()) != _RATE_RULE_KEYS:
            raise PolicyError(
                "rule keys must be client,name,type,window,query,response")
        client = rule["client"]
        name = rule["name"]
        qtype = rule["type"]
        window = rule["window"]
        query_quota = rule["query"]
        response_quota = rule["response"]
        if not isinstance(client, str):
            raise TypeError("client must be str")
        if not isinstance(name, str):
            raise TypeError("name must be str")
        if qtype is not None:
            _check_int(qtype, "type")
        _check_int(window, "window")
        _check_int(query_quota, "query")
        _check_int(response_quota, "response")
        net_kind, net = _parse_policy_network(client)
        if name != "*":
            try:
                normalized = _labels_to_name(_normalize_name(name))
            except RecordError as exc:
                raise PolicyError(str(exc)) from None
            if normalized != name:
                raise PolicyError("name must be a lowercase absolute name")
        if qtype is not None and not 0 <= qtype <= 0xFFFF:
            raise PolicyError("type out of range")
        if not _MIN_RATE_WINDOW <= window <= _MAX_RATE_WINDOW:
            raise PolicyError("window out of range")
        if not 0 <= query_quota <= _MAX_RATE_QUOTA:
            raise PolicyError("query out of range")
        if not 0 <= response_quota <= _MAX_RATE_QUOTA:
            raise PolicyError("response out of range")
        checked.append((net_kind, net, name, qtype, window,
                        query_quota, response_quota))
    return checked


class RateLimiter:
    """确定性固定窗查询/响应限流器。

    rules 为 0..256 项，项键序仅 client,name,type,window,query,response：
    前三项格式同 authorize 规则（client 为 "*" 或规范 IPv4/IPv6 CIDR，
    name 为 "*" 或小写绝对名，type 为 None 或 0..65535 非 bool 整数），
    window 为 1..3600、query/response 配额为 0..65535 的非 bool 整数。
    allow(query, client, now, kind="query") 按原序取首个网段、名称、
    类型均匹配项；无匹配返回 (True, -1)。命中按 now // window 划分
    固定窗，键为 (规则序号, IP, qname, qtype, kind, 窗号)：窗内未达
    对应配额则计数加一并返回 (True, 剩余配额)，已达配额则不加并返回
    (False, 0)。每次调用先删除当前已过期窗；计数表满 4096 键时淘汰
    (窗截止时刻, 创建序) 最小项。now 须为非负且不回退的 int，否则
    抛 CacheError；kind 仅 "query"/"response"，client 须为字面 IP
    地址，否则抛 PolicyError。query 沿用 decode_query，非单问题或
    QR 置位抛 EncodeError。规则在构造时一次性校验；任何失败都不
    改变计数状态与入参。

    stats(reset=False) 返回固定键序 query,response,expired,evicted,
    keys 的紧凑 ASCII JSON（末尾一个换行）：query/response 各为键序
    allow,deny,unmatched 的对象，值为非负十进制整数。统计仅在 allow
    成功返回后原子提交：匹配规则返回 True/False 分别增加对应 kind 的
    allow/deny；无匹配仅增加 unmatched；expired/evicted 分别累加本次
    实际删除的过期键数、容量淘汰键数；keys 为当前计数键数。配额 0 的
    拒绝不建键，配额耗尽的拒绝保留原键。allow 抛任何既有异常时，计数
    表、最后时钟与统计均不变。reset 非 bool 抛 TypeError 且无变化；
    False 重复读取不改状态；True 先返回重置前快照，再清零六个分类计数
    及 expired、evicted，保留规则、计数键、创建序和最后时钟，因此 keys
    不清零。相同初态和调用序列须逐字节相同。
    """

    def __init__(self, rules: list):
        # 校验即构造全新的不可变元组列表，与外部对入参的后续改动隔离。
        self._rules = _validate_rate_rules(rules)
        # 计数键 -> [窗起始, 窗截止, 计数, 创建序]
        self._counts = {}
        self._serial = 0  # 创建序：随新窗计数项从 0 递增
        self._last_now = None  # 上次成功 allow 的时钟值
        # 统计：各 kind 的 allow/deny/unmatched，以及本次重置周期内
        # 实际删除的过期键数与容量淘汰键数。仅在 allow 成功返回后提交。
        self._stat = {
            "query": {"allow": 0, "deny": 0, "unmatched": 0},
            "response": {"allow": 0, "deny": 0, "unmatched": 0},
            "expired": 0,
            "evicted": 0,
        }

    def allow(self, query: bytes, client: str, now: int,
              kind: str = "query") -> tuple[bool, int]:
        if not isinstance(query, bytes):
            raise TypeError("query must be bytes")
        if not isinstance(client, str):
            raise TypeError("client must be str")
        if not isinstance(now, int) or isinstance(now, bool):
            raise TypeError("now must be int")
        if not isinstance(kind, str):
            raise TypeError("kind must be str")
        if kind not in _RATE_KINDS:
            raise PolicyError("kind must be query or response")
        if now < 0 or (self._last_now is not None and now < self._last_now):
            raise CacheError("now must be non-negative and monotonic")
        # 规则须在任何匹配（含 query 解码）之前整体可用，client 与 query
        # 的校验顺序同 authorize：先地址、后解码。
        try:
            addr = ipaddress.ip_address(client)
        except (ValueError, TypeError):
            raise PolicyError("client must be an IP address") from None
        msg = decode_query(query)
        if msg["flags"] & _FLAG_QR:
            raise EncodeError("query has QR set")
        if len(msg["questions"]) != 1:
            raise EncodeError("query must contain exactly one question")
        qname = msg["questions"][0]["name"]
        qtype = msg["questions"][0]["type"]
        matched = None
        for index, (net_kind, net, name, rule_type, window,
                    query_quota, response_quota) in enumerate(self._rules):
            if net_kind == "net" and addr not in net:
                continue
            if name != "*" and name != qname:
                continue
            if rule_type is not None and rule_type != qtype:
                continue
            quota = query_quota if kind == "query" else response_quota
            matched = (index, window, quota)
            break
        if matched is None:
            # 统计随成功返回原子提交：无匹配仅增加对应 kind 的 unmatched。
            self._stat[kind]["unmatched"] += 1
            self._last_now = now
            return True, -1
        # 先删除当前已过期窗（截止时刻 <= now），再处理命中键。
        # 删除数先记为本次局部计数，待成功返回时与分类计数一并提交。
        expired = 0
        for dead in [key for key, value in self._counts.items()
                     if value[1] <= now]:
            del self._counts[dead]
            expired += 1
        index, window, quota = matched
        if quota == 0:
            # 配额为 0：一律拒绝，不创建计数项也不触发淘汰。
            self._stat[kind]["deny"] += 1
            self._stat["expired"] += expired
            self._last_now = now
            return False, 0
        bucket = now // window
        key = (index, str(addr), qname, qtype, kind, bucket)
        entry = self._counts.get(key)
        evicted = 0
        if entry is None:
            # 计数表满 4096 键时淘汰 (截止, 创建序) 最小项后再插入。
            if len(self._counts) >= _RATE_TABLE_CAPACITY:
                oldest = min(self._counts,
                             key=lambda k: (self._counts[k][1],
                                            self._counts[k][3]))
                del self._counts[oldest]
                evicted += 1
            self._counts[key] = [bucket * window, (bucket + 1) * window,
                                 0, self._serial]
            self._serial += 1
            entry = self._counts[key]
        if entry[2] >= quota:
            # 配额耗尽的拒绝保留原键，仅提交 deny 与过期/淘汰删除数。
            self._stat[kind]["deny"] += 1
            self._stat["expired"] += expired
            self._stat["evicted"] += evicted
            self._last_now = now
            return False, 0
        entry[2] += 1
        remaining = quota - entry[2]
        self._stat[kind]["allow"] += 1
        self._stat["expired"] += expired
        self._stat["evicted"] += evicted
        self._last_now = now
        return True, remaining

    def stats(self, reset: bool = False) -> str:
        """返回统计的固定键序紧凑 ASCII JSON（末尾一个换行）。

        顶层键序 query,response,expired,evicted,keys；query/response 为
        键序 allow,deny,unmatched 的对象，值为非负十进制整数；expired、
        evicted 为上次重置后实际删除的过期键数、容量淘汰键数；keys 为
        当前计数键数。统计仅在 allow 成功返回后原子提交，allow 抛异常
        不改变统计。reset 非 bool 抛 TypeError 且无变化；False 重复读取
        不改状态；True 先返回重置前快照，再清零六个分类计数及 expired、
        evicted，保留规则、计数键、创建序和最后时钟，因此 keys 不清零。
        """
        if not isinstance(reset, bool):
            raise TypeError("reset must be bool")
        stat = self._stat
        text = (
            '{"query":{"allow":' + str(stat["query"]["allow"])
            + ',"deny":' + str(stat["query"]["deny"])
            + ',"unmatched":' + str(stat["query"]["unmatched"]) + "}"
            + ',"response":{"allow":' + str(stat["response"]["allow"])
            + ',"deny":' + str(stat["response"]["deny"])
            + ',"unmatched":' + str(stat["response"]["unmatched"]) + "}"
            + ',"expired":' + str(stat["expired"])
            + ',"evicted":' + str(stat["evicted"])
            + ',"keys":' + str(len(self._counts)) + "}\n"
        )
        if reset:
            # 先返回重置前快照，再清零计数；计数键、创建序、规则、时钟
            # 均保留。
            for kind in _RATE_KINDS:
                stat[kind]["allow"] = 0
                stat[kind]["deny"] = 0
                stat[kind]["unmatched"] = 0
            stat["expired"] = 0
            stat["evicted"] = 0
        return text


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
