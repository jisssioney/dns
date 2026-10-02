"""DNS 问题报文解码与确定性权威应答编码（仅标准库、离线）。

名称八位组：公开名称统一为绝对名文本，未转义点分隔标签；除安全 ASCII
字母、数字、下划线、连字符外，文本输入接受反斜杠后恰三位十进制的
"\\DDD"（000..255）以及 "\\." 与 "\\\\" 两种简写。标签解码后为
1..63 字节、整名线格式不超过 255 字节；规范输出把 ASCII 大写折为小写，
字母、数字、下划线、连字符原样保留，其余八位组统一写三位十进制转义，
根名仍为 "."。解码后首标签恰为单字节 0x2A 的 owner 沿用通配语义；
线格式等价（仅 ASCII 字母大小写或合法转义拼写不同）的名称在 answer、
缓存、解析器、授权与限流器中视为同一键。主文件与区域配置的导入/导出/
迁移覆盖 owner 及 NS、CNAME、MX、SOA、SRV、NAPTR、NSEC、RRSIG 中
嵌入的名称，导出取唯一规范拼写。

公开接口：
- MessageError: 报文格式错误（ValueError 子类）。
- EDNSError: EDNS 查询截断、尾随、名字非法、AN/NS 非空或 AR/OPT
  （含 OPT 选项 TLV）非法、模型含 OPT（MessageError 子类）。
- CookieError: EDNS COOKIE 查询非法：OPT 版本非 0、COOKIE 缺失或
  不唯一、data 长度不符，或 secret 长度非 16..64、client 非合法
  IPv4/IPv6（EDNSError 子类）。
- EDEError: EDNS EDE 查询非法：OPT 缺失或版本非 0（EDNSError 子类）。
- ZoneError: zone 模型非法（ValueError 子类）。
- RecordError: 记录模型不符合编码要求（ValueError 子类）。
- EncodeError: 应答无法在给定限制内编码（ValueError 子类）。
- CNAMEError: CNAME 链出现名称重复或超过 16 跳（ValueError 子类）。
- CacheError: 缓存时钟非单调等缓存语义错误（ValueError 子类）。
- ConfigError: 配置文本解析或结构非法（ValueError 子类）。
- ReplayError: 回放操作序列非法或回放记录与期望不符（ValueError 子类）。
- PolicyError: 授权规则数量、键序或字段值非法（ValueError 子类）。
- decode_query(data: bytes) -> dict: 解码 DNS 查询报文。
- encode_response(query: bytes, model: dict) -> bytes: 编码权威应答报文；
  超限或区段计数超 16 位时按 RRset 原子截断（规范化 owner、数值 type、
  class 同一集合整组删除，键不含 TTL/rdata；ar、ns、an 优先级，置 TC）。
- edns(query: bytes, model: dict, rcode: int = 0, options: list | None = None)
  -> bytes: 编码可含 OPT（查询 RDATA 按选项 TLV 解析）的 EDNS 应答报文；
  OPT 版本 1..255 时返回 BADVERS 版本协商应答。
- edns_cookie(query: bytes, model: dict, secret: bytes, client: str,
  rcode: int = 0) -> bytes: 编码 EDNS(0) COOKIE（选项码 10）应答；查询须
  版本 0 且恰有一个 COOKIE，服务端值缺失或匹配按 model 应答，不匹配清空
  三段并以扩展 RCODE 23 应答，非法查询/参数抛 CookieError。
- edns_padded(query: bytes, model: dict, block: int = 128, rcode: int = 0)
  -> bytes: 编码 EDNS(0) Padding（选项码 12）应答；查询须恰有一个 OPT，
  版本 0 时 Padding 至多一项且 data 全零，应答 OPT 仅含一个 Padding
  TLV，按 ar、ns、an 的 RRset 整组淘汰枚举候选取首个
  B+(-B)%block≤min(limit, CLASS) 者填零；版本 1..255 在全部参数校验后
  返回 BADVERS 且不填充。
- edns_ede(query: bytes, model: dict, info_code: int, text: str = "",
  rcode: int = 0) -> bytes: 编码 EDNS(0) EDE（选项码 15）应答；查询须
  恰含一个版本 0 的 OPT（缺失或版本非 0 抛 EDEError），查询选项不
  回显，应答 OPT 仅含一个 EDE TLV（网络序 uint16 info_code 后接
  text 的 UTF-8 字节，可为空）。
- answer(query: bytes, zone: dict, limit: int = 512) -> bytes: 按 zone 应答查询；
  普通与 EDNS 权威应答均为计划中的 ANSWER、AUTHORITY 按现有顺序观察 NS、
  MX、SRV，取 NS 整个 rdata、MX 跳过两字节 preference、SRV 跳过六字节
  priority/weight/port 后的嵌入名为目标，目标须位于 origin 内且为非根全名，
  每个规范化目标只处理一次（按其在 ANSWER 后 AUTHORITY 首次出现的顺序），
  把区域中 owner 与目标精确相等的 A/AAAA 按区域原序作为地址附加段（不用
  通配合成、不追随目标处的 CNAME，重复记录不归并）；普通应答置于附加段，
  EDNS 应答置于唯一 OPT 之前（OPT 仍为末项）；附加 RRset 在 RRset 原子
  截断中先于授权段、回答段淘汰并置 TC，OPT 不淘汰；域外/根/无精确地址
  目标及不完整嵌入名不出附加项，RCODE、AA、ANSWER、AUTHORITY 不变。
- import_zone(text: str) -> dict: 导入 v0/v1/v2 配置文本为规范化 zone。
- export_zone(zone: dict) -> str: 把 zone 导出为 v1 配置文本。
- import_master(text: str) -> dict: 导入确定性主文件文本（首行
  "$ORIGIN 绝对名"，其后 1..65535 行 "owner ttl IN TYPE rdata"，
  TYPE 为 A/NS/CNAME/MX/TXT/AAAA/SRV/NAPTR/DS/RRSIG/NSEC/DNSKEY/CDS/
  CDNSKEY/CAA/SOA、
  class=1、rdata 为 bytes；
  末尾允许无换行或一个换行）为规范化 zone。
- export_master(zone: dict) -> str: 把仅含
  A/NS/CNAME/MX/TXT/AAAA/SRV/NAPTR/DS/RRSIG/NSEC/DNSKEY/CDS/CDNSKEY/
  CAA/SOA、
  class=1 记录的 zone 按原序导出为确定性主文件文本（单空格、
  规范域名/IP/整数/Base64/十六进制摘要、末尾换行）。
- migrate_zone(text: str) -> str: 把 v0/v1/v2 配置文本完整校验、规范化
  并迁移为 v2 配置文本（紧凑 ASCII JSON，末尾单换行）。
- migrate_zones(text: str) -> str: 把 schema=0/1 的区域历史配置文本
  完整校验并迁移为 schema=1 文本（旧格式历史限 1..256 项，先校验全部
  快照再仅留 revision 最大的 32 项并把 zone 转成 v2，version 不变；
  紧凑 ASCII JSON，末尾单换行）。
- migrate_state(text: str) -> str: 把 v0/v1/v2 整解析器状态文本完整
  校验并迁移为规范 v2 文本（v0 顶层键序 v,zones,rec、无 stats/ru，
  迁移补零值统计（c[1] 等于 rec.items 长度）与零值 ru；v1 键序
  v,zones,rec,stats、无 ru，补零值 ru；v2 键序 v,zones,rec,stats,ru，
  完整校验后规范化重写；ru 键序 l,t，l 含 16 个长度 7 的非负非 bool
  整数数组，t 长度 7 且逐列等于 l 之和；紧凑 ASCII JSON、r 六位小数、
  末尾单换行，最多 16777216 字节）。
- PositiveCache(zone): 容量 256 的正/负答案缓存，resolve(query, now, limit=512)
  返回 (应答报文, 是否命中)；resolve_edns(query, now, limit=65535) 处理
  含一个 OPT 的单问题查询，与 resolve 共享条目、键、FIFO、时钟与统计，
  应答末项回显 OPT（OPT 版本非 0 时直接返回 BADVERS，先于时钟回退
  判断且不触缓存）；版本 0 查询至多携带一个 ECS（选项码 8），ECS
  合法时缓存按 (family,source,address) 分区、应答 OPT 回写码 8
  （scope=source），非法 ECS 在访问缓存前抛 EDNSError；
  stats(reset=False) 返回键序 h,m,x,k 的
  紧凑 ASCII JSON（末尾换行），reset=True 先返回快照再清零 h,m,x。
- UpstreamError: 上游转发未获得可用应答（RuntimeError 子类）。
- UpstreamTimeout: 上游转发全部超时（UpstreamError 子类）。
- TransferError: 区传送差异或全量记录超过 limit（ValueError 子类）。
- forward(query, plan, now, timeout=5): 按 plan 顺序模拟上游转发，
  成功返回 (应答报文, 上游名, 结束时刻)。
- forward_edns(query, plan, now, timeout, max_len): forward 的 EDNS
  变体，时序、attempts、时钟累加与耗尽异常同 forward；候选应答除问题
  一致外还须恰含一个合法末项 OPT 且总长度不超 max_len，否则按不可用
  应答继续尝试。
- migrate_forward(text: str) -> str: 把 v0/v1 上游配置文本完整校验、
  规范化并迁移为 v1 配置文本（v0 顶层键序 v,timeout,plan，迁移补
  attempts=2；v1 键序 v,timeout,attempts,plan；timeout 1..60、
  attempts 1..2，均为非 bool 整数；plan 含 1..16 项，项键序
  name,events，events 含 0..2 项，项键序 delay,reply，reply 为 null
  或解码后不超 65535 字节的偶长小写十六进制，events 多于 attempts
  抛 ConfigError；紧凑 ASCII JSON、整数十进制、十六进制小写、末尾
  单换行；输入限 1048576 码点；规范 v1 再次迁移逐字节不变）。
- Resolver(zone, plan, timeout=5): 权威缓存与上游转发组合的解析器，
  resolve(query, now, limit=512) 返回 (应答报文, 来源, 结束时刻, 是否命中缓存)；
  resolve_edns(query, now, limit=65535) 处理恰含一个合法末项 OPT 的
  单问题 EDNS 查询，返回与 resolve 同形的四元组；报文、OPT、ECS、
  now、limit 的范围及异常类型与 PositiveCache.resolve_edns 一致，
  有效长度上限取 min(limit, OPT CLASS)；OPT 版本 1..255 在访问区域、
  缓存、时钟、统计与上游前直接返回 (BADVERS, "edns", now, False)；
  版本 0 区内查询沿用权威正/负缓存与 ECS 分区（无 ECS 时输出与现有
  权威 EDNS 逐字节一致，有 ECS 时仅回写规范 ECS），来源
  "authority"；区外查询按当前上游顺序、attempts 与 timeout 转发，
  候选应答还须问题一致、恰含一个合法末项 OPT 且不超有效上限，否则
  按不可用应答继续尝试，全部超时抛 UpstreamTimeout、存在非超时失败
  但无可用应答抛 UpstreamError，成功时来源为上游名、结束时刻累加
  事件延迟、命中恒为 False；区内按 authority 口径、区外成功或耗尽
  按 resolve 口径原子更新统计，BADVERS 与任何错误均不改变缓存、
  FIFO、时钟或统计；
  resolve_authorized(query, client, rules, now, limit=512, default="deny")
  先按授权规则判定再解析，放行行为同 resolve，拒绝返回
  (拒绝应答, "policy", now, False)（flags=0x8400|(flags&0x7910)|5，
  QDCOUNT=1，其余计数为 0，超 limit 抛 EncodeError），拒绝与失败均
  不改变区域、缓存、FIFO、时钟或统计；
  resolve_limited(query, client, policy, limiter, now, limit=512,
  default="deny") 组合 ACL、每客户端限流与解析，返回五元组
  (应答报文, 来源, 结束时刻, 是否命中, 余量)；limiter 非 RateLimiter
  抛 TypeError，其余校验与异常依次沿用 authorize、resolve、
  limiter.allow；授权拒绝复用 resolve_authorized 应答且不调用
  limiter/上游，后四值为 "policy",now,False,-1；授权后仅调用一次
  limiter.allow(...,"query")，限流拒绝不解析、不转发，返回同形
  REFUSED 报文及 "rate",now,False,0，仅提交 limiter 的 deny、清理、
  时钟与统计，拒绝报文超 limit 抛 EncodeError 且解析器与 limiter 均
  不变；放行调用 resolve 并追加余量，resolve 异常仍耗额度；
  resolve_rated(query, client, policy, limiter, now, limit=512,
  default="deny", truncate=True) 在 resolve_limited 的授权与查询
  限流之后追加响应限流，返回六元组 (应答报文或 None, 来源, 结束
  时刻, 是否命中, 查询余量, 响应余量)；truncate 非 bool 抛
  TypeError，解析成功后以应答与结束时刻调用一次 limiter.respond：
  放行保留原来源并返回两维余量，拒绝时来源为 "response-rate"、
  响应余量 0，truncate 真返回 TC 截断报文、假返回 None；
  rated_stats(reset=False) 返回 resolve_rated 的确定性统计，为
  仅含键序 o,e,l 的紧凑 ASCII JSON（末尾单换行），值为非负十进制
  整数数组：o 四项依次计 policy 拒绝、query-rate 拒绝、
  response-rate 拒绝与响应放行；e 两项依次计查询放行后 resolve
  异常、解析成功后 limiter.respond 异常（异常仍传播，原子计一次）；
  l 四项按实际上游耗时 0、1..timeout、timeout+1..2*timeout、
  >2*timeout 分桶，权威、缓存及未访问上游不计；前置参数、授权、
  查询限流或拒绝报文编码异常不计；reset 非 bool 抛 TypeError 且
  状态不变，True 先返回旧快照再清零十项计数，其余状态与 stats
  不变；
  resolve_recursive(query, levels, now, limit=512, stale_window=0) 按
  1–16 层转介计划递归解析域外查询，返回 (应答报文, 来源, 结束时刻,
  是否命中递归缓存)；stale_window 为可选非 bool 整数（0..86400，默认
  0），仅域外查询在 query/levels/now/limit 校验后、查递归缓存前校验，
  默认与显式 0 同既有行为逐字节兼容；命中已过期正答案、NXDOMAIN 或
  NODATA 不立即返回或删除，照常完成递归层与上游尝试，仅当结果原本应为
  UpstreamTimeout/UpstreamError、窗口大于 0 且耗尽时刻减条目到期时刻
  不超过窗口时返回 (陈旧应答, "stale", 耗尽时刻, True)（陈旧正答案
  ANSWER TTL 全 0，陈旧负答案仅把授权段 SOA TTL 置 0），不刷新/删除/
  重写过期项、不改 FIFO，按原耗尽类别计未中/到期/上游失败/耗时而不增
  命中计数并把最后成功时刻推进到耗尽时刻，窗口外抛原异常，陈旧编码失败
  抛 EncodeError 且全部状态不变；
  stats() 返回只读统计的紧凑 ASCII JSON（键序 h,m,x,u,c,l,r，末尾换行）；
  upstream_stats(reset=False) 返回构造 plan 直转的逐上游统计，为顶层
  键序仅 p,t 的紧凑 ASCII JSON（末尾单换行）：p 按 plan 位置列键序
  i,n,a,s,to,e,bad,ms 的对象（重名不合并，i 为从 0 起的序号，n 为
  原上游名，其余为非负整数），t 省略 i、n 并为逐项和；仅经 resolve
  或 resolve_edns 的直转在成功或耗尽（UpstreamTimeout/UpstreamError）
  时原子提交，权威、缓存与 resolve_recursive 的 levels 不计；
  reset=True 先返回旧快照再清零上述计数；
  recursive_upstream_stats(reset=False) 返回 resolve_recursive 逐层
  转发的按深度统计，为顶层键序仅 l,t 的紧凑 ASCII JSON（末尾单换行）：
  l 固定含 16 个数组，索引对应深度 0..15，每项为七个非负整数
  [a,r,s,to,e,bad,ms]（尝试数、接受的非末层转介数、kind=1/2/3 终态
  数、delay>timeout 数、reply=None 数、末层 kind=0 数、模拟耗时累计；
  超时仅给 ms 加 timeout，其余事件加 delay；每上游仅取前 2 事件，转介
  或终态后的事件不计），t 为同顺序七整数数组且逐项等于 l 之和；仅域外
  递归缓存未命中且 levels 全量校验通过后暂存，成功返回、耗尽抛
  UpstreamTimeout/UpstreamError 或返回陈旧应答时原子提交已访问事件，
  查询、levels、stale_window、编码、缓存写入或其他异常以及权威、缓存
  命中均不提交；reset 非 bool 抛 TypeError 且无变化，False 只读，
  True 先返回旧快照再清零本统计，缓存、时钟、区域、plan 及其他统计
  不变；
  dump_forward() 导出当前上游转发配置，返回键序 version,config 的
  紧凑 ASCII JSON（末尾单换行），version 从 0 起，config 为
  migrate_forward 的 v1 对象（初始 attempts=2），只读；
  reload_forward(text, expected) 带版本检查的原子上游配置热加载，
  返回键序 version,result 的紧凑 ASCII JSON 报告（末尾换行），
  result 为 "applied"、"unchanged" 或 "conflict"；applied 原子替换
  timeout、attempts 与 plan 并加一版本，upstream_stats 按新 plan
  清零，缓存、时钟与其他统计保留；仅 expected 匹配且未抛异常的
  applied/unchanged 按提交序记入 forward_audit；
  初始上游配置为版本 0，applied 时按新版本号归档快照，历史容量
  32、超量淘汰最小版本号且版本号不复用；
  forward_versions() 只读返回保留的上游配置版本号（严格升序元组）；
  forward_audit() 只读导出已提交变更的提交序审计（紧凑 ASCII JSON、
  末尾换行）：顶层键序仅 v,o（v=1），o 至多 4096 项、项键序仅
  k,x,e,r,a（k 取 l/r，x 为规范化配置文本或非负目标版本，e、a 为
  前后版本，r 取 applied/unchanged）；仅匹配且无异常的 reload/
  rollback 及成功 replay 内各步入账，冲突、异常与整批失败不入账；
  输出超 16777216 字节时淘汰最早项，其文本可直接重放；
  rollback_forward(target, expected) 带版本检查的原子上游配置回滚，
  返回键序 version,result,target 的紧凑 ASCII JSON 报告（末尾
  换行），result 为 "applied"、"unchanged" 或 "conflict"；target
  未保留抛 ConfigError，applied 恢复 timeout、attempts 与 plan 并
  加一版本，upstream_stats 按恢复 plan 清零，其余状态保留；
  replay_forward(log, expected) 原子重放上游配置操作序列，返回键序
  v,r 的紧凑 ASCII JSON 报告（末尾换行）：log 限 1048576 码点
  ASCII JSON，顶层键序 v,o（v=1），o 含 0..4096 项（空 o 合法），
  兼容键序仅 k,x,e 的旧三键项与键序仅 k,x,e,r,a 的五键审计项
  （可混用：k="l" 时 x 为 migrate_forward 配置文本，k="r" 时 x 为
  非负非 bool 目标版本，e 为非负非 bool 步骤前预期版本，r 为该步
  实际结果、a 为步骤后版本）；版本不符不解析 log 并报告 conflict，
  相符时先规范化全部项，再以副本推演配置、历史与版本，每步调用前
  核对 e、调用后核对五键项 r、a（不符抛 ReplayError），目标缺失等
  异常原样传播，任一失败不提交、不入账，全部成功后一次原子提交
  配置、版本、32 项历史、直转统计与审计队列，r 为出现 applied 则
  "applied" 否则 "unchanged"，其余状态不变，同初态同序列逐字节
  一致；
  cache_stats(now, reset=False) 返回缓存水位快照的紧凑 ASCII JSON
  （顶层键序仅 a,r,x,v，末尾换行）：a、r（权威、递归）键序均为
  p,nx,nd,total,capacity,ttl，ttl 为同顺序三类最小剩余 TTL（无条目
  为 -1），x、v 为 [权威,递归] 的成功解析到期删除数与 FIFO 淘汰数；
  reset=True 先返回旧快照再清零 x、v，保留缓存、FIFO、时钟及统计；
  dump_rec(now) 把此刻仍有效的递归缓存按 FIFO 插入次序导出为
  确定性配置文本（顶层键序 v,clock,items，v=1、clock=now；项键序
  k,q,t,c,rr，rr 元素键序 n,t,c,ttl,d；紧凑 ASCII JSON、整数十进制、
  末尾单换行），只读且同状态同参逐字节相同；
  load_rec(text, now) 校验递归缓存配置文本，按 now-clock 衰减并
  丢弃到期项后原子替换递归正负缓存与 FIFO、置成功时刻为 now，
  返回保留条目数，任何失败均无副作用；
  reload_zone(text) 原子换区并返回从 0 递增的修订号（stats() 不变，
  c[0] 于下次解析提交时同步）；
  reload_zone_tx(text, expected) 带修订号检查的原子换区事务，返回
  键序 version,result 的紧凑 ASCII JSON 报告（末尾换行），result 为
  "applied"、"unchanged" 或 "conflict"，修订号与 reload_zone 共用；
  reload_zone_serial_tx(text, expected, force=False) 带修订号检查与
  SOA 序列号比较的原子换区事务，返回键序 version,result,serial 的
  紧凑 ASCII JSON 报告（末尾换行），result 为 "applied"、"unchanged"、
  "stale"、"ambiguous" 或 "conflict"；
  构造时规范化初始区域存为修订 0，成功换区按新修订号保存区域深拷贝，
  历史容量 32、超量淘汰最小修订号且号码不复用；
  rollback_zone_tx(target, expected) 带修订号检查的原子回滚事务，返回
  键序 version,result,target 的紧凑 ASCII JSON 报告（末尾换行），
  result 为 "applied"、"unchanged"、"missing" 或 "conflict"；
  update_zone_tx(changes, serial, expected) 带修订号与 SOA 序列号检查
  的原子区域更新事务，返回键序 version,result,serial 的紧凑 ASCII
  JSON 报告（末尾换行），result 为 "applied"、"unchanged"、"stale"
  或 "conflict"，修订号与 reload_zone 共用；
  transfer_zone(from_serial, limit=65535) 只读返回键序
  version,serial,mode,delete,add 的紧凑 ASCII JSON（末尾换行），
  mode 为 "none"、"ixfr" 或 "axfr"，超限或序列号比较歧义抛
  TransferError；
  dump_zones() 把区域修订历史导出为 schema=1 的确定性配置文本
  （顶层键序 schema,version,history，history 按 revision 升序，
  项键序 revision,zone，zone 为 migrate_zone 的 v2 配置对象；
  紧凑 ASCII JSON，末尾单换行），只读且同状态逐字节相同；
  load_zones(text, plan, timeout=5) 类方法先校验全部快照再从配置
  文本恢复实例（schema 0/1，schema=0 旧格式历史限 1..256 项仅留
  revision 最大的 32 项，zone 接受 v0/v1/v2），以末项区域为当前
  区并恢复历史与修订号（后续成功变更从 version+1 继续），新实例
  缓存为空、时钟未设、统计清零；
  save_zones(path) 把 dump_zones() 字节写入同目录临时文件，fsync 后
  以 os.replace 原子替换，返回写入字节数，失败保留旧文件、删除临时
  文件且解析器不变；
  reload_zones_file(path, expected) 带修订号检查地从区域文件校验整份
  快照（schema 0/1，旧格式规则同 load_zones）并原子换区，返回键序
  version,result 的紧凑 ASCII JSON 报告
  （末尾换行），path 非 str/空串/含 NUL 或 expected 非 int（含
  bool）/负分别抛 TypeError/ConfigError，冲突不读文件，文件缺失、
  I/O 错、超 16777216 字节或非 ASCII 分别抛 FileNotFoundError、
  OSError、ConfigError，内容不同时文件 version 须更大，result 为
  "applied"、"unchanged" 或 "conflict"；
  dump_state(now) 导出区域历史、递归缓存、统计与递归逐层上游统计的
  整解析器快照（顶层键序仅 v,zones,rec,stats,ru，v=2，前三者分别为
  dump_zones()、dump_rec(now)、stats() 的解码对象，ru 为
  recursive_upstream_stats(False) 的解码对象；stats.c[1] 固定等于
  rec.items 长度；紧凑 ASCII JSON、末尾单换行，最多 16777216 字节，
  超限抛 ConfigError），now 异常沿用 dump_rec 且只读；
  load_state(text, plan, now, timeout=5) 类方法接受 v0/v1/v2 文本，
  先经 migrate_state 完整校验并迁移为 v2 再恢复实例（zones 沿用
  load_zones，rec 沿用 load_rec 并按 now-rec.clock 衰减，stats 键序
  h,m,x,u,c,l,r、c[2]=256、c[1] 等于 rec.items 长度且加载后重算、
  r 等于按 h,m 重算的 6 位小数比值，ru 恢复递归逐层上游计数；
  v0 补零值统计与零值 ru，v1 补零值 ru），恢复区域历史、修订号、
  stats 计数、递归正负缓存、FIFO、最后成功时刻与 ru 计数，权威缓存
  为空，plan/timeout 取参数；text 非 str 或 now 非 int（含 bool）抛
  TypeError，text 超 16777216 码点、JSON、重复键、键序、未知 v 或
  交叉约束错抛 ConfigError，区域或 RR 语义错沿用 ZoneError、
  RecordError，余错沿用 load_zones、load_rec 及构造器，失败无实例。
- migrate_bundle(text: str) -> str: 把 v1/v2 重放封包完整校验并迁移为
  规范 v2 封包文本（紧凑 ASCII JSON、末尾单换行，最多 16777216 字节）。
  v1/v2 顶层键序均仅 v,state,forward,log,result；state 经 migrate_state
  完整校验规范化，三段经与 replay_bundle 相同的隔离恢复路径重放 log 且
  其输出须与 result 逐字节相同。v1 的 v=1、forward 为 migrate_forward
  的 v1 对象，迁为版本 0、单项历史（version=0、config=规范 v1）与空
  audit（{"v":1,"o":[]}）；v2 的 v=2、forward 为键序
  version,history,audit 的包装：version 为非负非 bool 整数；history 含
  1..32 个键序 version,config 的项，version 严格升序、末项等于
  version，config 为规范 v1 配置；audit 键序 v,o（v=1），o 至多 4096
  个键序 k,x,e,r,a 的项（k 取 l/r；applied 须 a=e+1、unchanged 须
  a=e；后一 e 须等于前一 a、末 a 须等于 version，首 e 可已淘汰；r.x 为
  0<=x<=e；k="l" 的 x 经 migrate_forward 规范化；保留版本核快照：
  applied 核 a、unchanged 核 e 的快照等于 x（r 项核 x 与 a/e 快照
  相同），淘汰项不核内容）。text 非 str 抛 TypeError；超长、非 ASCII、
  JSON、重复键、顶层键序、v、forward 包装结构/关联、log/result 结构或
  结果不符抛 ReplayError；state、forward 配置语义错误沿用
  migrate_state、migrate_forward，操作异常原样传播；规范 v2 再次迁移
  逐字节不变。
- Resolver.replay_bundle(text: str) -> tuple[Resolver, str]: 从重放封包
  恢复计划、缓存、时钟、统计、ru、上游配置历史与审计并原子重放（接受
  v1/v2）。封包为 ASCII JSON 对象，顶层键序仅
  v,state,forward,log,result：v=1 时 forward 为 migrate_forward 的 v1
  对象，以 state.rec.clock 调 load_state，plan、timeout、attempts 取
  forward 并把当前生效配置重建为唯一版本 0 历史（不产生 forward 版本
  与审计，故 rollback_forward(0,0) 报告 unchanged 且不改配置）；v=2
  时 forward 为 migrate_bundle 的 version,history,audit 包装，完整校验
  关联后当前生效配置取末项 config，并按包装恢复版本号、32 项内历史与
  提交序审计（dump_forward/forward_versions/forward_audit/
  rollback_forward 与导出时一致）。两种形态的 state、log、result 依次
  为 dump_state 的 v2 对象、export_log 的 v1 对象与 replay_log 成功
  结果对象；replay_log 的 expected 取 state 区域修订号，执行 log 所得
  文本须与 result 按键序生成的紧凑文本逐字节相同。text 非 str 抛
  TypeError；超 16777216 码点、非 ASCII、JSON、重复键、顶层键序、v、
  forward 包装结构/关联、log/result 结构或结果不符抛 ReplayError；
  state、forward 配置错误沿用 load_state、migrate_forward 异常，操作
  异常原样传播；隔离执行，失败不产生实例，成功返回解析器与该文本。
- Resolver.export_bundle(ops: list, now: int) -> str: 只读导出可由
  replay_bundle 隔离恢复并重放的重放封包（v2）。ops 沿用 export_log 协议，
  限 1..4096 项；起始时刻取最后成功结束时刻，未设为 0。ops 非 list 或
  now 非 int（bool 非法）抛 TypeError；now 为负或早于起始时刻抛
  CacheError；ops 非法或结果超 16777216 字节抛 ReplayError；异常原样
  传播，失败不改变实例。输出顶层键序仅 v,state,forward,log,result：
  v=2；state 为起始时刻 dump_state 的 v2 对象，forward 为键序
  version,history,audit 的包装（当前 dump_forward 版本号、按
  forward_versions 升序的保留 config 快照、forward_audit() 对象），
  log 为 export_log(ops,now) 对象，result 为从前三者经与 replay_bundle
  相同路径（v2，连版本、历史与审计一并恢复）隔离恢复并重放所得对象。
  紧凑 ASCII JSON、末尾单换行；交给 replay_bundle 后返回文本与 result
  逐字节相同、恢复解析器的 dump_forward/forward_versions/
  forward_audit 与导出时一致；同态同参逐字节一致。
- Resolver.reload_bundle_file(path: str, expected: int) -> str: 带修订号
  检查地从封包文件原子接管整解析器状态，返回键序仅 version,result 的
  紧凑 ASCII JSON 报告（末尾换行）。path 非 str 或 expected 非 int
  （含 bool）抛 TypeError；path 为空串或含 NUL、expected<0 抛
  ConfigError；验参后先比修订号，不等不打开文件并报告 conflict，相等时
  调用 replay_bundle_file 隔离恢复重放，其 16MiB 读取上限、校验与全部
  异常原样沿用；候选修订号小于当前抛 ConfigError，候选最后成功结束
  时刻早于当前（未设视为 0）抛 CacheError；全部通过后一次性以候选的
  区域历史及修订号、权威和递归缓存/FIFO、时钟、全部统计、上游配置
  历史及审计替换当前对应状态，报告 applied（version 为操作后非负
  修订号）；冲突外任何异常均不改变原实例，同状态同文件逐字节一致。
- compare_serial(left: int, right: int) -> str: 按 RFC 1982 比较
  uint32 环形序列号，返回 "equal"、"newer"、"older" 或 "ambiguous"。
- replay(zone, plan, ops, expected=None, timeout=5) -> str: 在 Resolver
  上依次回放 reload/reload_tx/reload_serial/migrate/migrate_tx/
  restore_zones/
  resolve/transfer/recursive/rollback/rollback_batch/update/cache_stats 操作
  并记录为紧凑 ASCII JSON
  （末尾单换行）；ops 限 0..4096 项，结果上限 16777216 字节。
- authorize(query: bytes, client: str, rules: list, default: str = "deny")
  -> bool: 按 client/名称/类型规则原序匹配授权查询。
- RateLimiter(rules): 确定性固定窗查询/响应限流器，
  allow(query, client, now, kind="query") -> (是否放行, 余量或 -1)；
  respond(query, response, client, now, truncate=True) 按响应配额
  限流，放行返回 (response, 余量)，拒绝返回 (None, 0) 或仅含问题
  段的截断应答 (tc, 0)；respond_edns 为 EDNS 变体（查询与应答均须
  恰含一个合法 OPT，应答的 OPT 为附加段末项），截断应答末项回显
  应答 OPT 的 CLASS 与 TTL；
  stats(reset=False) -> str 返回键序 query,response,expired,evicted,
  keys 的紧凑 ASCII JSON（末尾换行），reset=True 先返回快照再清零计数；
  reload_rules(rules, expected) 带版本检查的原子规则热加载，版本初始
  为 0，返回键序 version,result,kept,dropped 的紧凑 ASCII JSON 报告
  （末尾换行），result 为 "applied"、"unchanged" 或 "conflict"；
  构造时规范规则存为版本 0，applied 时按新版本归档快照，历史容量
  32、超量淘汰最小版本且版本不复用；
  rollback_rules(target, expected) 带版本检查的原子规则回滚，返回
  键序 version,result,target,kept,dropped 的紧凑 ASCII JSON 报告
  （末尾换行），result 为 "applied"、"unchanged"、"missing" 或
  "conflict"；dump() 把规则版本历史导出为 schema=1 的确定性配置
  文本（顶层键序 schema,version,history，history 升序，项键序
  version,rules；紧凑 ASCII JSON，末尾单换行），只读且同状态逐
  字节相同；load(text) 类方法从配置文本恢复实例（schema 0/1，
  schema=0 历史限 256 项仅留最新 32 项），以末项为当前规则，
  版本继续递增，新实例计数为空、时钟未设、统计清零。
- ResponseRateLimiter(window, limit, slip=2): 按客户端 /24 或
  /56 网段、规范 qname、qtype 与应答 RCODE 分窗（now//window）的
  确定性固定窗响应速率限流器；apply(query, response, client, now)
  校验与异常沿用 RateLimiter.respond，未超 limit 返回
  (response, "pass", 余量)，超额按 slip 周期返回既有格式截断应答
  (tc, "slip", 0) 或 (None, "drop", 0)；状态至多 4096 项，插入第
  4097 键前淘汰 (窗截止, 创建序) 最小项；stats(reset=False) 返回键序
  pass,drop,slip,expired,evicted,keys,capacity 的紧凑 ASCII JSON
  （末尾换行），capacity 恒为 4096，reset=True 返回重置前快照并清零
  五个累计计数。
- replay_rate(rules, ops, expected=None, policy=None, default="deny")
  -> str: 在 RateLimiter 上依次回放 allow/authorize/reload/rollback
  操作并记录为紧凑 ASCII JSON（末尾单换行）；ops 限 0..4096 项，
  结果上限 16777216 字节。

命令行：
- python dns.py decode HEX：解码查询报文为紧凑 ASCII JSON（末尾换行）。
- python dns.py answer ZONE_PATH QUERY_HEX [LIMIT]：读取 v0/v1/v2 区域
  文件（至多 1048576 字节、须为 ASCII），对单问题查询给出权威应答；
  stdout 仅写应答原始字节、无追加换行，stderr 恒为空。参数数量、空路径
  或含 NUL、非法十六进制或 LIMIT（12..65535 的 ASCII 十进制整数）以
  ArgumentError 退出 2 且不打开区域文件；文件不存在、不可读、超限、
  非 ASCII 或配置结构非法以 ConfigError 退出 4，区域/记录语义非法分别
  以 ZoneError/RecordError 退出 4；查询报文非法以 MessageError 退出 3；
  不可应答、超 LIMIT 等编码失败以 EncodeError 退出 5，CNAME 名称重复
  或超跳数以 CNAMEError 退出 5。
"""

from collections import deque
import base64
import copy
import hashlib
import hmac
import ipaddress
import json
import os
import sys
import tempfile


class MessageError(ValueError):
    """DNS 报文无法解码。"""


class EDNSError(MessageError):
    """EDNS 报文无法解码：AR/OPT（含选项 TLV）非法、截断、尾随或模型含 OPT。"""


class CookieError(EDNSError):
    """EDNS COOKIE 查询非法：OPT 版本非 0、COOKIE（码 10）缺失或不唯一、
    COOKIE data 长度不符，或 secret 长度非 16..64、client 非合法 IP。"""


class EDEError(EDNSError):
    """EDNS EDE 查询非法：OPT 缺失或版本非 0。"""


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


class TransferError(ValueError):
    """区传送差异或全量记录总数超过 limit。"""


_MIN_MESSAGE_LEN = 12
_MAX_MESSAGE_LEN = 512
_MAX_QUESTIONS = 64
_MAX_NAME_WIRE_LEN = 255
_MAX_POINTER_JUMPS = 16
# 名称安全字符：小写字母、数字、下划线、连字符；大写 ASCII 仅出现在
# 输入文本中，规范时折为小写。标签内部表示统一为 bytes（任意八位组），
# 仅最左标签可为解码后恰为单字节 0x2A（"*"）的通配标签。
_NAME_SAFE_BYTES = frozenset(
    b"abcdefghijklmnopqrstuvwxyz0123456789_-")
_NAME_SAFE_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyz0123456789_-")
_WILDCARD_LABEL = b"*"
_HEXDIGITS = frozenset("0123456789abcdefABCDEF")
_LOWER_HEXDIGITS = frozenset("0123456789abcdef")


def _name_lower_octet(value):
    """ASCII 大写字母折为小写，其余八位组原样返回。"""
    if 0x41 <= value <= 0x5A:
        return value + 0x20
    return value


def _parse_name_text(name, syntax_error, star="none"):
    """把绝对名文本解析为线格式 bytes 标签列表（根为 []）。

    接受未转义点分隔的标签与反斜杠转义："\\DDD"（恰三位十进制、
    000..255）为单个八位组，"\\." 与 "\\\\" 为点或反斜杠本身；其余
    反斜杠形式（残缺、非三位数字、数值超 255）为语法错误，抛
    syntax_error（主文件为 ConfigError、应答模型为 RecordError）。
    未转义点仅作分隔符。star 控制八位组 0x2A（"*"）的形态：
    "wildcard"（owner 语境）仅允许首个标签解码后恰为单字节 "*"；
    "any"（查询名与嵌入名语境）任意位置的 "*" 均为普通八位组；
    "none"（origin 与策略名语境）拒绝任何 "*"。转义全部解码完成后
    才校验标签 1..63 字节与整名线格式 ≤255，违反抛 RecordError；
    非绝对名（不以未转义点结尾）抛 RecordError。
    """
    if not isinstance(name, str):
        raise TypeError("name must be str")
    if not name:
        raise RecordError("name not absolute")
    labels = []
    label = bytearray()
    literal_star = False  # 当前标签是否含未转义（字面）"*"
    label_stars = []  # 各标签是否含字面 "*"；转义 \042 不计
    pos = 0
    length = len(name)
    closed = False  # 末尾是否为未转义点（绝对名）
    while pos < length:
        ch = name[pos]
        if ch == "\\":
            if pos + 1 >= length:
                raise syntax_error("bad name escape")
            nxt = name[pos + 1]
            if nxt == "." or nxt == "\\":
                label.append(ord(nxt))
                pos += 2
                closed = False
                continue
            if pos + 4 > length:
                raise syntax_error("bad name escape")
            digits = name[pos + 1:pos + 4]
            if not digits.isascii() or not digits.isdigit():
                raise syntax_error("bad name escape")
            value = int(digits)
            if value > 0xFF:
                raise syntax_error("name escape out of range")
            label.append(value)
            pos += 4
            closed = False
            continue
        if ch == ".":
            labels.append(bytes(label))
            label_stars.append(literal_star)
            label = bytearray()
            literal_star = False
            pos += 1
            closed = True
            continue
        if ord(ch) > 0x7F:
            # 名称文本的非 ASCII 码点无法逐字节映射；除 \\DDD 外仅接受
            # ASCII 八位组。
            raise syntax_error("name must be ASCII")
        if ch == "*":
            # 字面 "*" 的合法性按 star 策略在标签解码完成后统一判定
            # （转义 \\042 是普通八位组，不经此分支）；此处仅做记录。
            literal_star = True
        elif ch not in _NAME_SAFE_CHARS and not ("A" <= ch <= "Z"):
            # 非安全字符（含空白与控制字符）只能以 \\DDD 等转义形式引入；
            # 原样书写按既有契约为记录错误。
            raise RecordError("invalid label character")
        label.append(ord(ch))
        pos += 1
        closed = False
    if not closed:
        raise RecordError("name not absolute")
    if labels == [b""]:
        return []  # 根名 "."
    result = []
    wire_len = 1  # 根终止符占 1 字节
    for index, raw in enumerate(labels):
        if not 1 <= len(raw) <= _MAX_LABEL_LEN:
            raise RecordError("bad label length")
        normalized = bytes(_name_lower_octet(value) for value in raw)
        is_literal_star = label_stars[index]
        if is_literal_star and star == "none":
            raise RecordError("invalid label character")
        if is_literal_star and star == "wildcard":
            # 字面 "*" 的唯一合法通配形态：首个标签恰为单字节 "*"；
            # 其余标签或多字节标签中的字面 "*" 均非法。转义 \042 是
            # 普通八位组，不受此限。
            if not (index == 0 and normalized == _WILDCARD_LABEL):
                raise RecordError("invalid label character")
        result.append(normalized)
        wire_len += len(normalized) + 1
        if wire_len > _MAX_NAME_WIRE_LEN:
            raise RecordError("name too long")
    return result


def _decode_wire_name(buf, error, offset=0):
    """从未压缩、0 结尾的线格式名解码为 bytes 标签列表。

    接受标签内任意八位组，ASCII 大写折为小写；标签 1..63 字节、总长
    ≤255、无压缩指针（长度字节 >63）、无截断。offset 为名后偏移；
    require_end 时名后不得有尾随字节。任何不符抛 error。
    """
    labels = []
    pos = offset
    wire_len = 1  # 根终止符占 1 字节
    while True:
        if pos >= len(buf):
            raise error("wire name not terminated")
        length = buf[pos]
        if length == 0:
            return labels, pos + 1
        if length > _MAX_LABEL_LEN:  # 含压缩指针形态
            raise error("wire name bad label length")
        pos += 1
        if pos + length > len(buf):
            raise error("wire name truncated")
        raw = bytes(buf[pos:pos + length])
        labels.append(bytes(_name_lower_octet(value) for value in raw))
        pos += length
        wire_len += length + 1
        if wire_len > _MAX_NAME_WIRE_LEN:
            raise error("wire name too long")


def _format_label_text(label):
    """把 bytes 标签渲染为名称文本：字母、数字、下划线、连字符原样，
    其余八位组（含点、反斜杠、星号等）统一写三位十进制 \\DDD。"""
    out = []
    for value in label:
        if value in _NAME_SAFE_BYTES:
            out.append(chr(value))
        else:
            out.append("\\%03d" % value)
    return "".join(out)


def _labels_to_name(labels, wildcard=True):
    """bytes 标签列表还原为规范绝对名文本（根为 "."）。

    wildcard 为真时（owner/查询名语境）首标签恰为单字节 0x2A 渲染为
    旧式通配形态 "*"，与既有安全 ASCII 名称输出逐字节一致；其余位置
    及嵌入名（rdata）语境统一渲染为三位十进制 \\042，保证非通配解析
    也能逐字节往返。
    """
    if not labels:
        return "."
    parts = []
    for index, label in enumerate(labels):
        if wildcard and index == 0 and label == _WILDCARD_LABEL:
            parts.append("*")
        else:
            parts.append(_format_label_text(label))
    return ".".join(parts) + "."


def _encode_wire_name(labels):
    """把 bytes 标签列表编码为未压缩绝对名线格式。"""
    out = bytearray()
    for label in labels:
        out.append(len(label))
        out.extend(label)
    out.append(0)
    return bytes(out)

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
_REPLAY_RELOAD_SERIAL_KEYS = ["op", "text", "expected", "force"]
_REPLAY_ROLLBACK_STEP_KEYS = ["op", "target"]
_REPLAY_ROLLBACK_BATCH_KEYS = ["op", "expected", "steps"]
_REPLAY_ROLLBACK_TX_KEYS = ["op", "target", "expected"]
_MAX_MIGRATE_TEXT_LEN = 1048576
# import_master/export_master 主文件文本限 1048576 码点，须为 ASCII；
# 除首行 $ORIGIN 外记录行限 1..65535 行。
_MAX_MASTER_TEXT_LEN = 1048576
_MAX_MASTER_RECORDS = 65535
_MAX_ROLLBACK_BATCH_STEPS = 32
_UPDATE_CHANGE_KEYS = ["op", "record"]
_UPDATE_OPS = frozenset(("add", "delete"))
_MAX_UPDATE_CHANGES = 256
_REPLAY_UPDATE_KEYS = ["op", "changes", "serial", "expected"]
_MIN_TRANSFER_LIMIT = 1
_MAX_TRANSFER_LIMIT = 65535
_REPLAY_RESOLVE_KEYS = ["op", "query", "now", "limit"]
_REPLAY_TRANSFER_KEYS = ["op", "from_serial", "limit"]
_REPLAY_RECURSIVE_KEYS = ["op", "query", "levels", "now", "limit"]
_REPLAY_LEVEL_KEYS = ["name", "events"]
_REPLAY_EVENT_KEYS = ["delay", "reply"]
_REPLAY_REPLY_KEYS = ["kind", "an", "ns"]
_REPLAY_RATE_OP_KEYS = ["op", "query", "client", "now", "kind"]
_REPLAY_AUTHORIZE_OP_KEYS = ["op", "query", "client"]
_REPLAY_RELOAD_OP_KEYS = ["op", "rules", "expected"]
_REPLAY_RATE_ROLLBACK_KEYS = ["op", "target", "expected"]
_MAX_REPLAY_RATE_OPS = 4096
_REPLAY_CACHE_STATS_KEYS = ["op", "reset"]
_MAX_REPLAY_CACHE_OPS = 4096
_REPLAY_RESOLVER_CACHE_STATS_KEYS = ["op", "now", "reset"]
_MAX_REPLAY_OPS = 4096
_MAX_REPLAY_RESULT_BYTES = 16777216
_REPLAY_LOG_KEYS = ["v", "now", "ops"]
_MAX_REPLAY_LOG_TEXT_LEN = 1048576
# replay_log/replay_log_file 的冲突报告：内容固定，共用同一常量保证
# 逐字节一致。
_REPLAY_LOG_CONFLICT = '{"v":1,"result":"conflict","ops":[],"state":null}\n'
# replay_bundle 的重放封包：顶层键序仅 v,state,forward,log,result
# （v1：v=1、forward 为 migrate_forward 的 v1 配置对象；v2：v=2、
# forward 为键序 version,history,audit 的对象）；文本限 16777216
# 码点、须为 ASCII。
_REPLAY_BUNDLE_KEYS = ["v", "state", "forward", "log", "result"]
_MAX_REPLAY_BUNDLE_LEN = 16777216
# 封包 v2 的 forward 包装：顶层键序仅 version,history,audit。version
# 为非负非 bool 整数；history 含 1..32 个键序 version,config 的项，
# version 严格升序且末项等于顶层 version，config 为 migrate_forward
# 的规范 v1 配置对象；audit 顶层键序仅 v,o（v 恒为 1），o 含 0..4096
# 个键序 k,x,e,r,a 的五键项。
_BUNDLE_V2_FORWARD_KEYS = ["version", "history", "audit"]
_BUNDLE_V2_HISTORY_ITEM_KEYS = ["version", "config"]
_BUNDLE_V2_AUDIT_KEYS = ["v", "o"]
_BUNDLE_V2_AUDIT_ITEM_KEYS = ["k", "x", "e", "r", "a"]
# replay_forward 的上游配置重放日志：顶层键序仅 v,o（v 恒为 1），o 含
# 0..4096 项。项有两种形态，同一日志内可混用：旧三键项键序仅
# k,x,e；forward_audit 导出的五键项键序仅 k,x,e,r,a。k="l" 时 x
# 为 migrate_forward 配置文本，k="r" 时 x 为非负非 bool 目标版本；
# e 为非负非 bool 的步骤前预期版本；五键项另含 r（仅
# "applied"/"unchanged"，即该步实际结果）与 a（非负非 bool 的步骤
# 后版本号）。
_REPLAY_FORWARD_KEYS = ["v", "o"]
_REPLAY_FORWARD_ITEM_KEYS = ["k", "x", "e"]
_REPLAY_FORWARD_AUDIT_ITEM_KEYS = ["k", "x", "e", "r", "a"]
_REPLAY_FORWARD_OPS = frozenset(("l", "r"))
_REPLAY_FORWARD_RESULTS = frozenset(("applied", "unchanged"))
# forward_audit 的入账上限：o 至多 4096 项；完整输出（{"v":1,"o":[...]}
# 加末尾换行）超过 16777216 字节时淘汰最早项。
_MAX_FORWARD_AUDIT_OPS = 4096
_MAX_FORWARD_AUDIT_BYTES = 16777216
# 非空审计输出长度对各项 (len(项文本)+1) 之和的固定增量：
# len('{"v":1,"o":[')=12、len(']}\n')=3、末项无逗号再减 1，共 14。
_FORWARD_AUDIT_FIXED_BYTES = 14
_POLICY_RULE_KEYS = ["client", "name", "type", "action"]
_POLICY_ACTIONS = frozenset(("allow", "deny"))
_MAX_POLICY_RULES = 256
_RATE_RULE_KEYS = ["client", "name", "type", "window", "query", "response"]
_RATE_KINDS = ("query", "response")
_MIN_RATE_WINDOW = 1
_MAX_RATE_WINDOW = 3600
_MAX_RATE_QUOTA = 65535
_RATE_TABLE_CAPACITY = 4096
# 限流规则历史容量：构造时的规范规则存为版本 0，每次 applied 热加载或
# 回滚按新版本保存一份规范规则深拷贝，超量淘汰最小版本；版本号单调
# 递增、不复用。
_RATE_RULE_HISTORY_CAPACITY = 32
# dump/load 配置：顶层键序仅 schema,version,history，history 项键序仅
# version,rules；schema=0 的历史限 256 项且 load 仅留最新 32 项，
# schema=1 的历史限 32 项（与规则历史容量一致）。
_RATE_CONFIG_KEYS = ["schema", "version", "history"]
_RATE_HISTORY_ITEM_KEYS = ["version", "rules"]
_RATE_LOAD_HISTORY_LIMIT_V0 = 256
_MAX_LABEL_LEN = 63
_MAX_RDATA_LEN = 65535
_MAX_TTL = 4294967295
_MIN_LIMIT = 12
_MAX_LIMIT = 65535
# answer 子命令区域文件读取上限（字节）；多读一字节即可判定超限，
# 避免把超限文件整体读入内存。
_MAX_ANSWER_ZONE_BYTES = 1048576
_MAX_POINTER_TARGET = 0x3FFF
_MAX_SECTION_RECORDS = 65535
_FLAGS_RESPONSE = 0x8400  # QR | AA
_FLAGS_KEPT = 0x7910  # opcode | RD | CD
_FLAG_TC = 0x0200
_TYPE_A = 1
_TYPE_NS = 2
_TYPE_CNAME = 5
_TYPE_SOA = 6
_TYPE_MX = 15
_TYPE_TXT = 16
_TYPE_AAAA = 28
_TYPE_SRV = 33
_TYPE_NAPTR = 35
_TYPE_DS = 43
_TYPE_RRSIG = 46
_TYPE_NSEC = 47
_TYPE_DNSKEY = 48
_TYPE_CDS = 59
_TYPE_CDNSKEY = 60
_TYPE_CAA = 257
_TYPE_OPT = 41
_MIN_OPT_CLASS = 512
_FLAG_DO = 0x8000
_MAX_EDNS_RCODE = 0xFFF
# EDNS(0) Client Subnet（选项码 8）：family 仅 1（IPv4）/2（IPv6），
# source prefix 分别限 0..32、0..128，查询 scope 须为 0，address 长度为
# (source+7)//8 且末字节未用低位须为 0；版本 0 查询至多一个 ECS。
_OPT_CODE_ECS = 8
_ECS_FAMILY_IPV4 = 1
_ECS_FAMILY_IPV6 = 2
_ECS_MAX_SOURCE = {_ECS_FAMILY_IPV4: 32, _ECS_FAMILY_IPV6: 128}
# EDNS(0) COOKIE（选项码 10）：版本 0 查询须恰有一个 COOKIE；data 为
# 8 字节客户端值，或 8 字节客户端值后接 16 字节服务端值。服务端值为
# HMAC-SHA256(secret, family(0x04/0x06)+packed IP+客户端值) 前 16 字节；
# secret 限 16..64 字节。服务端值缺失或匹配时按模型应答，不匹配返回
# 扩展 RCODE 23（BADCOOKIE）并清空三段。
_OPT_CODE_COOKIE = 10
_COOKIE_CLIENT_LEN = 8
_COOKIE_SERVER_LEN = 16
_FAMILY_IPV4 = 0x04
_FAMILY_IPV6 = 0x06
_MIN_COOKIE_SECRET_LEN = 16
_MAX_COOKIE_SECRET_LEN = 64
_RCODE_BADCOOKIE = 23
# EDNS(0) Padding（选项码 12）：版本 0 查询至多一个 Padding 且 data
# 全零；应答 OPT 仅含一个 Padding TLV，按 ar、ns、an 的 RRset 整组淘汰
# 枚举候选取首个 B+(-B)%block≤min(limit, CLASS) 者填零（B 为候选含零长
# TLV 的报文长度，n=0 仍保留 TLV）。block 限 16..512 内 2 的幂。
_OPT_CODE_PADDING = 12
_MIN_PADDING_BLOCK = 16
_MAX_PADDING_BLOCK = 512
# EDE（Extended DNS Errors，选项码 15）：data 为网络序 uint16 info_code
# 后接 UTF-8 文本（可空）；文本上限 65529 字节使 TLV 总 RDATA 不超
# 65535（4 字节 TLV 头 + 2 字节 info_code）。
_OPT_CODE_EDE = 15
_MAX_EDE_TEXT_LEN = 65529
_MAX_CNAME_CHAIN = 16
_RCODE_REFUSED = 5
_RCODE_NXDOMAIN = 3
_RCODE_BADVERS = 16
_CACHE_CAPACITY = 256
# 区域修订历史容量：每个成功换区修订保存一份规范化区域深拷贝，
# 超量淘汰最小修订号；修订号单调递增、不复用。
_ZONE_HISTORY_CAPACITY = 32
# dump_zones/load_zones 配置：顶层键序仅 schema,version,history
# （dump_zones 的 schema 恒为 1），history 项键序仅 revision,zone，
# revision 非负且严格递增、末项等于顶层 version。schema=1 历史限
# 1..32 项（与区域修订历史容量一致）；schema=0 为旧格式，历史限
# 1..256 项，load_zones/migrate_zones 先校验全部快照再仅留最新 32 项。
_ZONES_DUMP_KEYS = ["schema", "version", "history"]
_ZONES_HISTORY_ITEM_KEYS = ["revision", "zone"]
_ZONES_LOAD_HISTORY_LIMIT_V0 = 256
# save_zones/reload_zones_file 的区域文件大小上限（字节）。
_MAX_ZONES_FILE_BYTES = 16777216
_MAX_PLAN_ITEMS = 16
_PLAN_EVENTS_USED = 2
_MIN_TIMEOUT = 1
_MAX_TIMEOUT = 60
# migrate_forward 的 v0/v1 上游配置：v0 顶层键序仅 v,timeout,plan，
# 迁移补 attempts=2；v1 顶层键序仅 v,timeout,attempts,plan。timeout 为
# 1..60、attempts 为 1..2 的非 bool 整数；plan 项键序仅 name,events，
# events 项键序仅 delay,reply，每上游 events 限 0..2 且不得多于 attempts。
_FORWARD_CONFIG_KEYS_V0 = ["v", "timeout", "plan"]
_FORWARD_CONFIG_KEYS_V1 = ["v", "timeout", "attempts", "plan"]
_FORWARD_PLAN_ITEM_KEYS = ["name", "events"]
_FORWARD_EVENT_KEYS = ["delay", "reply"]
_FORWARD_MIN_ATTEMPTS = 1
_FORWARD_MAX_ATTEMPTS = 2
_FORWARD_DEFAULT_ATTEMPTS = 2
# 上游配置历史容量：每个 applied 版本保存一份规范化配置快照，
# 超量淘汰最小版本号；版本号单调递增、不复用。
_FORWARD_HISTORY_CAPACITY = 32
_MAX_REPLY_LEN = 65535
_FLAG_QR = 0x8000
_MAX_RECURSION_LEVELS = 16
_RECURSIVE_RCODES = {0: 0, 1: 0, 2: _RCODE_NXDOMAIN, 3: 0}
# resolve_recursive 的 stale_window：非 bool 整数，0 关闭陈旧应答，
# 上限一天（86400 秒）；仅域外查询在 query/levels/now/limit 全量
# 校验后、递归缓存查找前校验。
_MAX_STALE_WINDOW = 86400
# 递归缓存命中类别 -> stats 的 h 下标（正/NXDOMAIN/NODATA）
_RECURSIVE_HIT_KINDS = {"pos": 1, "nxdomain": 2, "nodata": 3}
# dump_rec/load_rec 递归缓存配置：顶层键序仅 v,clock,items（v 恒为 1，
# clock 为导出时刻），items 限 256 项（与递归缓存容量一致），项键序
# 仅 k,q,t,c,rr，rr 元素键序仅 n,t,c,ttl,d；文本限 1048576 码点。
_REC_DUMP_KEYS = ["v", "clock", "items"]
_REC_ITEM_KEYS = ["k", "q", "t", "c", "rr"]
_REC_RR_KEYS = ["n", "t", "c", "ttl", "d"]
_REC_ITEM_KINDS = frozenset(("p", "nx", "nd"))
_MAX_REC_TEXT_LEN = 1048576
# dump_state/load_state 整解析器快照：顶层键序仅 v,zones,rec,stats,ru
# （v 恒为 2，后四者分别为 dump_zones()、dump_rec(now)、stats() 与
# recursive_upstream_stats(False) 的解码对象）；v1 旧格式顶层键序仅
# v,zones,rec,stats（v 恒为 1，无 ru）；v0 旧格式顶层键序仅 v,zones,rec
# （v 恒为 0，无 stats、ru），迁移时逐级补全。文本上限 16777216 码点
# （同区域文件上限）。
_STATE_DUMP_KEYS = ["v", "zones", "rec", "stats", "ru"]
_STATE_DUMP_KEYS_V1 = ["v", "zones", "rec", "stats"]
_STATE_DUMP_KEYS_V0 = ["v", "zones", "rec"]
_MAX_STATE_TEXT_LEN = 16777216
# stats() JSON 的固定键序 h,m,x,u,c,l,r；加载时 c[1] 以 rec.items
# 长度重算，r 以 h、m 重算，仅核对键序与字段形态。
_STATS_KEYS = ["h", "m", "x", "u", "c", "l", "r"]
# recursive_upstream_stats() JSON 的固定键序 l,t：l 固定 16 行、每行 7
# 个非负整数，t 为 7 个非负整数且逐列等于 l 各行之和。
_RECURSIVE_UP_KEYS = ["l", "t"]
_RECURSIVE_UP_ROWS = _MAX_RECURSION_LEVELS
_RECURSIVE_UP_COLS = 7


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
        # 标签接受任意八位组；ASCII 大写折为小写，其余逐字节保留。
        label = bytes(_name_lower_octet(value)
                      for value in data[pos:pos + length])
        labels.append(label)
        wire_len += length + 1
        if wire_len > _MAX_NAME_WIRE_LEN:
            raise MessageError("name too long")
        pos += length
    return _labels_to_name(labels), end


def decode_query(data: bytes) -> dict:
    """解码 DNS 查询报文，返回 {"id", "flags", "questions"}。

    问题名标签接受任意八位组：ASCII 大写折为小写，其余逐字节保留并在
    返回的规范文本中写三位十进制转义；仍拒绝截断、越界、压缩指针循环
    或指向非标签边界的指针。
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
    """解码可含单个 OPT 的查询报文。

    返回 (msg, (opt_class, version, do, opts) 或 None)。问题段解码契约
    同 decode_query，但查询截断（问题区越界）、非法名字（含压缩问题）、
    AN/NS 非空、非法 AR/OPT 与尾随字节一律抛 EDNSError；报文长度与
    问题数等其余错误仍抛 MessageError。AR 限 0 或 1 条，有则须为未压缩
    根 owner、TYPE41、CLASS512..65535、扩展码 0、版本 0..255、flags
    仅 DO 的 OPT。OPT 的 RDATA 按选项 TLV 解析：每项为网络序
    uint16 code、uint16 length、length 字节 data，重复项保序；头或
    数据截断、RDLENGTH 内残缺抛 EDNSError。
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
        if ttl >> 24:
            raise EDNSError("opt extended rcode must be 0")
        if ttl & 0xFFFF & ~_FLAG_DO:
            raise EDNSError("opt flags must be DO only")
        if pos + rdlength > len(data):
            raise EDNSError("opt record truncated")
        rdata_end = pos + rdlength
        opts = []
        while pos < rdata_end:
            if pos + 4 > rdata_end:
                raise EDNSError("opt option truncated")
            code = int.from_bytes(data[pos:pos + 2], "big")
            opt_len = int.from_bytes(data[pos + 2:pos + 4], "big")
            pos += 4
            if pos + opt_len > rdata_end:
                raise EDNSError("opt option data truncated")
            opts.append((code, bytes(data[pos:pos + opt_len])))
            pos += opt_len
        opt = (rrclass, (ttl >> 16) & 0xFF, bool(ttl & _FLAG_DO), opts)
    if pos != len(data):
        raise EDNSError("trailing bytes")
    return {"id": msg_id, "flags": flags, "questions": questions}, opt


def _normalize_name(name):
    """按解码规则把 name 规范为绝对名，返回 bytes 标签列表（根为 []）。

    查询名与 rdata 语境：接受反斜杠转义（\\DDD、\\.、\\\\）与任意位置
    的字面 "*"（均为普通八位组）；转义语法错误在应答模型语境下与
    长度/字符错误同为 RecordError。
    """
    return _parse_name_text(name, RecordError, star="any")


def _normalize_origin_name(name):
    """规范 zone origin：同 _normalize_name，但拒绝任何字面 "*"
    （转义 \\042 产生的星号八位组为普通数据，允许）。"""
    return _parse_name_text(name, RecordError, star="none")


def _normalize_owner_name(name):
    """规范 zone 记录 owner，允许最左标签为字面单字节 "*" 的通配名。

    返回 bytes 标签列表；通配与否可由 labels[0] == b"*" 判别。
    转义 \\042 产生的星号为普通八位组，不构成通配。
    """
    return _parse_name_text(name, RecordError, star="wildcard")


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
        # 应答模型与递归终态 RR：名称为任意八位组的线格式名，字面 "*"
        # 亦为普通八位组（如直接查询通配节点本身时其 owner 进入应答）。
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


def _validate_edns_options(options):
    """校验应答 EDNS 选项表并编码为 OPT RDATA，重复项原序保留。

    options 为 None 时按空列表处理；每项须为仅含 "code"、"data" 两键
    （此序）的 dict，code 为 0..65535 非 bool 整数，data 为 bytes。
    容器或字段类型错抛 TypeError；键序错、code 越界、单项 data 或总
    RDATA 超 65535 字节抛 EncodeError。
    """
    if options is None:
        options = []
    if not isinstance(options, list):
        raise TypeError("options must be list")
    rdata = bytearray()
    for option in options:
        if not isinstance(option, dict):
            raise TypeError("option must be dict")
        if list(option.keys()) != ["code", "data"]:
            raise EncodeError("option keys must be code,data")
        code = option["code"]
        data = option["data"]
        if not isinstance(code, int) or isinstance(code, bool):
            raise TypeError("option code must be int")
        if not isinstance(data, bytes):
            raise TypeError("option data must be bytes")
        if not 0 <= code <= 0xFFFF:
            raise EncodeError("option code out of range")
        if len(data) > _MAX_RDATA_LEN:
            raise EncodeError("option data too long")
        if len(rdata) + 4 + len(data) > _MAX_RDATA_LEN:
            raise EncodeError("opt rdata too long")
        rdata += code.to_bytes(2, "big")
        rdata += len(data).to_bytes(2, "big")
        rdata += data
    return bytes(rdata)


def _parse_query_ecs(opts):
    """从版本 0 查询的 OPT 选项表中解析唯一 ECS（码 8）。

    无 ECS 返回 None；有则返回 (family, source, address)。重复 ECS、
    family 非 1/2、source 越界、scope 非 0、长度不符或末字节未用低位
    非 0 一律抛 EDNSError；其他选项码原样忽略。
    """
    ecs = None
    for code, data in opts:
        if code != _OPT_CODE_ECS:
            continue
        if ecs is not None:
            raise EDNSError("duplicate ECS option")
        if len(data) < 4:
            raise EDNSError("ECS option truncated")
        family = int.from_bytes(data[0:2], "big")
        source = data[2]
        scope = data[3]
        address = data[4:]
        if family not in _ECS_MAX_SOURCE:
            raise EDNSError("ECS family must be 1 or 2")
        if not 0 <= source <= _ECS_MAX_SOURCE[family]:
            raise EDNSError("ECS source prefix out of range")
        if scope != 0:
            raise EDNSError("ECS scope prefix must be 0 in queries")
        if len(address) != (source + 7) // 8:
            raise EDNSError("ECS address length mismatch")
        if source & 7 and address[-1] & (0xFF >> (source & 7)):
            raise EDNSError("ECS address has non-zero padding bits")
        ecs = (family, source, address)
    return ecs


def _encode_ecs_option(family, source, scope, address):
    """返回码 8 选项的 data 部分（family 两字节、source、scope、address）；
    选项 TLV 头由 _validate_edns_options 统一添加。"""
    return (family.to_bytes(2, "big") + bytes((source, scope)) + address)


def _decode_cname_target(rdata):
    """把 CNAME rdata 按未压缩绝对名线格式解码为 bytes 标签列表。

    标签接受任意八位组（大写折小写），1–63 字节、0 结尾、总长 ≤255；
    禁止压缩指针、尾随内容。
    """
    if len(rdata) > _MAX_NAME_WIRE_LEN:
        raise RecordError("cname rdata too long")
    labels, end = _decode_wire_name(rdata, RecordError)
    if end != len(rdata):
        raise RecordError("cname rdata trailing bytes")
    return labels


def _encode_cname_target(labels):
    """把标签列表重编码为未压缩绝对名线格式。"""
    return _encode_wire_name(labels)


def _read_soa_name(rdata, pos):
    """按 CNAME 目标规范解码 rdata pos 处的未压缩绝对名，返回下一偏移。

    标签接受任意八位组；任何格式问题都返回 None，不抛异常。
    """
    try:
        _labels, end = _decode_wire_name(rdata, ValueError, offset=pos)
    except ValueError:
        return None
    return end


def _parse_soa_minimum(rdata):
    """解析 SOA rdata 的 minimum 字段（第五个网络序 uint32）。

    rdata 须完整为两个未压缩绝对域名及五个网络序 uint32；
    格式不符返回 None，不抛异常。
    """
    pos = _parse_soa_uint32_offset(rdata)
    if pos is None:
        return None
    return int.from_bytes(rdata[pos + 16:pos + 20], "big")


def _parse_soa_uint32_offset(rdata):
    """SOA rdata 的两个未压缩绝对名后须恰为五个 uint32；返回其偏移或 None。"""
    pos = 0
    for _ in range(2):
        pos = _read_soa_name(rdata, pos)
        if pos is None:
            return None
    if len(rdata) - pos != 20:
        return None
    return pos


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


def _canonical_rdata(rrtype, rdata):
    """把含嵌入名的 rdata 中名称按线格式规范化（大写折小写）后重编码。

    覆盖 NS、CNAME、MX、SOA、SRV、NAPTR、NSEC、RRSIG：名称均为未压缩、
    0 结尾的绝对名，标签接受任意八位组。CNAME 沿用既有严格契约（结构
    非法抛 RecordError）；其余类型保持 zone 层历史宽松度——能完整解析
    嵌入名结构才折小写重编码，结构无法解析时 rdata 原样透传（与仅
    CNAME 规范化的历史行为一致，避免拒绝既有区域已接受的 rdata）。
    """
    if rrtype == _TYPE_CNAME:
        # CNAME 沿用既有严格契约：非法 rdata 在 zone 校验阶段即拒绝。
        return _encode_wire_name(_decode_cname_target(rdata))
    try:
        if rrtype == _TYPE_NS:
            return _encode_wire_name(_decode_cname_target(rdata))
        if rrtype == _TYPE_MX:
            if len(rdata) < 3:
                raise RecordError("mx rdata truncated")
            exchange = _decode_cname_target(rdata[2:])
            return rdata[:2] + _encode_wire_name(exchange)
        if rrtype == _TYPE_SRV:
            if len(rdata) < 7:
                raise RecordError("srv rdata truncated")
            target = _decode_cname_target(rdata[6:])
            return rdata[:6] + _encode_wire_name(target)
        if rrtype == _TYPE_SOA:
            # 前两个未压缩名总是可定位：折小写，其后字节（结构合法时恰为
            # 五个 uint32）逐字保留，不强制尾部形状。
            mname, pos1 = _decode_wire_name(rdata, RecordError, 0)
            rname, pos2 = _decode_wire_name(rdata, RecordError, pos1)
            return (_encode_wire_name(mname) + _encode_wire_name(rname)
                    + bytes(rdata[pos2:]))
        if rrtype == _TYPE_NAPTR:
            # 跳过两个 uint16 与三个一字节长度前缀字符串，再规范化 replacement。
            if len(rdata) < 7:
                raise RecordError("naptr rdata truncated")
            pos = 4
            for _ in range(3):
                if pos >= len(rdata):
                    raise RecordError("naptr rdata truncated")
                count = rdata[pos]
                pos += 1
                if pos + count > len(rdata):
                    raise RecordError("naptr rdata truncated")
                pos += count
            replacement = _decode_cname_target(rdata[pos:])
            return rdata[:pos] + _encode_wire_name(replacement)
        if rrtype == _TYPE_NSEC:
            next_labels, pos = _master_decode_nsec_name(rdata)
            return _encode_wire_name(next_labels) + bytes(rdata[pos:])
        if rrtype == _TYPE_RRSIG:
            signer, pos = _decode_wire_name(rdata, RecordError, offset=18)
            return rdata[:18] + _encode_wire_name(signer) + bytes(rdata[pos:])
    except RecordError:
        # 嵌入名结构无法解析：保持历史 zone 层行为，rdata 原样透传。
        return rdata
    return rdata


_NAME_BEARING_TYPES = frozenset((_TYPE_NS, _TYPE_CNAME, _TYPE_MX,
                                 _TYPE_SOA, _TYPE_SRV, _TYPE_NAPTR,
                                 _TYPE_NSEC, _TYPE_RRSIG))


def _validate_zone(zone):
    """校验 zone，返回 (origin 标签列表, 规范化 RR 列表, 统一 class)。"""
    if not isinstance(zone, dict):
        raise TypeError("zone must be dict")
    if list(zone.keys()) != _ZONE_KEYS:
        raise ZoneError("zone keys must be origin,records")
    try:
        origin = _normalize_origin_name(zone["origin"])
    except RecordError as exc:
        raise ZoneError(str(exc)) from None
    records = zone["records"]
    if not isinstance(records, list):
        raise TypeError("records must be list")
    rrs = []
    for rr in records:
        labels, rrtype, rrclass, ttl, rdata = _validate_rr(
            rr, allow_wildcard=True)
        if rrtype in _NAME_BEARING_TYPES:
            # 嵌入名规范：大写折小写、任意八位组保留，rdata 据此重编码。
            rdata = _canonical_rdata(rrtype, rdata)
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
        if labels and labels[0] == _WILDCARD_LABEL:
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


def _write_name(out, labels, offsets, log=None):
    """把域名写入 out；offsets 记录已出现的标签边界（后缀 -> 最小偏移）。

    log 非 None 时，实际新插入 offsets 的 (位置, 后缀) 追加其中，供
    RRset 截断按起始偏移回滚压缩表。
    """
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
            suffix = tuple(labels[i:])
            position = len(out)
            if suffix not in offsets:
                offsets[suffix] = position
                if log is not None:
                    log.append((position, suffix))
        out.append(len(label))
        out.extend(label)
    if target is not None:
        out.extend((0xC000 | target).to_bytes(2, "big"))
    else:
        out.append(0)


def _name_wire_len(labels, offsets):
    """以只读 offsets（压缩表在偏移 16383 后冻结）计算名字编码字节数。

    与 _write_name 的压缩判定一致，但不写缓冲、不改表，用于冷区记录的
    长度记账：压缩指针只能指向 <= 0x3FFF 的偏移，offsets 已为该冻结表，
    故冷区记录编码只取决于此表，不随其后冷区记录的增删而变。
    """
    match = 0
    for i in range(len(labels)):
        if tuple(labels[i:]) in offsets:
            match = len(labels) - i
            break
    if match:
        matched = sum(len(labels[i]) + 1
                      for i in range(len(labels) - match))
        return matched + 2
    return sum(len(label) + 1 for label in labels) + 1


def _rrset_unit(rr, position):
    """RR 在所属区段内的 RRset 单元键：规范化 owner、数值 type、数值 class。

    键不含 TTL 与 rdata；OPT（TYPE41）不属于 RRset，每条各自为独立
    单元（以位置区分），不与任何其他记录成组。
    """
    if rr[1] == _TYPE_OPT:
        return ("opt", position)
    return (tuple(rr[0]), rr[1], rr[2])


class _RRsetPlan:
    """RRset 原子截断的线性编码器，供 encode_response/edns/edns_padded 共用。

    三段按 an、ns、ar 线序编码；淘汰按 ar、ns、an 优先级，每次删除当前
    区段最后一条保留记录所属整个 RRset 在该区段的全部成员（即使原顺序
    不相邻），其余记录保持相对顺序。应答 OPT 不进入模型区段（ar 计数
    预算相应减一），由调用方在定稿时作为附加段末项追加。

    长度淘汰利用名字压缩的 16 位指针边界（目标偏移只可能 <= 0x3FFF）：
    名字起始偏移超过该边界的“冷”记录不会在压缩表注册任何后缀，其编码
    只取决于边界前约 16KB“热”前缀冻结下来的压缩表，故删除一个全部成员
    皆冷的 RRset 时热前缀与其他冷记录编码都不变，只需按其记录长度记账
    （O(成员数)）；只有触及热前缀的 RRset 才重建热前缀（至多约 16KB，
    与输入总记录数无关）并刷新受影响冷记录长度。每个 RRset 至多删除
    一次，单次处理时间与额外内存受区段记录数及编码总量的线性上界约束。
    """

    def __init__(self, msg, sections, rcode_low, caps):
        self.msg = msg
        self.rcode_low = rcode_low
        self.flags = (_FLAGS_RESPONSE | (msg["flags"] & _FLAGS_KEPT)
                      | rcode_low)
        self.sections = [list(section) for section in sections]
        self.caps = caps
        self.nexts = []
        self.prevs = []
        self.heads = []
        self.tails = []
        self.counts = []
        self.key_at = []
        self.groups = []
        self.hot = []
        self.cold_len = []
        for section in self.sections:
            size = len(section)
            self.nexts.append((list(range(1, size)) + [-1]) if size else [])
            self.prevs.append(([-1] + list(range(0, size - 1)))
                              if size else [])
            self.heads.append(0 if size else -1)
            self.tails.append(size - 1 if size else -1)
            self.counts.append(size)
            keys = [None] * size
            membership = {}
            for position, rr in enumerate(section):
                key = _rrset_unit(rr, position)
                keys[position] = key
                membership.setdefault(key, []).append(position)
            self.key_at.append(keys)
            self.groups.append(membership)
            self.hot.append([False] * size)
            self.cold_len.append([0] * size)
        self.truncated = False
        # 计数为 16 位：超上限先按同一 RRset 规则尾删，被删记录不编码。
        while True:
            section = next((i for i in (2, 1, 0)
                            if self.counts[i] > self.caps[i]), None)
            if section is None:
                break
            self._drop_tail_group(section)
        # 冷记录长度依赖索引：名字后缀 -> 含该后缀的保留记录集合，键为
        # (section, position)。冻结压缩后缀集合变化时只重测这些记录；
        # 每条记录每轮经 stamp 去重至多计一次。
        self.refs = {}
        for section in (0, 1, 2):
            position = self.heads[section]
            while position != -1:
                token = (section, position)
                labels = self.sections[section][position][0]
                for i in range(len(labels) + 1):
                    self.refs.setdefault(tuple(labels[i:]), set()).add(token)
                position = self.nexts[section][position]
        self.stamp = [[0] * len(section) for section in self.sections]
        self.gen = 0
        self.head = bytearray()
        self.offsets = {}
        self.frozen = frozenset()
        self.cold_total = 0
        self._encode_head()

    def _unlink(self, section, position):
        previous = self.prevs[section][position]
        following = self.nexts[section][position]
        if previous != -1:
            self.nexts[section][previous] = following
        else:
            self.heads[section] = following
        if following != -1:
            self.prevs[section][following] = previous
        else:
            self.tails[section] = previous

    def _drop_tail_group(self, section):
        """删除该区段最后一条保留记录所属的整个 RRset（仅断链与计数）。"""
        tail = self.tails[section]
        key = self.key_at[section][tail]
        members = self.groups[section].pop(key)
        for position in members:
            self._unlink(section, position)
        self.counts[section] -= len(members)
        self.truncated = True
        return members

    def _write_questions(self, out, offsets, log):
        for question in self.msg["questions"]:
            _write_name(out, _normalize_name(question["name"]),
                        offsets, log)
            out += question["type"].to_bytes(2, "big")
            out += question["class"].to_bytes(2, "big")

    def _encode_head(self, removed=()):
        """重新编码热前缀（名字起始 <= 0x3FFF）。

        removed 为本轮删除的 (section, position)：其中原冷成员先从冷长度
        合计扣除；越界后被提升为热成员的原冷记录同样扣除其旧冷长度。
        仅当冻结压缩后缀集合确有变化时才重算其余冷记录长度——热前缀
        恒为约 16KB，而问题段锚定的共享后缀（如同区 owner 的公共后缀）
        通常不变，纯冷 RRset 淘汰根本不进入本函数。
        """
        for section, position in removed:
            if not self.hot[section][position]:
                self.cold_total -= self.cold_len[section][position]
                self.hot[section][position] = False
        out = bytearray()
        out += self.msg["id"].to_bytes(2, "big")
        out += self.flags.to_bytes(2, "big")
        out += len(self.msg["questions"]).to_bytes(2, "big")
        out += (0).to_bytes(6)  # 三段计数占位，定稿前回填
        offsets = {}
        log = []
        self._write_questions(out, offsets, log)
        new_hot = [[False] * len(section) for section in self.sections]
        cold_len = self.cold_len
        in_cold = False
        for section in (0, 1, 2):
            position = self.heads[section]
            while position != -1:
                rr = self.sections[section][position]
                if not in_cold and len(out) <= _MAX_POINTER_TARGET:
                    _write_name(out, rr[0], offsets, log)
                    out += rr[1].to_bytes(2, "big")
                    out += rr[2].to_bytes(2, "big")
                    out += rr[3].to_bytes(4, "big")
                    out += len(rr[4]).to_bytes(2, "big")
                    out += rr[4]
                    new_hot[section][position] = True
                    if self.hot[section] and not self.hot[section][position]:
                        # 原冷记录提升为热：其旧冷长度不再计入合计。
                        self.cold_total -= cold_len[section][position]
                else:
                    in_cold = True  # 越过指针边界后全部为冷记录
                position = self.nexts[section][position]
        new_frozen = frozenset(offsets)
        self.head = out
        self.offsets = offsets
        self.hot = new_hot
        changed = new_frozen.symmetric_difference(self.frozen)
        if changed:
            # 冻结后缀集合变化：只重测名字含新增/消失后缀的保留冷记录，
            # 经 stamp 去重每条记录本轮至多计一次。根后缀恒在冻结表，
            # 故首轮即可覆盖全部冷记录。
            self.frozen = new_frozen
            self.gen += 1
            gen = self.gen
            for suffix in changed:
                for section, position in self.refs.get(suffix, ()):
                    if self.stamp[section][position] == gen:
                        continue
                    self.stamp[section][position] = gen
                    if new_hot[section][position]:
                        continue
                    rr = self.sections[section][position]
                    new_len = (_name_wire_len(rr[0], offsets) + 10
                               + len(rr[4]))
                    self.cold_total += (new_len
                                        - cold_len[section][position])
                    cold_len[section][position] = new_len

    def drop_last_group(self, section):
        """删除该区段尾记录所属 RRset，并维护热前缀/冷长度记账。"""
        members = self._drop_tail_group(section)
        for position in members:
            labels = self.sections[section][position][0]
            for i in range(len(labels) + 1):
                refs = self.refs.get(tuple(labels[i:]))
                if refs is not None:
                    refs.discard((section, position))
        if all(not self.hot[section][position] for position in members):
            # 全冷 RRset：热前缀与冻结压缩表不变，仅扣除成员冷长度。
            for position in members:
                self.cold_total -= self.cold_len[section][position]
            return
        # 组内含热前缀成员：热前缀改变，重编码并按需刷新冷记录长度。
        self._encode_head([(section, position) for position in members])

    def body_len(self):
        return len(self.head) + self.cold_total

    def fit(self, body_limit):
        """按 ar、ns、an 优先级整体淘汰 RRset，直到编码体不长于上限。"""
        while self.body_len() > body_limit:
            section = next((i for i in (2, 1, 0)
                            if self.counts[i] > 0), None)
            if section is None:
                # 三段已空仍超限：只剩头部与问题段，无法再淘汰。
                raise EncodeError("header and question exceed limit")
            self.drop_last_group(section)

    def finalize(self, suffix=b"", ar_extra=0):
        """一次性写出热前缀与全部冷记录，追加 suffix（应答 OPT），回填
        区段计数与（删除过普通 RR 时的）TC，返回应答字节。"""
        out = self.head
        offsets = self.offsets
        for section in (0, 1, 2):
            position = self.heads[section]
            while position != -1:
                if not self.hot[section][position]:
                    rr = self.sections[section][position]
                    _write_name(out, rr[0], offsets, None)
                    out += rr[1].to_bytes(2, "big")
                    out += rr[2].to_bytes(2, "big")
                    out += rr[3].to_bytes(4, "big")
                    out += len(rr[4]).to_bytes(2, "big")
                    out += rr[4]
                position = self.nexts[section][position]
        out += suffix
        na, nn, nr = self.counts
        out[6:8] = na.to_bytes(2, "big")
        out[8:10] = nn.to_bytes(2, "big")
        out[10:12] = (nr + ar_extra).to_bytes(2, "big")
        if self.truncated:
            out[2:4] = (self.flags | _FLAG_TC).to_bytes(2, "big")
        return bytes(out)


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
    # RRset 原子截断：计数超 16 位或总长超限时按 ar、ns、an 优先级，
    # 每次整组删除当前区段尾记录所属 RRset（规范化 owner、type、class，
    # 不含 TTL/rdata），其余记录保持相对顺序；删过普通 RR 集即置 TC。
    # 三段清空后仍超限时仅头部与问题段，抛 EncodeError。
    caps = (_MAX_SECTION_RECORDS,) * 3
    plan = _RRsetPlan(msg, (an, ns, ar), rcode, caps)
    plan.fit(limit)
    return plan.finalize()


def encode_response(query: bytes, model: dict) -> bytes:
    """把查询报文与应答模型编码为确定性权威应答报文（RCODE 恒为 0）。"""
    return _encode_response(query, model, 0)


def _encode_badvers(msg, opt, limit):
    """把已解码查询编码为 BADVERS 版本协商应答（OPT 版本 1..255）。

    flags=0x8400|(查询 flags&0x7910)，问题按规范化重编码，AN=NS=0、
    AR=1；OPT 为未压缩根 owner、TYPE41、回显 CLASS 与 DO，TTL 为
    DO?0x01008000:0x01000000（扩展码取 BADVERS>>4、版本 0），
    RDLENGTH=0。上限 min(limit, CLASS)，超限抛 EncodeError 且不置 TC。
    """
    opt_class, _version, do, _opts = opt
    limit = min(limit, opt_class)
    out = bytearray()
    out += msg["id"].to_bytes(2, "big")
    flags = _FLAGS_RESPONSE | (msg["flags"] & _FLAGS_KEPT)
    out += flags.to_bytes(2, "big")
    out += len(msg["questions"]).to_bytes(2, "big")
    out += (0).to_bytes(4)  # ANCOUNT/NSCOUNT 均为 0
    out += (1).to_bytes(2)  # ARCOUNT=1（末项 OPT）
    offsets = {}
    for question in msg["questions"]:
        _write_name(out, _normalize_name(question["name"]), offsets)
        out += question["type"].to_bytes(2, "big")
        out += question["class"].to_bytes(2, "big")
    ttl = ((_RCODE_BADVERS >> 4) << 24) | (_FLAG_DO if do else 0)
    out += (b"\x00" + _TYPE_OPT.to_bytes(2, "big")
            + opt_class.to_bytes(2, "big") + ttl.to_bytes(4, "big")
            + (0).to_bytes(2, "big"))
    if len(out) > limit:
        raise EncodeError("header, question and OPT exceed limit")
    return bytes(out)


def edns(query: bytes, model: dict, rcode: int = 0,
         options: list | None = None) -> bytes:
    """把（可含 OPT 的）查询报文与应答模型编码为 EDNS 应答报文。

    query/model 的解码与编码契约同 decode_query/encode_response；查询
    AR 限 0 或 1 条，有则须为未压缩根 owner、TYPE41、CLASS512..65535、
    扩展码 0、版本 0..255、flags 仅 DO 的 OPT，其 RDATA 按选项 TLV
    解析（重复项保序，头或数据截断、RDLENGTH 内残缺抛 EDNSError）。
    非法 AR/OPT、截断、尾随或 model 含 OPT 抛 EDNSError。rcode 须非
    bool 整数（类型错 TypeError）：有 OPT 限 0..4095、无 OPT 限
    0..15，越界 EncodeError。options 为应答 OPT 的 TLV 选项表，None
    表示空列表：每项为键序 "code"、"data" 的 dict，code 为 0..65535
    非 bool 整数，data 为 bytes，原序编码且不合并重复 code，RDLENGTH
    精确；容器或字段类型错抛 TypeError，键序错、code 越界、单项 data
    或总 RDATA 超 65535 字节抛 EncodeError。查询无 OPT 时 options
    必须为 None，否则 EncodeError。无 OPT 时上限 min(model.limit,
    512) 且不回 OPT；有 OPT 时上限 min(model.limit, CLASS)，应答 ar
    末项为同 CLASS 根 OPT，TTL=(rcode>>4)<<24|DO，头部低 4 位为
    rcode&15。OPT 版本 1..255 触发版本协商：既有参数校验不变，此外
    model 的 an/ns/ar 须全空、rcode 须为 0、options 须为 None，否则
    EncodeError；通过则返回 BADVERS 应答（flags=0x8400|(查询
    flags&0x7910)，问题重编码，AN=NS=0、AR=1，OPT 为根 owner、
    TYPE41、回显 CLASS 与 DO，TTL=DO?0x01008000:0x01000000，
    RDLENGTH=0），上限 min(model.limit, CLASS)，超限抛 EncodeError
    且不置 TC。版本 0 时编码其余同 encode_response：超限或区段计数超
    16 位时按 RRset 原子截断（每区按规范化 owner、type、class 成组，
    不含 TTL/rdata；ar、ns、an 优先级整组删除并置 TC），OPT 固定保留
    为附加段末项不删不截、其空间先行预留；问题与 OPT 超限抛 EncodeError。
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
    if opt is not None and opt[1] != 0:
        # 版本协商：仅支持 EDNS 版本 0；1..255 以 BADVERS 拒绝，应答不
        # 携带任何 RR 与选项，故要求 model 三段为空、rcode 为 0 且
        # options 为 None。
        if an or ns or ar:
            raise EncodeError("badvers response must have empty sections")
        if rcode:
            raise EncodeError("badvers requires rcode 0")
        if options is not None:
            raise EncodeError("badvers response carries no options")
        return _encode_badvers(msg, opt, limit)
    opt_wire = b""
    if opt is None:
        if options is not None:
            raise EncodeError("options require an OPT record in the query")
        if not 0 <= rcode <= 0xF:
            raise EncodeError("rcode out of range")
        limit = min(limit, _MAX_MESSAGE_LEN)
    else:
        if not 0 <= rcode <= _MAX_EDNS_RCODE:
            raise EncodeError("rcode out of range")
        opt_rdata = _validate_edns_options(options)
        opt_class, _opt_version, do, _query_opts = opt
        limit = min(limit, opt_class)
        ttl = ((rcode >> 4) << 24) | (_FLAG_DO if do else 0)
        opt_wire = (b"\x00" + _TYPE_OPT.to_bytes(2, "big")
                    + opt_class.to_bytes(2, "big") + ttl.to_bytes(4, "big")
                    + len(opt_rdata).to_bytes(2, "big") + opt_rdata)
    # RRset 原子截断：OPT 占 ar 一席且固定为末项不删，model ar 的计数
    # 预算相应减一；先为 OPT 预留空间，普通 RR 按 ar、ns、an 整组淘汰。
    cap_ar = _MAX_SECTION_RECORDS - (1 if opt_wire else 0)
    caps = (_MAX_SECTION_RECORDS, _MAX_SECTION_RECORDS, cap_ar)
    body_limit = limit - len(opt_wire)
    plan = _RRsetPlan(msg, (an, ns, ar), rcode & 0xF, caps)
    plan.fit(body_limit)
    # OPT 固定为附加段末项，不参与 RRset 重组，定稿时追加。
    return plan.finalize(opt_wire, 1 if opt_wire else 0)


def _server_cookie(secret, family, packed, client_cookie):
    """HMAC-SHA256(secret, family+packed IP+客户端值) 的前 16 字节。"""
    digest = hmac.new(secret, family + packed + client_cookie,
                      hashlib.sha256).digest()
    return digest[:_COOKIE_SERVER_LEN]


def edns_cookie(query: bytes, model: dict, secret: bytes, client: str,
                rcode: int = 0) -> bytes:
    """把携带 EDNS(0) COOKIE（选项码 10）的查询编码为 COOKIE 应答。

    query/model/rcode 的其余契约沿用 edns。查询须含版本 0 的 OPT 且
    OPT 中恰有一个 COOKIE；COOKIE data 须恰为 8 字节客户端值，或
    8 字节客户端值后接 16 字节服务端值，否则抛 CookieError；其余选项
    一律忽略、不回显。secret 非 bytes 或 client 非 str 抛 TypeError；
    secret 长度非 16..64 或 client 非合法 IPv4/IPv6 文本抛 CookieError。
    服务端值为 HMAC-SHA256(secret, family+packed+客户端值) 前 16 字节，
    family 为单字节 0x04（IPv4）或 0x06（IPv6），packed 取
    ipaddress 的 packed。未带服务端值或服务端值匹配时按 model、rcode
    应答；不匹配时先完成 model 校验，再以空 an/ns/ar 与扩展 RCODE 23
    应答。应答 OPT 回显 CLASS、DO、版本 0，RDATA 仅含码 10，data 为
    8 字节客户端值加新算的 16 字节服务端值；OPT 固定不删，超限与普通
    RR 的 RRset 原子截断规则沿用 edns。相同参数逐字节一致。
    """
    if not isinstance(query, bytes):
        raise TypeError("query must be bytes")
    _check_int(rcode, "rcode")
    if not isinstance(secret, bytes):
        raise TypeError("secret must be bytes")
    if not isinstance(client, str):
        raise TypeError("client must be str")
    an, ns, ar, limit = _validate_model(model)
    msg, opt = _decode_edns_query(query)
    if opt is None:
        raise CookieError("query must contain an OPT record")
    if opt[1] != 0:
        raise CookieError("OPT version must be 0")
    client_cookie = None
    for code, data in opt[3]:
        if code != _OPT_CODE_COOKIE:
            continue
        if client_cookie is not None:
            raise CookieError("duplicate COOKIE option")
        if len(data) not in (_COOKIE_CLIENT_LEN,
                             _COOKIE_CLIENT_LEN + _COOKIE_SERVER_LEN):
            raise CookieError("COOKIE data must be 8 or 24 bytes")
        client_cookie = data[:_COOKIE_CLIENT_LEN]
        server_cookie = data[_COOKIE_CLIENT_LEN:]
    if client_cookie is None:
        raise CookieError("query must contain exactly one COOKIE option")
    if not _MIN_COOKIE_SECRET_LEN <= len(secret) <= _MAX_COOKIE_SECRET_LEN:
        raise CookieError("secret length must be 16..64 bytes")
    try:
        address = ipaddress.ip_address(client)
    except ValueError:
        raise CookieError("client must be a valid IPv4/IPv6 address") from None
    # 不匹配时也须先暴露 model/查询的既有契约错误，再清空三段应答。
    for section in (an, ns, ar):
        if any(rr[1] == _TYPE_OPT for rr in section):
            raise EDNSError("model must not contain OPT records")
    if msg["flags"] & 0x8000:
        raise EncodeError("query has QR set")
    if not _MIN_LIMIT <= limit <= _MAX_LIMIT:
        raise EncodeError("limit out of range")
    if not 0 <= rcode <= _MAX_EDNS_RCODE:
        raise EncodeError("rcode out of range")
    if isinstance(address, ipaddress.IPv4Address):
        family = bytes((_FAMILY_IPV4,))
    else:
        family = bytes((_FAMILY_IPV6,))
    expected = _server_cookie(secret, family, address.packed, client_cookie)
    options = [{"code": _OPT_CODE_COOKIE,
                "data": client_cookie + expected}]
    if server_cookie and not hmac.compare_digest(server_cookie, expected):
        # 服务端值存在但不匹配：model 已先校验，再清空三段以 BADCOOKIE 应答。
        model = {"an": [], "ns": [], "ar": [], "limit": limit}
        rcode = _RCODE_BADCOOKIE
    return edns(query, model, rcode, options)


def edns_padded(query: bytes, model: dict, block: int = 128,
                rcode: int = 0) -> bytes:
    """把（可含 OPT 的）查询报文编码为 EDNS(0) Padding（选项码 12）应答。

    query/model/rcode 的契约沿用 edns；查询须恰有一个 OPT，否则抛
    EDNSError。block 为填充块长：非 int 或为 bool 抛 TypeError，非
    16..512 内 2 的幂抛 EncodeError。OPT 版本 1..255 时在全部参数
    校验后返回既有 BADVERS 应答（同 edns 的版本协商契约：model 三段
    须空、rcode 须为 0），不填充。版本 0 查询中 Padding 选项至多一
    项且 data 全零，否则抛 EDNSError；其余选项一律忽略、不回显。
    应答 OPT 仅含一个 Padding TLV：按 ar、ns、an 的 RRset 整组淘汰顺序
    枚举候选（优先保留最多普通 RR，每区按规范化 owner、type、class
    成组，不含 TTL/rdata，删除该组在区内全部成员即使不相邻），B 为
    候选含零长 TLV 时的报文长度，n=(-B)%block，取首个
    B+n≤min(model.limit, OPT CLASS) 的候选并写 n 个零（n=0 仍保留
    TLV）；无候选抛 EncodeError。OPT 不删不截，仅删过普通 RRset 才置
    TC；标志、扩展 RCODE、名称压缩与其余异常沿用 edns。相同参数逐字节
    一致，时空 O(报文长+RR 数)。
    """
    if not isinstance(query, bytes):
        raise TypeError("query must be bytes")
    _check_int(rcode, "rcode")
    _check_int(block, "block")
    an, ns, ar, limit = _validate_model(model)
    msg, opt = _decode_edns_query(query)
    if opt is None:
        raise EDNSError("query must contain an OPT record")
    for section in (an, ns, ar):
        if any(rr[1] == _TYPE_OPT for rr in section):
            raise EDNSError("model must not contain OPT records")
    if msg["flags"] & 0x8000:
        raise EncodeError("query has QR set")
    if not _MIN_LIMIT <= limit <= _MAX_LIMIT:
        raise EncodeError("limit out of range")
    if not 0 <= rcode <= _MAX_EDNS_RCODE:
        raise EncodeError("rcode out of range")
    if (not _MIN_PADDING_BLOCK <= block <= _MAX_PADDING_BLOCK
            or block & (block - 1)):
        raise EncodeError("block must be a power of 2 in 16..512")
    if opt[1] != 0:
        # 版本协商：全部参数校验完成后按 edns 的 BADVERS 契约应答，不填充。
        if an or ns or ar:
            raise EncodeError("badvers response must have empty sections")
        if rcode:
            raise EncodeError("badvers requires rcode 0")
        return _encode_badvers(msg, opt, limit)
    # 版本 0：查询 Padding 至多一项且 data 全零，其余选项不回显。
    seen_padding = False
    for code, data in opt[3]:
        if code != _OPT_CODE_PADDING:
            continue
        if seen_padding:
            raise EDNSError("duplicate PADDING option")
        if any(data):
            raise EDNSError("PADDING data must be all zeros")
        seen_padding = True
    opt_class, _opt_version, do, _query_opts = opt
    limit = min(limit, opt_class)
    ttl = ((rcode >> 4) << 24) | (_FLAG_DO if do else 0)
    # OPT 占 ar 一席且固定为末项；计数超限时先做 RRset 原子预修剪。
    caps = (_MAX_SECTION_RECORDS, _MAX_SECTION_RECORDS,
            _MAX_SECTION_RECORDS - 1)
    plan = _RRsetPlan(msg, (an, ns, ar), rcode & 0xF, caps)
    # OPT 固定部分（根 owner、TYPE41、CLASS、TTL）与零长 TLV 的字节数。
    opt_fixed = (b"\x00" + _TYPE_OPT.to_bytes(2, "big")
                 + opt_class.to_bytes(2, "big") + ttl.to_bytes(4, "big"))
    zero_tlv_len = len(opt_fixed) + 2 + 4  # RDLENGTH 字段 + 零长 TLV
    # 候选按 ar、ns、an 的 RRset 整组淘汰顺序枚举，优先保留最多普通 RR：
    # 每淘汰一组维护一次热前缀/冷长度记账，B 为候选含零长 TLV 时的
    # 报文长度（=热前缀+冷记录+零长 TLV）。
    chosen_pad = None
    while True:
        msg_len = plan.body_len() + zero_tlv_len  # B
        pad = (-msg_len) % block
        if msg_len + pad <= limit:
            chosen_pad = pad
            break
        section = next((i for i in (2, 1, 0)
                        if plan.counts[i] > 0), None)
        if section is None:
            raise EncodeError("no padding candidate fits the limit")
        plan.drop_last_group(section)
    tlv = (_OPT_CODE_PADDING.to_bytes(2, "big")
           + chosen_pad.to_bytes(2, "big") + b"\x00" * chosen_pad)
    opt_wire = opt_fixed + (4 + chosen_pad).to_bytes(2, "big") + tlv
    # OPT 固定为附加段末项，不参与 RRset 重组，定稿时追加。
    return plan.finalize(opt_wire, 1)


def edns_ede(query: bytes, model: dict, info_code: int, text: str = "",
             rcode: int = 0) -> bytes:
    """把携带 OPT 的查询编码为 EDNS(0) EDE（选项码 15）应答。

    query/model/rcode 与 RR 编码的契约沿用 edns。查询须恰含一个版本
    0 的 OPT，缺失或版本非 0 抛 EDEError；查询选项一律忽略、不回显。
    info_code 为非 bool 的 0..65535 整数，text 为 str；类型错抛
    TypeError，info_code 越界、text 含代理码点或 UTF-8 编码超 65529
    字节抛 EncodeError。应答 ar 末项为同 CLASS 根 OPT，回显 DO、版本
    0，扩展 RCODE 取 rcode>>4、头部低 4 位取 rcode&15，RDATA 仅含一
    个 EDE TLV：code=15、length=2+text 的 UTF-8 字节数、data 为网络
    序 uint16 info_code 后接 text 的 UTF-8 字节（可为空）。上限
    min(model.limit, OPT CLASS)；超限或区段计数超 16 位时按 RRset 原子
    截断（ar、ns、an 优先级，整组删除并置 TC），OPT 不删不截，删空仍
    超限抛 EncodeError。其余错误沿用 edns。
    相同参数逐字节一致，时空 O(报文长+RR 数)。
    """
    if not isinstance(query, bytes):
        raise TypeError("query must be bytes")
    _check_int(rcode, "rcode")
    _check_int(info_code, "info_code")
    if not isinstance(text, str):
        raise TypeError("text must be str")
    an, ns, ar, limit = _validate_model(model)
    msg, opt = _decode_edns_query(query)
    if opt is None:
        raise EDEError("query must contain an OPT record")
    if opt[1] != 0:
        raise EDEError("OPT version must be 0")
    for section in (an, ns, ar):
        if any(rr[1] == _TYPE_OPT for rr in section):
            raise EDNSError("model must not contain OPT records")
    if msg["flags"] & 0x8000:
        raise EncodeError("query has QR set")
    if not _MIN_LIMIT <= limit <= _MAX_LIMIT:
        raise EncodeError("limit out of range")
    if not 0 <= rcode <= _MAX_EDNS_RCODE:
        raise EncodeError("rcode out of range")
    if not 0 <= info_code <= 0xFFFF:
        raise EncodeError("info_code out of range")
    try:
        text_bytes = text.encode("utf-8")
    except UnicodeEncodeError:
        raise EncodeError("text must be encodable as UTF-8") from None
    if len(text_bytes) > _MAX_EDE_TEXT_LEN:
        raise EncodeError("text exceeds 65529 UTF-8 bytes")
    options = [{"code": _OPT_CODE_EDE,
                "data": info_code.to_bytes(2, "big") + text_bytes}]
    return edns(query, model, rcode, options)


def _rr_to_model(rr):
    """把规范化 RR 元组还原为键序固定的模型 dict。"""
    labels, rrtype, rrclass, ttl, rdata = rr
    return {"name": _labels_to_name(labels), "type": rrtype,
            "class": rrclass, "ttl": ttl, "rdata": rdata}


def _transfer_rr_model(rr):
    """把规范化 RR 元组还原为传送用 dict：键序 name,type,class,ttl,rdata，
    rdata 为偶长小写十六进制字符串。"""
    labels, rrtype, rrclass, ttl, rdata = rr
    return {"name": _labels_to_name(labels), "type": rrtype,
            "class": rrclass, "ttl": ttl, "rdata": rdata.hex()}


def _zone_soa_serial(records, origin):
    """返回 origin 唯一 SOA rdata 中的序列号（五个网络序 uint32 之首）。

    rdata 不符两个未压缩绝对名加五个 uint32 格式时返回 None，不抛异常。
    """
    soa = [rr for rr in records
           if rr[0] == origin and rr[1] == _TYPE_SOA][0]
    offset = _parse_soa_uint32_offset(soa[4])
    if offset is None:
        return None
    return int.from_bytes(soa[4][offset:offset + 4], "big")


def _snapshot_records(snapshot):
    """校验历史快照，返回 (origin 标签列表, 规范化 RR 原序列表)。"""
    origin, records, _zone_class = _validate_zone(snapshot)
    return origin, records


def _rr_diff_key(rr):
    """RR 五字段求差用哈希键（规范化元组的 labels 为 list，转为 tuple）。"""
    return (tuple(rr[0]), rr[1], rr[2], rr[3], rr[4])


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
    wildcard = [_WILDCARD_LABEL] + encloser
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


def _embedded_glue_target(rr):
    """取 NS/MX/SRV rdata 中的地址目标标签列表，其余类型或结构非法返回 None。

    NS 取整个 rdata 的未压缩绝对名；MX 跳过两字节 preference 后取名；
    SRV 跳过 priority、weight、port 共六字节后取名。嵌入名若不是完整
    未压缩绝对名（截断、含压缩指针、尾随字节等区域层宽松兼容形态）则
    返回 None：调用方正常输出原记录但不据此生成附加记录，不抛异常。
    """
    rrtype = rr[1]
    rdata = rr[4]
    if rrtype == _TYPE_NS:
        payload = rdata
    elif rrtype == _TYPE_MX:
        if len(rdata) < 2:
            return None
        payload = rdata[2:]  # 跳过两字节 preference
    elif rrtype == _TYPE_SRV:
        if len(rdata) < 6:
            return None
        payload = rdata[6:]  # 跳过 priority、weight、port 共六字节
    else:
        return None
    try:
        labels, end = _decode_wire_name(payload, RecordError)
    except ValueError:
        return None
    if end != len(payload):
        # 嵌入名后有尾随字节（区域层宽松兼容形态）：不出附加项。
        return None
    return labels


def _glue_addresses(an, ns, origin, records):
    """按确定性顺序为权威计划收集区域内地址附加记录，返回附加段 RR 列表。

    依次观察 ANSWER 后 AUTHORITY 中现有顺序的 NS、MX、SRV；目标取 NS
    整个 rdata、MX 跳过两字节 preference 后、SRV 跳过六字节
    priority/weight/port 后的嵌入名。目标须为 origin 内的非根全名，
    结构非法（区域层宽松兼容）、根目标或域外目标均跳过。每个规范化
    目标只处理一次（按其在 ANSWER 后 AUTHORITY 中首次出现的顺序）；
    同一目标沿用区域记录原顺序收集 owner 与其精确相等的 A、AAAA，不
    以通配记录合成、不追随目标处的 CNAME，区域原有重复记录不归并。
    候选数与临时内存以区域记录数为线性上界。
    """
    targets = []
    seen = set()
    for section in (an, ns):
        for rr in section:
            if rr[1] not in (_TYPE_NS, _TYPE_MX, _TYPE_SRV):
                continue
            labels = _embedded_glue_target(rr)
            if labels is None or not labels:
                continue  # 宽松兼容的不完整嵌入名或根目标：不出附加项
            if (len(labels) < len(origin)
                    or labels[len(labels) - len(origin):] != origin):
                continue  # 域外目标：不出附加项
            target = tuple(labels)
            if target in seen:
                continue
            seen.add(target)
            targets.append(labels)
    if not targets:
        return []
    wanted = frozenset(tuple(labels) for labels in targets)
    addresses = {}
    for rr in records:
        if rr[1] not in (_TYPE_A, _TYPE_AAAA):
            continue
        owner = tuple(rr[0])
        if owner in wanted:
            # 仅 owner 与目标精确相等的 A/AAAA；通配 owner（首标签 "*"）
            # 不等于任何目标，自然排除；目标处的 CNAME 不追随。
            addresses.setdefault(owner, []).append(rr)
    additional = []
    for labels in targets:
        additional.extend(addresses.get(tuple(labels), ()))
    return additional


def _answer_plan(msg, origin, records, zone_class):
    """answer 的完整（未截断）应答计划，返回 (rcode, an, ns, ar)。

    msg 为已解码且通过可应答性检查的单问题查询；zone 已校验，
    RR 均为规范化元组。ar 为按 NS/MX/SRV 嵌入目标从区域确定性收集的
    精确 owner A/AAAA 地址附加记录（不通配合成、不追随 CNAME）。
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
    # 对最终计划的 ANSWER、AUTHORITY 统一观察 NS/MX/SRV 收集地址附加项；
    # REFUSED 的空段与域外/NXDOMAIN/NODATA 的 SOA-only 授权段均不含
    # NS/MX/SRV 目标，自然不产生附加项，RCODE、AA、ANSWER、AUTHORITY 不变。
    ar = _glue_addresses(an, ns, origin, records)
    return rcode, an, ns, ar


def _encode_plan(query, rcode, an, ns, limit, ecs=None, ar=None):
    """把完整应答计划编码为权威应答报文。

    ecs 仅 EDNS 变体使用，普通解析路径恒为 None 并忽略。ar 为权威计划
    确定性生成的地址附加记录；None 按空附加段处理（递归终态等非权威
    生成路径沿用空 ar，显式 ar 仅经 encode_response 模型入口提供）。
    """
    model = {
        "an": [_rr_to_model(rr) for rr in an],
        "ns": [_rr_to_model(rr) for rr in ns],
        "ar": [_rr_to_model(rr) for rr in (ar if ar is not None else ())],
        "limit": limit,
    }
    return _encode_response(query, model, rcode)


def _encode_plan_edns(query, rcode, an, ns, limit, ecs=None, ar=None):
    """把完整应答计划按 edns 契约编码为应答报文（查询含 OPT 时末项回显）。

    ar 为权威计划确定性生成的地址附加记录，置于应答 OPT 之前，OPT 仍
    为附加段唯一末项；None 按空附加段处理。ecs 非 None 时应答 OPT 仅
    回写该 ECS（码 8）选项：family、source 不变，scope=source，
    address 同查询；查询携带的其他选项不回显。
    """
    model = {
        "an": [_rr_to_model(rr) for rr in an],
        "ns": [_rr_to_model(rr) for rr in ns],
        "ar": [_rr_to_model(rr) for rr in (ar if ar is not None else ())],
        "limit": limit,
    }
    options = None
    if ecs is not None:
        family, source, address = ecs
        options = [{"code": _OPT_CODE_ECS,
                    "data": _encode_ecs_option(family, source, source,
                                               address)}]
    return edns(query, model, rcode, options)


def _encode_policy_refusal(query, limit):
    """把单问题查询编码为授权拒绝应答（RCODE=5，三段为空）。

    ID 保留，问题按规范化 qname/qtype/qclass 重编码；flags 为
    QR|AA|(查询 flags 的 opcode/RD/CD 位)|REFUSED，QDCOUNT=1，
    ANCOUNT/NSCOUNT/ARCOUNT 均为 0（不回显 OPT）。仅头部与问题超
    limit 抛 EncodeError，其余报文非法已由调用方校验排除。
    """
    _check_int(limit, "limit")
    if not _MIN_LIMIT <= limit <= _MAX_LIMIT:
        raise EncodeError("limit out of range")
    msg = decode_query(query)
    out = bytearray()
    out += msg["id"].to_bytes(2, "big")
    flags = (_FLAGS_RESPONSE | (msg["flags"] & _FLAGS_KEPT)
             | _RCODE_REFUSED)
    out += flags.to_bytes(2, "big")
    out += (1).to_bytes(2, "big")
    out += (0).to_bytes(6)  # ANCOUNT/NSCOUNT/ARCOUNT 均为 0
    _write_name(out, _normalize_name(msg["questions"][0]["name"]), {})
    question = msg["questions"][0]
    out += question["type"].to_bytes(2, "big")
    out += question["class"].to_bytes(2, "big")
    if len(out) > limit:
        raise EncodeError("header and question exceed limit")
    return bytes(out)


def answer(query: bytes, zone: dict, limit: int = 512) -> bytes:
    """按 zone 对查询报文给出确定性权威应答（支持最左 "*" 通配与 CNAME 链）。"""
    msg = decode_query(query)  # MessageError/TypeError 原样传播
    _check_int(limit, "limit")
    questions = msg["questions"]
    if (msg["flags"] & 0x8000 or len(questions) != 1
            or not _MIN_LIMIT <= limit <= _MAX_LIMIT):
        raise EncodeError("query or limit not answerable")
    origin, records, zone_class = _validate_zone(zone)
    rcode, an, ns, ar = _answer_plan(msg, origin, records, zone_class)
    return _encode_plan(query, rcode, an, ns, limit, ar=ar)


def _config_pairs(pairs):
    """json object_pairs_hook：保序构造 dict，重复键抛 ConfigError。"""
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ConfigError("duplicate key")
        obj[key] = value
    return obj


def _replay_log_pairs(pairs):
    """json object_pairs_hook：保序构造 dict，重复键抛 ReplayError。"""
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ReplayError("duplicate key")
        obj[key] = value
    return obj


def _parse_replay_forward_log(text):
    """解析并结构预检 replay_forward 的日志文本，返回项列表（不执行）。

    text 已由调用方限定为不超过 1048576 码点的 ASCII str。日志须为
    ASCII JSON 对象：顶层键序仅 v,o，v 恒为 1；o 为含 0..4096 项的
    数组（空 o 为合法空操作），同一日志内旧三键项（键序仅 k,x,e）与
    forward_audit 五键项（键序仅 k,x,e,r,a）可混用。k 仅 "l"/"r"：
    k="l" 时 x 为 str（migrate_forward 配置文本，其内容与长度由配置
    预检阶段收口），k="r" 时 x 为非负非 bool 整数（rollback 目标
    版本）；e 为非负非 bool 整数（步骤前暂存预期版本）。五键项另须
    r 为 "applied"/"unchanged"、a 为非负非 bool 整数（声明的步骤后
    版本），由执行预检阶段与隔离推演结果逐项核对。JSON 解析（含超长
    整数、超深嵌套）、重复键、顶层/项键序、v、容器与字段类型、项
    数量或取值错误统一抛 ReplayError，不泄漏 json 异常。
    """
    try:
        log = json.loads(text, object_pairs_hook=_replay_log_pairs)
    except ReplayError:
        # 重复键由 _replay_log_pairs 抛 ReplayError，原样传播。
        raise
    except (json.JSONDecodeError, RecursionError, ValueError):
        # json 对超长整数抛非 JSONDecodeError 的 ValueError、对超深
        # 嵌套抛 RecursionError，统一归为 ReplayError，不泄漏 json 异常。
        raise ReplayError("invalid JSON") from None
    if not isinstance(log, dict):
        raise ReplayError("log must be an object")
    if list(log.keys()) != _REPLAY_FORWARD_KEYS:
        raise ReplayError("log keys must be v,o")
    version = log["v"]
    if (not isinstance(version, int) or isinstance(version, bool)
            or version != 1):
        raise ReplayError("unsupported v")
    items = log["o"]
    if not isinstance(items, list):
        raise ReplayError("o must be list")
    if not 0 <= len(items) <= _MAX_FORWARD_AUDIT_OPS:
        raise ReplayError("o must contain 0..4096 items")
    checked = []
    for item in items:
        if not isinstance(item, dict):
            raise ReplayError("item must be dict")
        keys = list(item.keys())
        if keys == _REPLAY_FORWARD_ITEM_KEYS:
            audited = False
        elif keys == _REPLAY_FORWARD_AUDIT_ITEM_KEYS:
            audited = True
        else:
            raise ReplayError("item keys must be k,x,e or k,x,e,r,a")
        kind = item["k"]
        if not isinstance(kind, str) or kind not in _REPLAY_FORWARD_OPS:
            raise ReplayError('k must be "l" or "r"')
        value = item["x"]
        if kind == "l":
            if not isinstance(value, str):
                raise ReplayError("x must be str when k is l")
        elif not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ReplayError("x must be a non-negative int when k is r")
        expected = item["e"]
        if (not isinstance(expected, int) or isinstance(expected, bool)
                or expected < 0):
            raise ReplayError("e must be a non-negative int")
        if audited:
            result = item["r"]
            if (not isinstance(result, str)
                    or result not in _REPLAY_FORWARD_RESULTS):
                raise ReplayError('r must be "applied" or "unchanged"')
            after = item["a"]
            if (not isinstance(after, int) or isinstance(after, bool)
                    or after < 0):
                raise ReplayError("a must be a non-negative int")
        else:
            result = None
            after = None
        checked.append((kind, value, expected, result, after))
    return checked


def _atomic_write_file(path, data, prefix):
    """把 data 逐字节原子写入 path（save_state 与 export_log 共用）。

    在目标同目录创建唯一临时文件（path 无目录成分时以当前目录为同
    目录，os.replace 才能在同一文件系统内原子改名），循环 write 至
    全部字节写完（write 返回 None、非 int 或非正数抛 OSError），
    flush、fsync 后以 os.replace 原子替换目标。任一步 I/O 失败抛
    OSError，删除本次临时文件、保留旧目标文件。
    """
    directory = os.path.dirname(path) or os.curdir
    fd, tmp_path = tempfile.mkstemp(prefix=prefix, suffix=".tmp",
                                    dir=directory)
    try:
        with os.fdopen(fd, "wb") as stream:
            # 循环写至全部字节落盘：write 短写返回已写字节数；返回
            # None、非 int（含 bool）或非正数视为 I/O 失败。
            offset = 0
            while offset < len(data):
                written = stream.write(data[offset:])
                if (not isinstance(written, int)
                        or isinstance(written, bool) or written <= 0):
                    raise OSError("write returned no progress")
                offset += written
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        # 失败：临时项绝不残留；replace 未成功则旧目标保持原样。
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


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
    return _check_zone_config(config)


def _check_zone_config(config):
    """对已解析的 v0/v1/v2 配置对象做结构层校验，返回 (zone dict, version)。

    校验规则与 _parse_zone_config 的文本解析后部分一致（版本、键序、
    字段类型、布尔整数与十六进制），错误统一抛 ConfigError。
    """
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
    return {"version": 2, "origin": _labels_to_name(origin_labels, wildcard=False),
            "class": zone_class, "records": records}


def _zone_model_to_v2(model):
    """把规范化 zone 模型（键序 origin,records）组装为 v2 配置对象。

    记录保持原序，项键序 name,type,ttl,rdata，rdata 为偶长小写十六
    进制；统一 class 取自首条记录（zone 规则已保证全类一致且至少
    含一条 SOA）。
    """
    records = []
    for rr in model["records"]:
        records.append({"name": rr["name"], "type": rr["type"],
                        "ttl": rr["ttl"], "rdata": rr["rdata"].hex()})
    return {"version": 2, "origin": model["origin"],
            "class": model["records"][0]["class"], "records": records}


def _load_zone_snapshot(zone):
    """校验 dump_zones 历史中的 v2 zone 对象，返回规范化 zone 模型。

    结构错误（键序、版本、字段类型、布尔整数、十六进制）抛
    ConfigError；zone 语义错误沿用 RecordError、ZoneError。
    """
    if not isinstance(zone, dict):
        raise ConfigError("zone must be an object")
    if list(zone.keys()) != _CONFIG_KEYS_V2:
        raise ConfigError("zone keys must be version,origin,class,records")
    parsed, _version = _check_zone_config(zone)
    origin, rrs, _zone_class = _validate_zone(parsed)
    return {"origin": _labels_to_name(origin, wildcard=False),
            "records": [_rr_to_model(rr) for rr in rrs]}


def _load_zone_snapshot_any(zone):
    """校验旧格式历史中的 v0/v1/v2 zone 配置对象，返回规范化 zone 模型。

    与 _load_zone_snapshot 相同但接受 migrate_zone 的 v0/v1/v2 三种
    对象契约：结构错误（非对象、键序、版本、字段类型、布尔整数、
    十六进制）抛 ConfigError；zone 语义错误沿用 RecordError、ZoneError。
    """
    if not isinstance(zone, dict):
        raise ConfigError("zone must be an object")
    parsed, _version = _check_zone_config(zone)
    origin, rrs, _zone_class = _validate_zone(parsed)
    return {"origin": _labels_to_name(origin, wildcard=False),
            "records": [_rr_to_model(rr) for rr in rrs]}


def _parse_zones_config(text):
    """解析 schema=0/1 的 zones 配置文本（结构层校验）。

    返回 (schema, version, history 原始列表)。仅做 JSON 解析与结构层
    校验：重复键、顶层/项键序、schema 与 revision/version 的类型
    （非 bool 整数）、version/revision 非负且严格递增、末项等于顶层
    version、历史数量（schema=0 限 1..256 项，schema=1 限 1..32 项）。
    text 非 str 抛 TypeError；其余结构错误统一抛 ConfigError。各 zone
    快照不在此校验，由调用方先全部校验再截断、恢复或迁移。
    """
    if not isinstance(text, str):
        raise TypeError("text must be str")
    try:
        config = json.loads(text, object_pairs_hook=_config_pairs)
    except json.JSONDecodeError:
        raise ConfigError("invalid JSON") from None
    if not isinstance(config, dict):
        raise ConfigError("config must be an object")
    if list(config.keys()) != _ZONES_DUMP_KEYS:
        raise ConfigError("config keys must be schema,version,history")
    schema = config["schema"]
    if not isinstance(schema, int) or isinstance(schema, bool):
        raise ConfigError("schema must be int")
    if schema not in (0, 1):
        raise ConfigError("unsupported schema")
    version = config["version"]
    if not isinstance(version, int) or isinstance(version, bool):
        raise ConfigError("version must be int")
    if version < 0:
        raise ConfigError("version must be non-negative")
    history = config["history"]
    if not isinstance(history, list):
        raise ConfigError("history must be list")
    capacity = (_ZONES_LOAD_HISTORY_LIMIT_V0 if schema == 0
                else _ZONE_HISTORY_CAPACITY)
    if not 1 <= len(history) <= capacity:
        raise ConfigError(
            "history must contain 1.." + str(capacity) + " items")
    # 结构层校验（项键序、revision 类型与严格递增、末项等于顶层
    # version）全部先于各 zone 快照校验完成。
    revisions = []
    for item in history:
        if not isinstance(item, dict):
            raise ConfigError("history item must be an object")
        if list(item.keys()) != _ZONES_HISTORY_ITEM_KEYS:
            raise ConfigError("history item keys must be revision,zone")
        revision = item["revision"]
        if not isinstance(revision, int) or isinstance(revision, bool):
            raise ConfigError("revision must be int")
        if revision < 0:
            raise ConfigError("revision must be non-negative")
        if revisions and revision <= revisions[-1]:
            raise ConfigError("revisions must be strictly increasing")
        revisions.append(revision)
    if revisions[-1] != version:
        raise ConfigError("last history revision must equal version")
    return schema, version, history


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


def migrate_zones(text: str) -> str:
    """把 schema=0/1 区域历史配置文本完整校验并迁移为 schema=1 文本。

    顶层键序仅 schema,version,history：schema 为非 bool 整数 0 或 1，
    version 为非负非 bool 整数；history 项键序仅 revision,zone，
    revision 为严格递增的非负非 bool 整数且末项等于顶层 version。
    schema=0（旧格式）的 history 限 1..256 项，schema=1 限 1..32 项；
    各 zone 沿用 migrate_zone 的 v0/v1/v2 对象契约（v0/v1 键序
    version,origin,records，记录末键分别为 data/rdata；v2 键序
    version,origin,class,records）。先校验全部快照（结构层校验先于
    快照语义校验，任何失败均不产生输出），再仅保留 revision 最大的
    32 项并把 zone 规范化迁移为 v2。输出沿用现有 schema=1 格式：
    schema 为 1，version 保持不变，history 按 revision 升序、项键序
    revision,zone；紧凑 ASCII JSON、十进制整数、rdata 为偶长小写
    十六进制、末尾单换行；同输入逐字节一致，schema=1 输入等价于
    dump_zones 风格文本（规范化后逐字节不变）。text 非 str 抛
    TypeError；JSON 解析、重复键、键序、未知 schema、版本关系、数量
    或 zone 结构错误抛 ConfigError；zone 语义错误沿用 RecordError、
    ZoneError。
    """
    schema, version, history = _parse_zones_config(text)
    # 先校验全部快照：schema=1 的 zone 必须为 v2，旧格式接受
    # v0/v1/v2；结构错误抛 ConfigError，语义错误沿用
    # RecordError、ZoneError；全部通过后才截断与组装。
    snapshot_loader = (_load_zone_snapshot if schema == 1
                       else _load_zone_snapshot_any)
    snapshots = [(item["revision"], snapshot_loader(item["zone"]))
                 for item in history]
    kept = snapshots[-_ZONE_HISTORY_CAPACITY:]
    migrated_history = [{
        "revision": revision,
        "zone": _zone_model_to_v2(zone),
    } for revision, zone in kept]
    config = {"schema": 1, "version": version,
              "history": migrated_history}
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
    return {"origin": _labels_to_name(origin_labels, wildcard=False),
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
    config = {"version": 1, "origin": _labels_to_name(origin, wildcard=False),
              "records": records}
    return json.dumps(config, ensure_ascii=True, separators=(",", ":")) + "\n"


_MASTER_DIRECTIVE = "$ORIGIN"
_MASTER_CLASS = "IN"
_MASTER_TYPES = {"A": _TYPE_A, "NS": _TYPE_NS, "CNAME": _TYPE_CNAME,
                 "MX": _TYPE_MX, "TXT": _TYPE_TXT,
                 "AAAA": _TYPE_AAAA, "SRV": _TYPE_SRV,
                 "NAPTR": _TYPE_NAPTR, "DS": _TYPE_DS,
                 "RRSIG": _TYPE_RRSIG,
                 "NSEC": _TYPE_NSEC,
                 "DNSKEY": _TYPE_DNSKEY, "CDS": _TYPE_CDS,
                 "CDNSKEY": _TYPE_CDNSKEY, "CAA": _TYPE_CAA,
                 "SOA": _TYPE_SOA}
# NSEC 位图允许的类型码 -> 助记符（_MASTER_TYPES 的逆映射，码值唯一）。
_NSEC_TYPE_NAMES = {code: name for name, code in _MASTER_TYPES.items()}
_MASTER_HEADER_TOKENS = 4  # owner ttl IN TYPE


def _master_parse_uint32(token):
    """把十进制 token 解析为 uint32；允许任意前导零，非纯 ASCII 数字
    （含符号、空白、Unicode 数字）或越界抛 ConfigError。先去前导零并
    按位数裁剪，避免超长数字串触发解释器整数转换限制。"""
    if not token or not token.isascii() or not token.isdigit():
        raise ConfigError("invalid uint32 decimal")
    digits = token.lstrip("0") or "0"
    if len(digits) > 10:
        raise ConfigError("uint32 out of range")
    value = int(digits)
    if value > _MAX_TTL:
        raise ConfigError("uint32 out of range")
    return value


def _master_parse_uint16(token):
    """把十进制 token 解析为 uint16；允许任意前导零，非纯 ASCII 数字
    （含符号、空白、Unicode 数字）或越界抛 ConfigError。"""
    if not token or not token.isascii() or not token.isdigit():
        raise ConfigError("invalid uint16 decimal")
    digits = token.lstrip("0") or "0"
    if len(digits) > 5:
        raise ConfigError("uint16 out of range")
    value = int(digits)
    if value > 0xFFFF:
        raise ConfigError("uint16 out of range")
    return value


def _master_parse_uint8(token):
    """把十进制 token 解析为 uint8；允许任意前导零，非纯 ASCII 数字
    （含符号、空白、Unicode 数字）或越界抛 ConfigError。"""
    if not token or not token.isascii() or not token.isdigit():
        raise ConfigError("invalid uint8 decimal")
    digits = token.lstrip("0") or "0"
    if len(digits) > 3:
        raise ConfigError("uint8 out of range")
    value = int(digits)
    if value > 0xFF:
        raise ConfigError("uint8 out of range")
    return value


def _master_is_printable(ch):
    """主文件引号串内可直接书写的可打印 ASCII：0x20..0x7E。"""
    return 0x20 <= ord(ch) <= 0x7E


def _master_parse_quoted(rest, pos):
    """从 rest[pos]（须恰为双引号）解析一个引号串，返回 (bytes, 下一偏移)。

    串内仅接受可打印 ASCII（0x20..0x7E），转义仅 "\\"、"\"" 或
    三位十进制 "\\DDD"（000..255）；未终止或转义非法抛 ConfigError。
    """
    length = len(rest)
    if pos >= length or rest[pos] != '"':
        raise ConfigError("quoted string must start with a quote")
    pos += 1
    out = bytearray()
    while True:
        if pos >= length:
            raise ConfigError("quoted string not terminated")
        ch = rest[pos]
        if ch == '"':
            return bytes(out), pos + 1
        if ch == "\\":
            if pos + 1 >= length:
                raise ConfigError("bad escape")
            escaped = rest[pos + 1]
            if escaped == "\\" or escaped == '"':
                out.append(ord(escaped))
                pos += 2
            else:
                if pos + 4 > length:
                    raise ConfigError("bad escape")
                digits = rest[pos + 1:pos + 4]
                if not digits.isascii() or not digits.isdigit():
                    raise ConfigError("bad escape")
                value = int(digits)
                if value > 0xFF:
                    raise ConfigError("escape out of range")
                out.append(value)
                pos += 4
            continue
        if not _master_is_printable(ch):
            raise ConfigError("quoted string must be printable ASCII")
        out.append(ord(ch))
        pos += 1


def _master_parse_txt_rdata(rest):
    """把 TXT rdata 原文解析为 1..255 个 bytes 段（引号内允许空白）。

    rest 为行中 TYPE 之后的原文（split(None, 4) 所得，无首部空白，
    可能保留尾部空白）；每段须为双引号串，段间以 ASCII 空白分隔。
    串内规则同 _master_parse_quoted；每段解码后 ≤255 字节。字段数、
    引号或转义非法抛 ConfigError。
    """
    segments = []
    pos = 0
    length = len(rest)
    while True:
        segment, pos = _master_parse_quoted(rest, pos)
        if len(segment) > 0xFF:
            raise ConfigError("TXT segment exceeds 255 bytes")
        segments.append(segment)
        if pos == length:
            break
        if not rest[pos].isspace():
            raise ConfigError("TXT strings must be separated by whitespace")
        # 跳过段间（含行末）ASCII 空白；行末空白与其他类型一样忽略，
        # 行中空白之后由循环顶部要求紧接下一段的双引号。
        while pos < length and rest[pos].isspace():
            pos += 1
        if pos == length:
            break
    if not 1 <= len(segments) <= 0xFF:
        raise ConfigError("TXT rdata must contain 1..255 strings")
    return segments


def _master_txt_rdata(segments):
    """把解码后的 TXT 段依次编码为「一字节长度+内容」的 rdata。"""
    rdata = bytearray()
    for segment in segments:
        rdata.append(len(segment))
        rdata.extend(segment)
    return bytes(rdata)


# CAA tag：1..15 字节，字符仅小写字母/数字/连字符。
_CAA_TAG_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")
_CAA_MAX_TAG_LEN = 15
# DNSKEY/CDNSKEY：固定 protocol=3；公钥解码后 1..65531 字节（连同 4 字节
# 头恰不超 65535 字节 rdata）。
_DNSKEY_PROTOCOL = 3
_DNSKEY_MIN_KEY_LEN = 1
_DNSKEY_MAX_KEY_LEN = 65531
# DS/CDS：digest type 1/2/4 的摘要字节长度（对应 40/64/96 个十六进制
# 字符）；CDS 另允许 RFC 8078 删除标记，文本恰为 "0 0 0 00"：
# keytag、algorithm、digesttype 均为 0，digest 为单个 0x00 字节。
_DS_DIGEST_LEN = {1: 20, 2: 32, 4: 48}


def _master_valid_caa_tag(tag):
    return (1 <= len(tag) <= _CAA_MAX_TAG_LEN
            and all(ch in _CAA_TAG_CHARS for ch in tag))


def _master_parse_caa_rdata(rest):
    """把 CAA rdata 原文解析为 (flags, tag bytes, value bytes)。

    rest 为行中 TYPE 之后的原文，形如 'flags tag "value"'：flags 为
    uint8 十进制，tag 为 1..15 字节小写 [a-z0-9-]，value 为单个双引号
    串（可为空，引号内允许空白），引号后仅可余 ASCII 空白。字段数、
    整数、tag、引号或转义非法抛 ConfigError。
    """
    parts = rest.split(None, 2)
    if len(parts) != 3:
        raise ConfigError("CAA rdata must be flags tag and value")
    flags_token, tag, value_rest = parts
    flags = _master_parse_uint8(flags_token)
    if not _master_valid_caa_tag(tag):
        raise ConfigError("CAA tag must be 1..15 lowercase [a-z0-9-]")
    value, pos = _master_parse_quoted(value_rest, 0)
    if value_rest[pos:].strip():
        raise ConfigError("CAA rdata has trailing characters")
    return flags, tag.encode("ascii"), value


def _master_caa_rdata(flags, tag, value):
    """把 CAA 字段编码为「flags 一字节、tag 长度一字节、tag、value」。"""
    return bytes((flags, len(tag))) + tag + value


def _master_parse_naptr_quoted(rest, pos):
    """解析 NAPTR 的一个字符串并校验解码后为 0..255 字节。"""
    value, pos = _master_parse_quoted(rest, pos)
    if len(value) > 0xFF:
        raise ConfigError("NAPTR character-string exceeds 255 bytes")
    return value, pos


def _master_parse_naptr_rdata(rest):
    """把 NAPTR rdata 原文解析为
    (order, preference, flags, services, regexp, replacement token)。

    rest 为行中 TYPE 之后的原文，形如
    'order preference "flags" "services" "regexp" replacement'，三个引号
    串（引号内允许空白）与各字段以 ASCII 空白分隔；order、preference 为
    允许前导零的 uint16 十进制，引号串解析规则同 CAA value，replacement
    作为末个 token 原样返回（"@" 由调用方处理）。字段数、整数、引号、
    转义、串长或尾随非法抛 ConfigError。
    """
    parts = rest.split(None, 2)
    if len(parts) != 3:
        raise ConfigError(
            "NAPTR rdata must be order preference flags services "
            "regexp replacement")
    order = _master_parse_uint16(parts[0])
    preference = _master_parse_uint16(parts[1])
    body = parts[2]
    strings = []
    pos = 0
    for index in range(3):
        if index > 0:
            if pos >= len(body) or not body[pos].isspace():
                raise ConfigError("NAPTR fields must be separated by "
                                  "whitespace")
            while pos < len(body) and body[pos].isspace():
                pos += 1
        value, pos = _master_parse_naptr_quoted(body, pos)
        strings.append(value)
    if pos >= len(body) or not body[pos].isspace():
        raise ConfigError("NAPTR fields must be separated by whitespace")
    while pos < len(body) and body[pos].isspace():
        pos += 1
    start = pos
    while pos < len(body) and not body[pos].isspace():
        pos += 1
    replacement = body[start:pos]
    if not replacement or body[pos:].strip():
        raise ConfigError("NAPTR rdata has trailing characters")
    return (order, preference, strings[0], strings[1], strings[2],
            replacement)


def _master_naptr_rdata(order, preference, flags, services, regexp,
                        replacement_labels):
    """把 NAPTR 字段编码为 rdata：两个网络序 uint16，三个「一字节长度+
    内容」字符串，最后为未压缩、0 结尾的 replacement 线格式名。"""
    return (order.to_bytes(2, "big") + preference.to_bytes(2, "big")
            + bytes((len(flags),)) + flags
            + bytes((len(services),)) + services
            + bytes((len(regexp),)) + regexp
            + _master_wire_name(replacement_labels))


def _master_parse_canonical_b64(token):
    """把 token 解析为规范 RFC4648 Base64 的原始字节。

    token 须无任何空白且解码后再编码与原文逐字符相同（规范字母表、
    正确填充、末块无用位为 0）；空串、字符集、长度、填充或编码非法
    抛 ConfigError。
    """
    if not token:
        raise ConfigError("empty base64 token")
    try:
        key = base64.b64decode(token, validate=True)
    except ValueError:
        raise ConfigError("invalid canonical Base64") from None
    if base64.b64encode(key).decode("ascii") != token:
        raise ConfigError("non-canonical Base64")
    return key


def _master_parse_dnskey_rdata(rest, type_name="DNSKEY"):
    """把 DNSKEY/CDNSKEY rdata 原文解析为 (flags, protocol, algorithm, key)。

    rest 为行中 TYPE 之后的原文，恰为四个以 ASCII 空白分隔的 token：
    'flags protocol algorithm publickey'。flags 为允许前导零的 uint16，
    algorithm 为允许前导零的 uint8，protocol 须恰为 3，publickey 为无
    空白的规范 RFC4648 Base64（解码再编码不变），解码后 1..65531 字节。
    type_name 为诊断信息中的记录类型名（"DNSKEY"/"CDNSKEY"）。字段数、
    整数、值域或 Base64 错抛 ConfigError。
    """
    parts = rest.split()
    if len(parts) != 4:
        raise ConfigError(
            type_name
            + " rdata must be flags protocol algorithm and publickey")
    flags_token, protocol_token, algorithm_token, key_token = parts
    flags = _master_parse_uint16(flags_token)
    protocol = _master_parse_uint8(protocol_token)
    if protocol != _DNSKEY_PROTOCOL:
        raise ConfigError(type_name + " protocol must be 3")
    algorithm = _master_parse_uint8(algorithm_token)
    key = _master_parse_canonical_b64(key_token)
    if not _DNSKEY_MIN_KEY_LEN <= len(key) <= _DNSKEY_MAX_KEY_LEN:
        raise ConfigError(type_name + " public key must be 1..65531 bytes")
    return flags, protocol, algorithm, key


def _master_dnskey_rdata(flags, protocol, algorithm, key):
    """把 DNSKEY/CDNSKEY 字段编码为 rdata：网络序两字节 flags、一字节
    protocol、一字节 algorithm，后接公钥原始字节。"""
    return (flags.to_bytes(2, "big") + bytes((protocol, algorithm)) + key)


def _master_parse_ds_rdata(rest, allow_delete, type_name):
    """把 DS/CDS rdata 原文解析为 (keytag, algorithm, digesttype, digest)。

    rest 为行中 TYPE 之后的原文，恰为四个以 ASCII 空白分隔的 token：
    'keytag algorithm digesttype digest'。keytag 为允许前导零的 uint16，
    algorithm、digesttype 为允许前导零的 uint8；digesttype 仅 1、2、4，
    digest 分别须恰为 40、64、96 个十六进制字符（大小写均可）。allow_delete
    （CDS）时 digesttype 0 仅作为 RFC 8078 删除标记接受：keytag、algorithm
    均为 0 且 digest token 恰为 "00"，digest 为单字节 0x00。字段数、整数、
    删除标记、digesttype、十六进制字符或长度错抛 ConfigError。
    """
    parts = rest.split()
    if len(parts) != 4:
        raise ConfigError(
            type_name
            + " rdata must be keytag algorithm digesttype and digest")
    keytag_token, algorithm_token, digesttype_token, digest_token = parts
    keytag = _master_parse_uint16(keytag_token)
    algorithm = _master_parse_uint8(algorithm_token)
    digesttype = _master_parse_uint8(digesttype_token)
    if digesttype == 0:
        if not allow_delete:
            raise ConfigError(type_name + " digesttype must be 1, 2 or 4")
        if keytag != 0 or algorithm != 0 or digest_token != "00":
            raise ConfigError("CDS delete marker must be 0 0 0 00")
        return 0, 0, 0, b"\x00"
    expected_len = _DS_DIGEST_LEN.get(digesttype)
    if expected_len is None:
        raise ConfigError(type_name + " digesttype must be 1, 2 or 4")
    hex_len = expected_len * 2
    if (len(digest_token) != hex_len
            or any(ch not in _HEXDIGITS for ch in digest_token)):
        raise ConfigError(
            type_name + " digest must be " + str(hex_len)
            + " hexadecimal characters")
    digest = bytes.fromhex(digest_token)
    return keytag, algorithm, digesttype, digest


def _master_ds_rdata(keytag, algorithm, digesttype, digest):
    """把 DS/CDS 字段编码为 rdata：网络序两字节 keytag、一字节 algorithm、
    一字节 digesttype，后接摘要原始字节。"""
    return (keytag.to_bytes(2, "big")
            + bytes((algorithm, digesttype)) + digest)


def _master_decode_ds_rdata(rdata, allow_delete, type_name):
    """解码 DS/CDS rdata 为 (keytag, algorithm, digesttype, digest bytes)。

    rdata 须恰为网络序两字节 keytag、一字节 algorithm、一字节 digesttype 与
    摘要；digesttype 须为 1、2、4 且摘要长度分别恰为 20、32、48 字节。
    allow_delete（CDS）时另允许恰为四字节 00 00 00 00 加一字节 0x00 的
    删除标记。type_name 为诊断信息中的记录类型名（"ds"/"cds"）。不足
    4 字节（截断）、摘要长度不符（截断或尾随）、digesttype 非法或删除
    标记语义错抛 RecordError。
    """
    if len(rdata) < 4:
        raise RecordError(type_name + " rdata truncated")
    keytag = int.from_bytes(rdata[0:2], "big")
    algorithm = rdata[2]
    digesttype = rdata[3]
    digest = bytes(rdata[4:])
    if digesttype == 0:
        if not allow_delete:
            raise RecordError(type_name + " digesttype must be 1, 2 or 4")
        if keytag != 0 or algorithm != 0 or digest != b"\x00":
            raise RecordError(
                "cds delete marker must encode 0 0 0 and one zero byte")
        return 0, 0, 0, digest
    expected_len = _DS_DIGEST_LEN.get(digesttype)
    if expected_len is None:
        raise RecordError(type_name + " digesttype must be 1, 2 or 4")
    if len(digest) != expected_len:
        raise RecordError(type_name + " digest length mismatch")
    return keytag, algorithm, digesttype, digest


def _master_parse_nsec_rdata(rest):
    """把 NSEC rdata 原文解析为 (next token, 按数值升序的类型码列表)。

    rest 为行中 TYPE 之后的原文，至少两个以 ASCII 空白分隔的 token：
    'next types...'；types 为 1..256 个互异的大写 TYPE 助记符（限当前
    已支持类型及 NSEC）。字段数、助记符或重复类型错抛 ConfigError。
    """
    parts = rest.split()
    if len(parts) < 2:
        raise ConfigError("NSEC rdata must be next and types")
    type_tokens = parts[1:]
    if len(type_tokens) > 256:
        raise ConfigError("NSEC rdata must have at most 256 types")
    codes = []
    seen = set()
    for token in type_tokens:
        code = _MASTER_TYPES.get(token)
        if code is None:
            raise ConfigError("NSEC type mnemonic not supported")
        if code in seen:
            raise ConfigError("NSEC type mnemonic duplicated")
        seen.add(code)
        codes.append(code)
    return parts[0], sorted(codes)


def _master_nsec_rdata(next_labels, type_codes):
    """把 NSEC 字段编码为 rdata：未压缩、0 结尾的 next 线格式名，后接
    RFC4034 类型位图；类型码按数值升序分窗，每块为窗口号、长度各一字节
    及位图，窗口严格升序且非空，长度为覆盖该窗最高类型所需的 1..32
    字节，类型号低八位按高位优先置位。"""
    rdata = bytearray(_master_wire_name(next_labels))
    windows = {}
    for code in type_codes:
        windows.setdefault(code >> 8, []).append(code & 0xFF)
    for window in sorted(windows):
        lows = windows[window]
        bitmap = bytearray((max(lows) >> 3) + 1)
        for low in lows:
            bitmap[low >> 3] |= 0x80 >> (low & 7)
        rdata += bytes((window, len(bitmap))) + bytes(bitmap)
    return bytes(rdata)


def _master_decode_nsec_name(rdata):
    """从 rdata[0] 起解码未压缩、0 结尾的绝对名，返回 (bytes 标签列表, 名后偏移)。

    标签接受任意八位组（ASCII 大写折小写），1..63、总长 ≤255；压缩
    指针（长度字节 >63）、截断抛 RecordError。名后的位图不在此解码。
    """
    return _decode_wire_name(rdata, RecordError, offset=0)


def _master_decode_nsec_rdata(rdata):
    """解码 NSEC rdata 为 (next 标签列表, 按数值升序的类型码列表)。

    rdata 须恰为一个未压缩、0 结尾的小写绝对名后接至少一个位图块；
    每块为窗口号、长度各一字节与 1..32 字节位图，窗口严格升序且不
    重复，长度恰覆盖该窗最高类型（末字节非 0），置位类型须为当前已
    支持类型或 NSEC。压缩名、截断、尾随、未知类型、空位图、窗口不
    升序或重复、长度越界或末字节为 0 抛 RecordError。
    """
    next_labels, pos = _master_decode_nsec_name(rdata)
    if pos == len(rdata):
        raise RecordError("nsec bitmap empty")
    codes = []
    prev_window = -1
    while pos < len(rdata):
        if pos + 2 > len(rdata):
            raise RecordError("nsec bitmap truncated")
        window = rdata[pos]
        length = rdata[pos + 1]
        if not 1 <= length <= 32:
            raise RecordError("nsec bitmap length out of range")
        if window <= prev_window:
            raise RecordError("nsec bitmap windows not strictly ascending")
        prev_window = window
        pos += 2
        if pos + length > len(rdata):
            raise RecordError("nsec bitmap truncated")
        bitmap = rdata[pos:pos + length]
        if bitmap[-1] == 0:
            raise RecordError("nsec bitmap last byte zero")
        for index, value in enumerate(bitmap):
            for bit in range(8):
                if value & (0x80 >> bit):
                    code = (window << 8) + index * 8 + bit
                    if code not in _NSEC_TYPE_NAMES:
                        raise RecordError("nsec bitmap unknown type")
                    codes.append(code)
        pos += length
    return next_labels, codes


def _master_days_from_civil(year, month, day):
    """公历日期距 1970-01-01 的天数（Howard Hinnant 算法）。"""
    year -= month <= 2
    era = year // 400
    yoe = year - era * 400
    doy = (153 * (month - 3 if month > 2 else month + 9) + 2) // 5 + day - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def _master_civil_from_days(days):
    """_master_days_from_civil 的逆算：距 1970-01-01 的天数转公历日期。"""
    z = days + 719468
    era = z // 146097
    doe = z - era * 146097
    yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    year = yoe + era * 400
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    mp = (5 * doy + 2) // 153
    day = doy - (153 * mp + 2) // 5 + 1
    month = mp + 3 if mp < 10 else mp - 9
    return year + (month <= 2), month, day


def _master_parse_rrsig_time(token):
    """把 14 位 UTC 公历时间 YYYYMMDDHHMMSS 解析为自 1970-01-01T00:00:00Z
    起、不回绕的 uint32 秒数。

    token 须恰为 14 个 ASCII 数字且为范围
    19700101000000..21060207062815 内的合法公历时间，秒 00..59
    （拒闰秒）；任何不符抛 ConfigError。
    """
    if len(token) != 14 or not token.isascii() or not token.isdigit():
        raise ConfigError("RRSIG time must be 14 decimal digits")
    year = int(token[0:4])
    month = int(token[4:6])
    day = int(token[6:8])
    hour = int(token[8:10])
    minute = int(token[10:12])
    second = int(token[12:14])
    if not 1 <= month <= 12:
        raise ConfigError("RRSIG time month out of range")
    if month == 2:
        leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
        max_day = 29 if leap else 28
    elif month in (4, 6, 9, 11):
        max_day = 30
    else:
        max_day = 31
    if not 1 <= day <= max_day:
        raise ConfigError("RRSIG time day out of range")
    if hour > 23 or minute > 59 or second > 59:
        raise ConfigError("RRSIG time of day out of range")
    value = (_master_days_from_civil(year, month, day) * 86400
             + hour * 3600 + minute * 60 + second)
    if not 0 <= value <= _MAX_TTL:
        raise ConfigError("RRSIG time out of range")
    return value


def _master_format_rrsig_time(value):
    """把 uint32 秒数逆算为 14 位 UTC 公历时间文本 YYYYMMDDHHMMSS。"""
    days, rem = divmod(value, 86400)
    hour, rem = divmod(rem, 3600)
    minute, second = divmod(rem, 60)
    year, month, day = _master_civil_from_days(days)
    return "%04d%02d%02d%02d%02d%02d" % (year, month, day,
                                         hour, minute, second)


def _master_parse_rrsig_rdata(rest):
    """把 RRSIG rdata 原文解析为 (覆盖类型码, algorithm, labels,
    originalttl, expiration, inception, keytag, signer token, signature)。

    rest 为行中 TYPE 之后的原文，恰为九个以 ASCII 空白分隔的 token：
    'typecovered algorithm labels originalttl expiration inception
    keytag signer signature'。typecovered 为当前已支持的大写 TYPE
    助记符（RRSIG 除外）；algorithm、labels 为允许前导零的 uint8，
    originalttl 为允许前导零的 uint32，keytag 为允许前导零的 uint16；
    expiration、inception 为范围 19700101000000..21060207062815 内的
    合法 14 位 UTC 公历时间（秒 00..59，拒闰秒），编码为自
    1970-01-01T00:00:00Z 起、不回绕的 uint32 秒；signer 作为 token
    原样返回（"@" 由调用方处理）；signature 为无空白且解码非空的
    规范 RFC4648 Base64。字段数、助记符、整数、日期或 Base64 错抛
    ConfigError。
    """
    parts = rest.split()
    if len(parts) != 9:
        raise ConfigError("RRSIG rdata must contain 9 fields")
    covered = _MASTER_TYPES.get(parts[0])
    if covered is None or covered == _TYPE_RRSIG:
        raise ConfigError("RRSIG covered type mnemonic not supported")
    algorithm = _master_parse_uint8(parts[1])
    labels = _master_parse_uint8(parts[2])
    original_ttl = _master_parse_uint32(parts[3])
    expiration = _master_parse_rrsig_time(parts[4])
    inception = _master_parse_rrsig_time(parts[5])
    keytag = _master_parse_uint16(parts[6])
    signature = _master_parse_canonical_b64(parts[8])
    return (covered, algorithm, labels, original_ttl, expiration,
            inception, keytag, parts[7], signature)


def _master_rrsig_rdata(covered, algorithm, labels, original_ttl,
                        expiration, inception, keytag, signer_labels,
                        signature):
    """把 RRSIG 字段编码为 rdata：网络序两字节覆盖类型、一字节
    algorithm、一字节 labels、网络序 uint32 originalttl、uint32
    expiration、uint32 inception、网络序两字节 keytag，后接未压缩、
    0 结尾的 signer 线格式名与签名原始字节。"""
    return (covered.to_bytes(2, "big") + bytes((algorithm, labels))
            + original_ttl.to_bytes(4, "big")
            + expiration.to_bytes(4, "big")
            + inception.to_bytes(4, "big")
            + keytag.to_bytes(2, "big")
            + _master_wire_name(signer_labels) + signature)


def _master_decode_rrsig_rdata(rdata):
    """解码 RRSIG rdata 为 (覆盖类型码, algorithm, labels, originalttl,
    expiration, inception, keytag, signer 标签列表, signature bytes)。

    rdata 须恰为 18 字节固定头（网络序两字节覆盖类型、一字节
    algorithm、一字节 labels、三个网络序 uint32、网络序两字节
    keytag）、一个未压缩、0 结尾的小写绝对名（标签仅小写，含大写
    ASCII 即抛 RecordError，不得小写化）与非空签名；覆盖类型码须为
    当前已支持类型（RRSIG 除外）。截断、压缩名、非法字符、空签名或
    覆盖类型不受支持抛 RecordError。
    """
    if len(rdata) < 18:
        raise RecordError("rrsig rdata truncated")
    covered = int.from_bytes(rdata[0:2], "big")
    algorithm = rdata[2]
    labels = rdata[3]
    original_ttl = int.from_bytes(rdata[4:8], "big")
    expiration = int.from_bytes(rdata[8:12], "big")
    inception = int.from_bytes(rdata[12:16], "big")
    keytag = int.from_bytes(rdata[16:18], "big")
    if covered not in _NSEC_TYPE_NAMES or covered == _TYPE_RRSIG:
        raise RecordError("rrsig covered type not supported")
    try:
        signer, pos = _decode_wire_name(rdata, ValueError, offset=18)
    except ValueError as exc:
        raise RecordError(str(exc)) from None
    signature = bytes(rdata[pos:])
    if not signature:
        raise RecordError("rrsig signature empty")
    return (covered, algorithm, labels, original_ttl, expiration,
            inception, keytag, signer, signature)


def _master_parse_name(token, allow_wildcard=False):
    """把主文件中的绝对域名（"@" 由调用方先行处理）解析为 bytes 标签列表。

    接受反斜杠转义：\\DDD（000..255）、\\. 与 \\\\；未转义点分隔标签，
    根名 "." 为 []，标签解码后 1..63 字节、线格式总长 ≤255。
    allow_wildcard 为真时（owner 专用）允许最左标签为字面单字节 "*"
    的通配形态；为假时（$ORIGIN 与 NS/CNAME/MX/SOA/SRV/NAPTR/NSEC/
    RRSIG 等嵌入名）字面 "*" 非法，但转义 \\042 引入的星号八位组是
    普通数据。反斜杠残缺、非三位数字转义或数值超 255 抛 ConfigError；
    合法转义解码后的长度或名称形态错误抛 RecordError。
    """
    return _parse_name_text(
        token, ConfigError,
        star="wildcard" if allow_wildcard else "none")


def _master_wire_name(labels):
    """把 bytes 标签列表编码为未压缩绝对名线格式。"""
    return _encode_wire_name(labels)


def import_master(text: str) -> dict:
    """把确定性 DNS 主文件文本导入为规范化 zone dict（键序 origin,records）。

    文本限 1048576 码点且须为 ASCII：首行仅 "$ORIGIN 绝对名"，其后
    1..65535 行记录 "owner ttl IN TYPE rdata"，头部按 ASCII 空白分词
    （TXT 的引号串内允许空白）；末尾允许无换行或恰一个换行，其余任何
    空行（含连续换行）均非法。owner 可为 "@"（代表 origin）、小写绝对
    名或最左标签恰为 "*" 且后缀在 origin 内的通配绝对名；SOA 的
    mname/rname、CNAME/NS/SRV 目标与 MX 交换名仅可为 "@" 或不含通配
    的小写绝对名；TYPE 为 "A"（1）、"NS"（2）、"CNAME"（5）、"MX"（15）、
    "TXT"（16）、"AAAA"（28）、"SRV"（33）、"NAPTR"（35）、
    "DS"（43）、"RRSIG"（46）、"NSEC"（47）、"DNSKEY"（48）、
    "CDS"（59）、
    "CDNSKEY"（60）、"CAA"（257）或 "SOA"（6），
    仅接受 class "IN"；ttl、MX preference、SRV 的 priority/weight/port
    及 SOA 的 serial/refresh/retry/expire/minimum 为允许前导零的十进制
    整数（uint32 为 0..4294967295，uint16 为 0..65535）；A 的 rdata
    为点分十进制 IPv4（导入为 4 字节），AAAA 的 rdata 为一个 IPv6
    文本（导入为 16 字节），NS/CNAME/SRV 目标与 MX 交换名写入未压缩、
    0 结尾且无尾随的线格式（MX 前加网络序 uint16 preference，SRV 前加
    三个网络序 uint16 priority/weight/port），SOA 的两个域名以未压缩
    线格式写入 rdata、后接五个网络序 uint32；TXT rdata 为 1..255 个
    双引号串，CAA rdata 为「flags tag "value"」：flags 为允许前导零的
    uint8，tag 为 1..15 字节小写 [a-z0-9-]，value 为单个双引号串
    （可为空）；NAPTR rdata 为
    'order preference "flags" "services" "regexp" replacement'：order、
    preference 为允许前导零的 uint16 十进制，三个引号串（均可为空，
    引号内允许空白）各解码为 0..255 字节，replacement 为 "@" 或不含
    通配的小写绝对名；三类引号串内仅接受可打印 ASCII，转义仅反斜杠
    反斜杠、反斜杠双引号或三位十进制反斜杠加 DDD（000..255），TXT
    每段解码后 ≤255 字节、依次写一字节长度及内容，CAA 依次写 flags
    一字节、tag 长度一字节、tag 与 value，NAPTR 依次写两个网络序
    uint16、三个一字节长度及内容、未压缩 0 结尾 replacement，DNSKEY/
    CDNSKEY rdata 为 'flags protocol algorithm publickey'：flags 为
    允许前导零的 uint16、algorithm 为允许前导零的 uint8、protocol 须
    恰为 3，publickey 无空白且为规范 RFC4648 Base64（解码再编码不变）、
    解码后 1..65531 字节，rdata 依次为网络序两字节 flags、一字节
    protocol、一字节 algorithm 与密钥；DS/CDS rdata 为
    'keytag algorithm digesttype digest'：keytag 为允许前导零的 uint16，
    algorithm、digesttype 为允许前导零的 uint8 十进制，digesttype 仅
    1、2、4，digest 分别须恰为 40、64、96 个十六进制字符（导入接受
    大小写），rdata 依次编码网络序两字节 keytag、一字节 algorithm、
    一字节 digesttype 与摘要字节；CDS 的 digesttype 0 仅作为删除标记
    接受，此时四字段文本须恰为 '0 0 0 00'、rdata 为五个零字节
    （00 00 00 00 00），DS 不接受 digesttype 0；NSEC rdata 为
    'next types...'：next 为 "@" 或不含通配的小写绝对名，types 为
    1..256 个互异的大写 TYPE 助记符（限当前已支持类型及 NSEC），
    next 写为未压缩、0 结尾的线格式名，类型按数值升序编码为
    RFC4034 位图，每块为窗口号、长度各一字节及位图，窗口严格升序
    且非空，长度为覆盖该窗最高类型所需的 1..32 字节，类型号低八位
    按高位优先置位；RRSIG rdata 为
    'typecovered algorithm labels originalttl expiration inception
    keytag signer signature'：typecovered 为当前已支持的大写 TYPE
    助记符（RRSIG 除外），algorithm、labels 为允许前导零的 uint8，
    originalttl 为允许前导零的 uint32，expiration、inception 为
    范围 19700101000000..21060207062815 内的合法 14 位 UTC 公历
    时间（秒 00..59，拒闰秒），keytag 为允许前导零的 uint16，
    signer 为 "@" 或不含通配的小写绝对名，signature 为无空白且
    解码非空的规范 RFC4648 Base64；rdata 依次为网络序两字节覆盖
    类型、一字节 algorithm、一字节 labels、网络序 uint32
    originalttl、uint32 expiration、uint32 inception、网络序两
    字节 keytag、未压缩 0 结尾的 signer 线格式名与签名（时间编码
    为自 1970-01-01T00:00:00Z 起、不回绕的 uint32 秒）；rdata
    总长 ≤65535。返回记录键序
    name,type,class,ttl,rdata，class 恒为 1、rdata 为 bytes，记录保序
    并沿用 zone 约束（origin 恰一条 SOA、owner 均在 origin 内、CNAME
    不与同 owner 其他类型并存等）。text 非 str 抛 TypeError；超长、
    非 ASCII、语法、未知 TYPE、非 IN、字段数/引号/转义、整数、Base64、
    删除标记、digesttype、十六进制字符或摘要长度、tag、NSEC 助记符/
    重复类型、RRSIG 助记符/日期/总长或 IP 错误抛
    ConfigError；名称及 rdata 错误抛 RecordError；zone 约束
    错误抛 ZoneError。时空复杂度为 O(字符数+记录数+类型数)。
    """
    if not isinstance(text, str):
        raise TypeError("text must be str")
    if len(text) > _MAX_MASTER_TEXT_LEN:
        raise ConfigError("text exceeds 1048576 characters")
    if not text.isascii():
        raise ConfigError("text must be ASCII")
    # 末尾允许无换行或恰一个换行；以两个换行结尾（末行为空）或行中
    # 出现空行属于非法空行。
    if text.endswith("\n\n"):
        raise ConfigError("blank lines are not allowed")
    if text.endswith("\n"):
        text = text[:-1]
    lines = text.split("\n")
    if not 2 <= len(lines) <= _MAX_MASTER_RECORDS + 1:
        raise ConfigError("master text must contain 1..65535 records")
    first = lines[0].split()
    if len(first) != 2 or first[0] != _MASTER_DIRECTIVE:
        raise ConfigError("first line must be $ORIGIN name")
    origin_labels = _master_parse_name(first[1])
    origin_text = _labels_to_name(origin_labels, wildcard=False)
    records = []
    for line in lines[1:]:
        # 以 maxsplit=4 保留 rdata 原文：TXT 的引号串内允许 ASCII 空白，
        # 其余类型对原文再 split() 与逐字段计数。
        parts = line.split(None, 4)
        if len(parts) < _MASTER_HEADER_TOKENS + 1:
            raise ConfigError("malformed record line")
        owner_token, ttl_token, class_token, type_token, rdata_rest = parts
        rdata_tokens = rdata_rest.split()
        ttl = _master_parse_uint32(ttl_token)
        if class_token != _MASTER_CLASS:
            raise ConfigError("class must be IN")
        if type_token not in _MASTER_TYPES:
            raise ConfigError(
                "type must be A, NS, CNAME, MX, TXT, AAAA, SRV, NAPTR, "
                "DS, RRSIG, NSEC, DNSKEY, CDS, CDNSKEY, CAA or SOA")
        rrtype = _MASTER_TYPES[type_token]
        if owner_token == "@":
            owner_labels = origin_labels
        else:
            owner_labels = _master_parse_name(
                owner_token, allow_wildcard=True)
        if rrtype == _TYPE_A:
            if len(rdata_tokens) != 1:
                raise ConfigError("A rdata must be one address")
            try:
                rdata = ipaddress.IPv4Address(rdata_tokens[0]).packed
            except ValueError:
                raise ConfigError("invalid IPv4 address") from None
        elif rrtype == _TYPE_AAAA:
            if len(rdata_tokens) != 1:
                raise ConfigError("AAAA rdata must be one address")
            address_token = rdata_tokens[0]
            if "%" in address_token:
                raise ConfigError("invalid IPv6 address")
            try:
                rdata = ipaddress.IPv6Address(address_token).packed
            except ValueError:
                raise ConfigError("invalid IPv6 address") from None
            if len(rdata) != 16:
                raise ConfigError("invalid IPv6 address")
        elif rrtype == _TYPE_NS:
            if len(rdata_tokens) != 1:
                raise ConfigError("NS rdata must be one name")
            target_token = rdata_tokens[0]
            if target_token == "@":
                target_labels = origin_labels
            else:
                target_labels = _master_parse_name(target_token)
            rdata = _master_wire_name(target_labels)
        elif rrtype == _TYPE_CNAME:
            if len(rdata_tokens) != 1:
                raise ConfigError("CNAME rdata must be one name")
            target_token = rdata_tokens[0]
            if target_token == "@":
                target_labels = origin_labels
            else:
                target_labels = _master_parse_name(target_token)
            rdata = _master_wire_name(target_labels)
        elif rrtype == _TYPE_MX:
            if len(rdata_tokens) != 2:
                raise ConfigError("MX rdata must be preference and name")
            preference = _master_parse_uint16(rdata_tokens[0])
            exchange_token = rdata_tokens[1]
            if exchange_token == "@":
                exchange_labels = origin_labels
            else:
                exchange_labels = _master_parse_name(exchange_token)
            rdata = (preference.to_bytes(2, "big")
                     + _master_wire_name(exchange_labels))
        elif rrtype == _TYPE_TXT:
            segments = _master_parse_txt_rdata(rdata_rest)
            rdata = _master_txt_rdata(segments)
        elif rrtype == _TYPE_SRV:
            if len(rdata_tokens) != 4:
                raise ConfigError(
                    "SRV rdata must be priority weight port and target")
            priority = _master_parse_uint16(rdata_tokens[0])
            weight = _master_parse_uint16(rdata_tokens[1])
            port = _master_parse_uint16(rdata_tokens[2])
            target_token = rdata_tokens[3]
            if target_token == "@":
                target_labels = origin_labels
            else:
                target_labels = _master_parse_name(target_token)
            rdata = (priority.to_bytes(2, "big") + weight.to_bytes(2, "big")
                     + port.to_bytes(2, "big")
                     + _master_wire_name(target_labels))
        elif rrtype == _TYPE_NAPTR:
            (order, preference, flags, services, regexp,
             replacement_token) = _master_parse_naptr_rdata(rdata_rest)
            if replacement_token == "@":
                replacement_labels = origin_labels
            else:
                replacement_labels = _master_parse_name(replacement_token)
            rdata = _master_naptr_rdata(order, preference, flags, services,
                                        regexp, replacement_labels)
        elif rrtype == _TYPE_DS:
            keytag, algorithm, digesttype, digest = _master_parse_ds_rdata(
                rdata_rest, False, "DS")
            rdata = _master_ds_rdata(keytag, algorithm, digesttype, digest)
        elif rrtype in (_TYPE_DNSKEY, _TYPE_CDNSKEY):
            dnskey_type_name = (
                "DNSKEY" if rrtype == _TYPE_DNSKEY else "CDNSKEY")
            flags, protocol, algorithm, key = _master_parse_dnskey_rdata(
                rdata_rest, dnskey_type_name)
            rdata = _master_dnskey_rdata(flags, protocol, algorithm, key)
        elif rrtype == _TYPE_CDS:
            keytag, algorithm, digesttype, digest = _master_parse_ds_rdata(
                rdata_rest, True, "CDS")
            rdata = _master_ds_rdata(keytag, algorithm, digesttype, digest)
        elif rrtype == _TYPE_NSEC:
            next_token, nsec_codes = _master_parse_nsec_rdata(rdata_rest)
            if next_token == "@":
                next_labels = origin_labels
            else:
                next_labels = _master_parse_name(next_token)
            rdata = _master_nsec_rdata(next_labels, nsec_codes)
            if len(rdata) > _MAX_RDATA_LEN:
                raise ConfigError("NSEC rdata too long")
        elif rrtype == _TYPE_RRSIG:
            (covered, algorithm, label_count, original_ttl, expiration,
             inception, keytag, signer_token,
             signature) = _master_parse_rrsig_rdata(rdata_rest)
            if signer_token == "@":
                signer_labels = origin_labels
            else:
                signer_labels = _master_parse_name(signer_token)
            rdata = _master_rrsig_rdata(covered, algorithm, label_count,
                                        original_ttl, expiration,
                                        inception, keytag, signer_labels,
                                        signature)
            if len(rdata) > _MAX_RDATA_LEN:
                raise ConfigError("RRSIG rdata too long")
        elif rrtype == _TYPE_CAA:
            flags, tag, value = _master_parse_caa_rdata(rdata_rest)
            rdata = _master_caa_rdata(flags, tag, value)
        else:
            if len(rdata_tokens) != 7:
                raise ConfigError("SOA rdata must contain 7 fields")
            name_labels = []
            for name_token in rdata_tokens[:2]:
                if name_token == "@":
                    name_labels.append(origin_labels)
                else:
                    name_labels.append(_master_parse_name(name_token))
            rdata = b"".join(_master_wire_name(labels)
                             for labels in name_labels)
            for number in rdata_tokens[2:]:
                rdata += _master_parse_uint32(number).to_bytes(4, "big")
        records.append({"name": _labels_to_name(owner_labels),
                        "type": rrtype, "class": 1, "ttl": ttl,
                        "rdata": rdata})
    # 结构层解析通过后统一套用 zone 约束：origin 恰一条 SOA、owner 在
    # origin 内、ttl/rdata 长度等；错误沿用 RecordError、ZoneError。
    zone = {"origin": origin_text, "records": records}
    checked_origin, checked_rrs, _cls = _validate_zone(zone)
    return {"origin": _labels_to_name(checked_origin, wildcard=False),
            "records": [_rr_to_model(rr) for rr in checked_rrs]}


def _master_decode_soa_rdata(rdata):
    """解码 SOA rdata 为 (mname 标签, rname 标签, 五个 uint32)。

    rdata 须恰为两个未压缩绝对名（标签接受任意八位组，大写折小写）加
    20 字节五个网络序 uint32；任何不符抛 RecordError。
    """
    names = []
    pos = 0
    for _ in range(2):
        labels, pos = _decode_wire_name(rdata, RecordError, offset=pos)
        names.append(labels)
    if len(rdata) - pos != 20:
        raise RecordError("soa rdata must end with five uint32")
    numbers = tuple(int.from_bytes(rdata[pos + i * 4:pos + i * 4 + 4], "big")
                    for i in range(5))
    return names[0], names[1], numbers


def _master_decode_mx_rdata(rdata):
    """解码 MX rdata 为 (uint16 preference, exchange 标签列表)。

    rdata 须恰为两个网络序字节 preference 加一个未压缩、0 结尾且无
    尾随的小写绝对名；任何不符抛 RecordError。
    """
    if len(rdata) < 3:
        raise RecordError("mx rdata truncated")
    preference = int.from_bytes(rdata[:2], "big")
    exchange = _decode_cname_target(rdata[2:])
    return preference, exchange


def _master_decode_txt_rdata(rdata):
    """解码 TXT rdata 为 1..255 个 bytes 段（允许空段）。

    rdata 依次为一字节长度与该长度内容，直至恰尽；段数超 255 或
    长度越界抛 RecordError。
    """
    if not rdata:
        raise RecordError("txt rdata empty")
    segments = []
    pos = 0
    while pos < len(rdata):
        count = rdata[pos]
        pos += 1
        if pos + count > len(rdata):
            raise RecordError("txt rdata truncated")
        segments.append(bytes(rdata[pos:pos + count]))
        pos += count
    if len(segments) > 0xFF:
        raise RecordError("txt rdata too many strings")
    return segments


def _master_format_quoted(octets):
    """把 bytes 渲染为双引号串内容（不含引号）的转义形式。

    双引号与反斜杠写 \\"、\\\\，其余可打印字节（0x20..0x7E）原样写，
    非打印字节写三位十进制 \\DDD；空 bytes 渲染为 ""。
    """
    out = []
    for value in octets:
        if value == 0x22:
            out.append('\\"')
        elif value == 0x5C:
            out.append("\\\\")
        elif 0x20 <= value <= 0x7E:
            out.append(chr(value))
        else:
            out.append("\\%03d" % value)
    return "".join(out)


def _master_format_txt_segment(segment):
    """把单个 TXT bytes 段渲染为带双引号的主文件字符串。转义规则见
    _master_format_quoted；空段渲染为 ""。"""
    return '"' + _master_format_quoted(segment) + '"'


def _master_decode_srv_rdata(rdata):
    """解码 SRV rdata 为 (priority, weight, port, target 标签列表)。

    rdata 须恰为三个网络序 uint16 加一个未压缩、0 结尾且无尾随的
    小写绝对名；任何不符抛 RecordError。
    """
    if len(rdata) < 7:
        raise RecordError("srv rdata truncated")
    priority = int.from_bytes(rdata[0:2], "big")
    weight = int.from_bytes(rdata[2:4], "big")
    port = int.from_bytes(rdata[4:6], "big")
    target = _decode_cname_target(rdata[6:])
    return priority, weight, port, target


def _master_decode_caa_rdata(rdata):
    """解码 CAA rdata 为 (flags, tag bytes, value bytes)。

    rdata 须恰为一字节 flags、一字节 tag 长度（1..15）、该长度的
    小写 [a-z0-9-] tag 与任意 value 字节，总长 ≤65535；截断、长度或
    tag 非法抛 RecordError。
    """
    if len(rdata) < 2:
        raise RecordError("caa rdata truncated")
    flags = rdata[0]
    tag_len = rdata[1]
    if not 1 <= tag_len <= _CAA_MAX_TAG_LEN:
        raise RecordError("caa tag length out of range")
    if 2 + tag_len > len(rdata):
        raise RecordError("caa rdata truncated")
    tag = bytes(rdata[2:2 + tag_len])
    if not all(chr(ch) in _CAA_TAG_CHARS for ch in tag):
        raise RecordError("caa invalid tag character")
    value = bytes(rdata[2 + tag_len:])
    return flags, tag, value


def _master_decode_naptr_name(rdata, pos):
    """从 rdata[pos] 起解码未压缩、0 结尾的绝对名。

    返回 (bytes 标签列表, 名后偏移)；标签接受任意八位组（大写折小写），
    1..63、总长 ≤255；禁止压缩指针与截断，任何不符抛 RecordError。
    """
    if len(rdata) - pos > _MAX_NAME_WIRE_LEN:
        raise RecordError("naptr replacement too long")
    return _decode_wire_name(rdata, RecordError, offset=pos)


def _master_decode_naptr_rdata(rdata):
    """解码 NAPTR rdata 为
    (order, preference, flags, services, regexp, replacement 标签列表)。

    rdata 须恰为两个网络序 uint16、三个各以一字节长度开头的 0..255
    字节字符串，以及一个未压缩、0 结尾且无尾随的绝对名（标签仅小写，
    含大写即 RecordError）；总长
    ≤65535；压缩指针、截断或尾随抛 RecordError。
    """
    if len(rdata) < 7:
        raise RecordError("naptr rdata truncated")
    order = int.from_bytes(rdata[0:2], "big")
    preference = int.from_bytes(rdata[2:4], "big")
    strings = []
    pos = 4
    for _ in range(3):
        if pos >= len(rdata):
            raise RecordError("naptr rdata truncated")
        count = rdata[pos]
        pos += 1
        if pos + count > len(rdata):
            raise RecordError("naptr rdata truncated")
        strings.append(bytes(rdata[pos:pos + count]))
        pos += count
    replacement, pos = _master_decode_naptr_name(rdata, pos)
    if pos != len(rdata):
        raise RecordError("naptr rdata trailing bytes")
    return (order, preference, strings[0], strings[1], strings[2],
            replacement)


def _master_decode_dnskey_rdata(rdata, type_name="dnskey"):
    """解码 DNSKEY/CDNSKEY rdata 为 (flags, protocol, algorithm, key bytes)。

    rdata 须恰为网络序两字节 flags、一字节 protocol、一字节 algorithm 与
    1..65531 字节公钥；protocol 须恰为 3；不足 4 字节（截断）、密钥
    为空或超长（长度错）、protocol 错抛 RecordError。type_name 为诊断
    信息中的记录类型名（"dnskey"/"cdnskey"）。
    """
    if len(rdata) < 4:
        raise RecordError(type_name + " rdata truncated")
    flags = int.from_bytes(rdata[0:2], "big")
    protocol = rdata[2]
    algorithm = rdata[3]
    key = bytes(rdata[4:])
    if protocol != _DNSKEY_PROTOCOL:
        raise RecordError(type_name + " protocol must be 3")
    if not _DNSKEY_MIN_KEY_LEN <= len(key) <= _DNSKEY_MAX_KEY_LEN:
        raise RecordError(type_name + " public key must be 1..65531 bytes")
    return flags, protocol, algorithm, key


def export_master(zone: dict) -> str:
    """把 zone dict 导出为确定性主文件文本（单空格分隔，末尾换行）。

    zone 先按 zone 规则校验并规范化；仅接受 class 为 1（IN）、类型为
    A/NS/CNAME/MX/TXT/AAAA/SRV/NAPTR/DS/RRSIG/NSEC/DNSKEY/CDS/CDNSKEY/
    CAA/SOA
    的记录。输出首行
    "$ORIGIN 绝对名"，
    字段以单空格分隔、末尾恰一个换行，记录保序；owner、SOA 域名、
    NS/CNAME/SRV 目标、NAPTR replacement 与 MX 交换名等于 origin 时输出
    "@"，否则输出小写
    绝对名（owner 允许最左标签恰为 "*" 的通配名，其余名称不压缩亦
    不含通配；NAPTR replacement 线标签含大写 ASCII 时直接抛
    RecordError，不得小写化）；A 地址、AAAA 地址（IPv6Address 的小写
    压缩形式）、TTL、
    SOA、MX preference、SRV priority/weight/port、NAPTR order/preference
    与 CAA flags、DNSKEY/CDNSKEY flags/algorithm 整数均
    按规范形式输出（无前导零）；NS/CNAME rdata 须为未压缩、0 结尾且
    无尾随的线格式，MX rdata 须恰为网络序 uint16 preference 加该线
    格式名，SRV rdata 须恰为三个网络序 uint16 加该线格式名，AAAA
    rdata 须恰为 16 字节；TXT rdata 依次为一字节长度及内容，逐段加
    双引号输出（1..255 段），空段写 ""，段间单空格；NAPTR rdata 须恰为
    两个网络序 uint16、三个各以一字节长度开头的 0..255 字节字符串与
    未压缩、0 结尾且无尾随的 replacement（标签仅小写），按
    'order preference "flags" "services" "regexp" replacement' 输出，
    三个字符串均可为空；DNSKEY/CDNSKEY rdata 须恰为网络序两字节 flags、
    一字节 protocol（须恰为 3）、一字节 algorithm 与 1..65531 字节密钥，
    按 'flags protocol algorithm publickey' 输出，整数无前导零、密钥以
    规范 RFC4648 Base64（无空白）输出；DS/CDS rdata 须恰为网络序两字节
    keytag、一字节 algorithm、一字节 digesttype 与摘要，digesttype 须为
    1、2、4 且摘要长度分别恰为 20、32、48 字节，按
    'keytag algorithm digesttype digest' 输出，整数无前导零、digest 以
    小写十六进制输出；CDS 另允许恰为五字节 00 00 00 00 00 的删除标记，
    输出 '0 0 0 00'，DS 不允许 digesttype 0；NSEC rdata 须恰为一个
    未压缩、0 结尾且无尾随的小写绝对名（标签仅小写，含大写即
    RecordError）后接至少一个 RFC4034 位图块：每块为窗口号、长度各
    一字节与 1..32 字节位图，窗口严格升序且不重复、末字节非 0，置位
    类型须为当前已支持类型或 NSEC；按 'next types...' 输出，next 等于
    origin 时写 "@"，类型按类型码升序写助记符；RRSIG rdata 须恰为
    18 字节固定头（网络序两字节覆盖类型、一字节 algorithm、一字节
    labels、三个网络序 uint32 originalttl/expiration/inception、
    网络序两字节 keytag）、一个未压缩、0 结尾且无尾随的小写绝对名
    signer（标签仅小写，含大写即 RecordError）与非空签名，覆盖类型
    码须为当前已支持类型（RRSIG 除外）；按
    'typecovered algorithm labels originalttl expiration inception
    keytag signer signature' 输出，整数无前导零，两个时间按 uint32
    秒逆算为 14 位 UTC 公历时间，signer 等于 origin 时写 "@"，
    签名以规范 RFC4648 Base64（无空白）输出；CAA rdata 须恰为
    一字节 flags、一字节 tag 长度（1..15）、tag 与 value，按
    'flags tag "value"' 输出，value 可为空。引号串内双引号与反斜杠
    写转义形式、其余可打印字节原样写、非打印字节写三位十进制 \\DDD。
    对导出结果再 import_master 得到等价 zone；同一 zone 多次导出逐字节
    一致。zone 非 dict 抛 TypeError；名称及各 rdata 的格式或长度错误
    （含截断、尾随、protocol、digesttype/删除标记/摘要长度、tag/长度、
    NSEC 位图、RRSIG 头/signer/签名或编码错）抛 RecordError，zone
    约束错误或 RR 的 class 非 1 抛
    ZoneError；类型不受支持、记录超 65535 条或文本超 1048576
    字符抛 ConfigError。
    """
    if not isinstance(zone, dict):
        raise TypeError("zone must be dict")
    origin_labels, rrs, _zone_class = _validate_zone(zone)
    if len(rrs) > _MAX_MASTER_RECORDS:
        raise ConfigError("zone must contain at most 65535 records")
    origin_text = _labels_to_name(origin_labels, wildcard=False)
    lines = [_MASTER_DIRECTIVE + " " + origin_text]
    for labels, rrtype, rrclass, ttl, rdata in rrs:
        if rrclass != 1:
            raise ZoneError("master export only supports class IN")
        owner = "@" if labels == origin_labels else _labels_to_name(labels)
        prefix = owner + " " + str(ttl) + " " + _MASTER_CLASS + " "
        if rrtype == _TYPE_A:
            if len(rdata) != 4:
                raise RecordError("A rdata must be 4 bytes")
            try:
                address = str(ipaddress.IPv4Address(rdata))
            except ValueError:
                raise RecordError("invalid A rdata") from None
            lines.append(prefix + "A " + address)
        elif rrtype == _TYPE_AAAA:
            if len(rdata) != 16:
                raise RecordError("AAAA rdata must be 16 bytes")
            try:
                address = str(ipaddress.IPv6Address(rdata))
            except ValueError:
                raise RecordError("invalid AAAA rdata") from None
            lines.append(prefix + "AAAA " + address)
        elif rrtype == _TYPE_NS:
            target = _decode_cname_target(rdata)
            target_text = ("@" if target == origin_labels
                           else _labels_to_name(target, wildcard=False))
            lines.append(prefix + "NS " + target_text)
        elif rrtype == _TYPE_CNAME:
            target = _decode_cname_target(rdata)
            target_text = ("@" if target == origin_labels
                           else _labels_to_name(target, wildcard=False))
            lines.append(prefix + "CNAME " + target_text)
        elif rrtype == _TYPE_MX:
            preference, exchange = _master_decode_mx_rdata(rdata)
            exchange_text = ("@" if exchange == origin_labels
                             else _labels_to_name(exchange, wildcard=False))
            lines.append(prefix + "MX " + str(preference) + " "
                         + exchange_text)
        elif rrtype == _TYPE_TXT:
            segments = _master_decode_txt_rdata(rdata)
            txt = " ".join(_master_format_txt_segment(segment)
                           for segment in segments)
            lines.append(prefix + "TXT " + txt)
        elif rrtype == _TYPE_SRV:
            priority, weight, port, target = _master_decode_srv_rdata(rdata)
            target_text = ("@" if target == origin_labels
                           else _labels_to_name(target, wildcard=False))
            lines.append(prefix + "SRV "
                         + str(priority) + " " + str(weight) + " "
                         + str(port) + " " + target_text)
        elif rrtype == _TYPE_NAPTR:
            (order, preference, flags, services, regexp,
             replacement) = _master_decode_naptr_rdata(rdata)
            replacement_text = ("@" if replacement == origin_labels
                                else _labels_to_name(
                                    replacement, wildcard=False))
            lines.append(prefix + "NAPTR "
                         + str(order) + " " + str(preference) + " "
                         + '"' + _master_format_quoted(flags) + '"' + " "
                         + '"' + _master_format_quoted(services) + '"' + " "
                         + '"' + _master_format_quoted(regexp) + '"' + " "
                         + replacement_text)
        elif rrtype == _TYPE_DS:
            keytag, algorithm, digesttype, digest = _master_decode_ds_rdata(
                rdata, False, "ds")
            lines.append(prefix + "DS "
                         + str(keytag) + " " + str(algorithm) + " "
                         + str(digesttype) + " "
                         + digest.hex())
        elif rrtype in (_TYPE_DNSKEY, _TYPE_CDNSKEY):
            dnskey_type_name = (
                "DNSKEY" if rrtype == _TYPE_DNSKEY else "CDNSKEY")
            flags, protocol, algorithm, key = _master_decode_dnskey_rdata(
                rdata, "dnskey" if rrtype == _TYPE_DNSKEY else "cdnskey")
            lines.append(prefix + dnskey_type_name + " "
                         + str(flags) + " " + str(protocol) + " "
                         + str(algorithm) + " "
                         + base64.b64encode(key).decode("ascii"))
        elif rrtype == _TYPE_CDS:
            keytag, algorithm, digesttype, digest = _master_decode_ds_rdata(
                rdata, True, "cds")
            lines.append(prefix + "CDS "
                         + str(keytag) + " " + str(algorithm) + " "
                         + str(digesttype) + " "
                         + digest.hex())
        elif rrtype == _TYPE_NSEC:
            next_labels, nsec_codes = _master_decode_nsec_rdata(rdata)
            next_text = ("@" if next_labels == origin_labels
                         else _labels_to_name(next_labels, wildcard=False))
            lines.append(prefix + "NSEC " + next_text + " "
                         + " ".join(_NSEC_TYPE_NAMES[code]
                                    for code in nsec_codes))
        elif rrtype == _TYPE_RRSIG:
            (covered, algorithm, label_count, original_ttl, expiration,
             inception, keytag, signer,
             signature) = _master_decode_rrsig_rdata(rdata)
            signer_text = ("@" if signer == origin_labels
                           else _labels_to_name(signer, wildcard=False))
            lines.append(prefix + "RRSIG " + _NSEC_TYPE_NAMES[covered]
                         + " " + str(algorithm) + " "
                         + str(label_count) + " " + str(original_ttl)
                         + " " + _master_format_rrsig_time(expiration)
                         + " " + _master_format_rrsig_time(inception)
                         + " " + str(keytag) + " " + signer_text + " "
                         + base64.b64encode(signature).decode("ascii"))
        elif rrtype == _TYPE_CAA:
            flags, tag, value = _master_decode_caa_rdata(rdata)
            lines.append(prefix + "CAA " + str(flags) + " "
                         + tag.decode("ascii") + " "
                         + '"' + _master_format_quoted(value) + '"')
        elif rrtype == _TYPE_SOA:
            mname, rname, numbers = _master_decode_soa_rdata(rdata)
            mname_text = ("@" if mname == origin_labels
                          else _labels_to_name(mname, wildcard=False))
            rname_text = ("@" if rname == origin_labels
                          else _labels_to_name(rname, wildcard=False))
            fields = " ".join(str(value) for value in (mname_text, rname_text)
                              + numbers)
            lines.append(prefix + "SOA " + fields)
        else:
            raise ConfigError(
                "master export only supports A, NS, CNAME, MX, TXT, "
                "AAAA, SRV, NAPTR, DS, RRSIG, NSEC, DNSKEY, CDS, CDNSKEY, "
                "CAA and SOA")
    text = "\n".join(lines) + "\n"
    if len(text) > _MAX_MASTER_TEXT_LEN:
        raise ConfigError("master text exceeds 1048576 characters")
    return text


def compare_serial(left: int, right: int) -> str:
    """按 RFC 1982 比较 uint32 环形序列号。

    left、right 均须为 0..4294967295 的非 bool int：非 int 或 bool 抛
    TypeError，越界抛 ConfigError。相等返回 "equal"；令
    d=(left-right) mod 2^32，1<=d<2^31 返回 "newer"，
    2^31<d<2^32 返回 "older"，d=2^31 返回 "ambiguous"。
    """
    if not isinstance(left, int) or isinstance(left, bool):
        raise TypeError("left must be int")
    if not isinstance(right, int) or isinstance(right, bool):
        raise TypeError("right must be int")
    if not 0 <= left <= _MAX_TTL:
        raise ConfigError("left serial out of range")
    if not 0 <= right <= _MAX_TTL:
        raise ConfigError("right serial out of range")
    if left == right:
        return "equal"
    diff = (left - right) % (1 << 32)
    if diff < (1 << 31):
        return "newer"
    if diff > (1 << 31):
        return "older"
    return "ambiguous"


class PositiveCache:
    """容量 256 的正/负答案缓存（FIFO 淘汰，命中不重排）。

    正缓存键为 (小写绝对 qname, qtype, qclass)，与 ID、flags、limit 无关。
    仅缓存 RCODE=0、ns 空、an 非空且 ANSWER 与地址 ADDITIONAL 各记录
    原始 TTL 均为正的完整有序应答；条目保存插入时刻、原始 ANSWER RR 与
    权威计划为该计划生成的原始地址 ADDITIONAL RR（可能为空），输出 TTL
    随经过时间递减，两段等量衰减；整条正条目以 ANSWER 与 ADDITIONAL
    全部记录的最小原始 TTL 判断到期，到期即删除。

    负缓存仅收完整计划所得且 an 为空的 NXDOMAIN（RCODE=3，键为小写绝对
    (qname, qclass)，匹配任意 qtype）与 NODATA（RCODE=0，键为
    (qname, qtype, qclass)），且 ns 恰为 origin 唯一 SOA；SOA rdata 须
    完整为两个未压缩绝对域名及五个网络序 uint32，负 TTL 为
    min(SOA ttl, 第五个 uint32)，格式错或负 TTL 为 0 则不缓存。
    负命中时 RCODE 不变，an/ar 为空，ns 仅该 SOA 且 ttl 随经过时间递减。

    查找顺序为正缓存、NODATA、NXDOMAIN；正负条目共用容量与同一 FIFO。
    任何失败（含编码失败）都不改变条目与时钟状态。

    resolve_edns(query, now, limit=65535) 处理恰含一个合法 OPT 的单问题
    查询：查缓存前须恰有一个合法 OPT，OPT 缺失（ARCOUNT=0）、非法或
    尾随字节均抛 EDNSError；报文解码与 OPT 校验沿用 edns 契约（未压缩
    根 owner、TYPE41、CLASS512..65535、扩展码 0、版本 0..255、flags
    仅 DO、选项 TLV 校验），QDCOUNT 非 1 或 QR 置位抛 EncodeError，
    其余报文非法抛 EDNSError。OPT 版本 1..255 时按版本协商直接返回
    (BADVERS 应答, False)，上限 min(limit, OPT CLASS)，先于时钟回退
    判断返回，不读写缓存、FIFO、统计或时钟，也不校验 ECS。版本 0
    查询至多携带一个 ECS（选项码 8）：data 依次为网络序 family
    uint16、source、scope 各一字节与 address；family 仅 1（source
    0..32）或 2（source 0..128），scope 须为 0，address 长度为
    (source+7)//8 且末字节未用低位须为 0；重复 ECS、未知 family、
    source/scope 或长度非法、填充位非 0 均在访问缓存前抛 EDNSError。
    合法 ECS 时缓存按 (family,source,address) 单独分区：正缓存、
    NODATA、NXDOMAIN 均纳入，无 ECS 查询使用与 resolve 相同的无分区
    键；版本 0 时缓存分区、正负缓存、TTL 衰减、FIFO、
    命中与统计和 resolve 完全共享（分区内键忽略 OPT、ID、flags 与
    limit）；应答按同一权威计划以 edns 语义编码：上限为 min(limit,
    OPT CLASS)，RCODE 取计划值，末项 OPT 回显 CLASS 与 DO，查询含
    ECS 时仅回写码 8 选项（family、source 不变，scope=source，
    address 同查询，其他选项不回显；ECS 使报文超 min(limit,OPT
    CLASS) 抛 EncodeError），无 ECS 时扩展码、版本及 RDLENGTH 为 0，
    普通 RR 超限或区段计数超 16 位时按 RRset 原子截断整组删除并置
    TC（规范化 owner、type、class 同组，不含 TTL/rdata；ar、ns、an
    优先级）、OPT
    不删，头部、问题和 OPT 超限抛 EncodeError。异常不改变缓存、统计
    或最后时刻，成功原子提交；未触发截断时输出与既有逐字节相同。

    stats(reset=False) 输出键序 h,m,x,k 的紧凑 ASCII JSON（末尾单换行）：
    h 键序 p,nx,nd，按 resolve 命中正缓存、NXDOMAIN、NODATA 递增；
    m 键序 p,nx,nd,o，按成功未命中后新写正缓存、NXDOMAIN、NODATA 或
    未写条目递增；x 累计成功 resolve 实际删除的到期条目数；k 键序
    p,nx,nd,total,capacity，依次为当前三类条目数、合计与 256。统计仅在
    resolve 成功返回时原子提交，任何异常均不改变它们；检测到期后编码
    失败不计 x，截断不改分类，命中不重排 FIFO。reset 非 bool 抛
    TypeError 且无变化；False 重复读取逐字节相同；True 先返回旧快照再
    清零 h、m、x，保留缓存、FIFO、时钟与 k。另有仅供 Resolver 在成功
    解析后折叠的清理事件累计（成功到期删除数、FIFO 淘汰数）：它们不在
    stats() 的 JSON 中，也不随 stats(reset=True) 清零。
    """

    def __init__(self, zone: dict):
        # 深拷贝后按 answer 规则校验：外部对 zone 的后续改动与缓存隔离，
        # 校验异常与 answer 完全一致。
        zone = copy.deepcopy(zone)
        self._origin, self._records, self._zone_class = _validate_zone(zone)
        self._entries = {}  # 正缓存键 -> (插入时刻, 规范化 an, 规范化 ar)
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
        # 清理事件累计（供 Resolver.cache_stats 读取，不属 stats() 的
        # JSON）：clean_expired 计成功解析实际删除的到期条目，
        # clean_evicted 计容量满时的 FIFO 淘汰；二者仅随成功缓存变更
        # 原子提交，stats(reset=True) 不清零。
        self._clean_expired = 0
        self._clean_evicted = 0

    def _negative_entry(self, key, rcode, an, ns, now):
        """完整计划可负缓存时返回 (负缓存键, 条目)，否则返回 None。

        key 已含 ECS 分区（无 ECS 时末项为 None），负键在原 NXDOMAIN/
        NODATA 键基础上保留该分区，故不同 ECS 分区各自独立。
        """
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
        partition = key[-1]
        if rcode == _RCODE_NXDOMAIN:
            neg_key = ("nxdomain", key[0], key[2], partition)  # 匹配任意 qtype
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
        return self._resolve_cached(msg, query, now, limit, _encode_plan)

    def resolve_edns(self, query: bytes, now: int,
                     limit: int = 65535) -> tuple[bytes, bool]:
        """处理含一个 OPT 的单问题查询，返回 (应答报文, 是否命中)。

        query 非 bytes 抛 TypeError；QDCOUNT 非 1 或 QR 置位抛
        EncodeError；其余报文非法及 OPT 缺失（ARCOUNT=0）、OPT 非法或
        尾随字节沿用 edns 契约抛 EDNSError，即查缓存前须恰有一个合法
        OPT。now、limit 非 int 或为 bool 抛 TypeError；now 为负或回退抛
        CacheError；limit 不在 12..65535 抛 EncodeError。

        OPT 版本 1..255 时按版本协商直接返回 (BADVERS 应答, False)：
        应答同 edns 的 BADVERS 契约（上限 min(limit, CLASS)，超限抛
        EncodeError 且不置 TC），先于时钟回退判断返回，不校验 ECS，
        不读写缓存、FIFO、统计或时钟；版本 0 时 now 回退仍抛
        CacheError。版本 0 查询至多携带一个 ECS（码 8）：family 仅
        1/2、source 分别限 0..32/0..128、scope 须为 0、address 长度为
        (source+7)//8 且末字节未用低位须为 0；重复 ECS、未知 family、
        长度或位值非法在访问缓存前抛 EDNSError，不改变任何状态。合法
        ECS 时缓存按 (family,source,address) 分区，正缓存、NODATA、
        NXDOMAIN 均纳入，无 ECS 查询与 resolve 同区；缓存分区、TTL
        衰减、FIFO、命中与统计和 resolve 完全共享（分区内键忽略 OPT、
        ID、flags 与 limit）。应答按同一权威计划以 edns 语义编码，
        查询含 ECS 时 OPT 仅回写码 8（family、source 不变，
        scope=source，address 同查询，其他选项不回显），ECS 使报文超
        min(limit,OPT CLASS) 抛 EncodeError；异常不改变缓存、统计或
        最后时刻，成功原子提交；无 ECS 时应答与既有输出逐字节相同。
        """
        if not isinstance(now, int) or isinstance(now, bool):
            raise TypeError("now must be int")
        if now < 0:
            raise CacheError("now must be non-negative and monotonic")
        if not isinstance(query, bytes):
            raise TypeError("query must be bytes")
        if not _MIN_MESSAGE_LEN <= len(query) <= _MAX_MESSAGE_LEN:
            raise EDNSError("bad message length")
        _check_int(limit, "limit")
        if (int.from_bytes(query[2:4], "big") & 0x8000
                or int.from_bytes(query[4:6], "big") != 1
                or not _MIN_LIMIT <= limit <= _MAX_LIMIT):
            raise EncodeError("query or limit not answerable")
        # 长度、QDCOUNT 与可应答性已预检；EDNS 查询查缓存前须恰有一个
        # 合法 OPT：opt 为 None（缺失）、OPT 非法或尾随字节均为
        # EDNSError（_decode_edns_query 对其余非法已统一抛 EDNSError）。
        msg, opt = _decode_edns_query(query)
        if opt is None:
            raise EDNSError("query must contain exactly one OPT")
        if opt[1] != 0:
            # 版本协商：OPT 版本 1..255 直接以 BADVERS 拒绝，先于时钟
            # 回退判断返回，不校验 ECS，不读写缓存、FIFO、统计或时钟。
            return _encode_badvers(msg, opt, limit), False
        # 版本 0：ECS 校验先于缓存访问（含时钟回退判断），任何非法均
        # 不改变缓存、统计或最后时刻；其他选项码原样忽略。
        ecs = _parse_query_ecs(opt[3])
        if self._last_now is not None and now < self._last_now:
            raise CacheError("now must be non-negative and monotonic")
        return self._resolve_cached(msg, query, now, limit,
                                    _encode_plan_edns, ecs)

    def _resolve_cached(self, msg, query, now, limit, encode_plan,
                        ecs=None):
        """resolve/resolve_edns 共用的缓存查找、计划应答与原子提交。

        msg 为已解码且通过可应答性检查的单问题报文；encode_plan 为
        (query, rcode, an, ns, limit, ecs=None) -> 应答报文 的编码器，
        其异常即本次失败，不改变条目、统计与时钟。ecs 非 None 时缓存
        键追加 (family,source,address) 分区，普通 resolve 路径恒为
        None（无 ECS 单独分区）。
        """
        question = msg["questions"][0]
        partition = None if ecs is None else (ecs[0], ecs[1], ecs[2])
        key = (question["name"], question["type"], question["class"],
               partition)
        expired = None  # 到期条目在 _order 中的标记键，待编码成功后清理
        entry = self._entries.get(key)
        if entry is not None:
            inserted, an, ar_glue = entry
            elapsed = now - inserted
            # 整条正缓存的到期以 ANSWER 与 ADDITIONAL 全部记录的最小原始
            # TTL 判断；命中时两段 TTL 按同一显式 now 等量衰减。
            min_ttl = min([rr[3] for rr in an]
                          + [rr[3] for rr in ar_glue])
            if elapsed < min_ttl:
                aged = [(labels, rrtype, rrclass, ttl - elapsed, rdata)
                        for labels, rrtype, rrclass, ttl, rdata in an]
                aged_ar = [(labels, rrtype, rrclass, ttl - elapsed, rdata)
                           for labels, rrtype, rrclass, ttl, rdata
                           in ar_glue]
                # 用本次 ID、flags、问题段、limit 重编码；截断不改条目，
                # 命中也不改变插入次序。
                response = encode_plan(query, 0, aged, [], limit, ecs,
                                       ar=aged_ar)
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
                neg_key = ("nxdomain", key[0], key[2], partition)
                neg = self._neg_entries.get(neg_key)
            if neg is not None:
                inserted, rcode, soa, neg_ttl = neg
                elapsed = now - inserted
                if elapsed < neg_ttl:
                    aged_soa = (soa[0], soa[1], soa[2],
                                neg_ttl - elapsed, soa[4])
                    # 用本次 ID、flags、问题段、limit 重编码；RCODE 不变，
                    # an/ar 为空，ns 仅 SOA；截断不改条目与插入次序。
                    response = encode_plan(query, rcode, [], [aged_soa],
                                           limit, ecs)
                    # 统计、时钟仅在成功返回时原子提交；命中不重排 FIFO。
                    # neg_key 首项区分 NXDOMAIN（h[1]）与 NODATA（h[2]）。
                    self._stats_h[1 if neg_key[0] == "nxdomain" else 2] += 1
                    self._last_now = now
                    return response, True
                expired = ("neg", neg_key)
        # 未命中（含到期）：先按 answer 语义生成未截断的完整有序应答
        # （含确定性地址附加段）。
        rcode, an, ns, ar_glue = _answer_plan(
            msg, self._origin, self._records, self._zone_class)
        # 先编码成功再落条目，保证编码失败不改变任何状态（含统计与时钟）。
        response = encode_plan(query, rcode, an, ns, limit, ecs, ar=ar_glue)
        # 编码已成功：到期清理、新条目、统计与时钟随成功返回原子提交。
        # 分类按未截断完整计划，故截断不改变 m 的分类。
        if expired is not None:
            tag, ekey = expired
            del (self._entries if tag == "pos" else self._neg_entries)[ekey]
            self._order.remove(expired)  # 到期删除后按未命中刷新
        if (rcode == 0 and not ns and an
                and all(rr[3] > 0 for rr in an)
                and all(rr[3] > 0 for rr in ar_glue)):
            # 正条目把 ANSWER 与地址 ADDITIONAL 纳入同一计划：命中时两段
            # TTL 等量衰减，并以两段最小原始 TTL 判断整条是否到期。
            self._entries[key] = (now, an, ar_glue)
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
            self._clean_evicted += 1  # 容量 FIFO 淘汰，随成功原子提交
        if expired is not None:
            self._stats_x += 1  # 本次成功 resolve 实际删除的到期条目
            self._clean_expired += 1
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


def _decode_edns_response(query, response, max_len=None):
    """校验 EDNS 应答并返回其 OPT 的 (CLASS, TTL)；任何不符抛 EncodeError。

    response 须 QR=1、ID 与 QDCOUNT 同 query、问题字节与 query 的问题段
    逐字节相同，且全报文恰有一个合法 OPT 并为附加段末项：未压缩根
    owner、TYPE41、CLASS512..65535、扩展码 0、版本 0..255、flags 仅
    DO、RDLENGTH 内选项 TLV 完整（同 _decode_edns_query 的 OPT 契约，
    此处违例一律 EncodeError）。max_len 非 None 时总长度还须不超该
    有效上限，否则抛 EncodeError。query 须已通过 _decode_edns_query
    校验（单问题）。
    """
    if not _MIN_MESSAGE_LEN <= len(response) <= _MAX_REPLY_LEN:
        raise EncodeError("bad response length")
    if max_len is not None and len(response) > max_len:
        raise EncodeError("response exceeds effective limit")
    if not int.from_bytes(response[2:4], "big") & _FLAG_QR:
        raise EncodeError("response must have QR set")
    if response[0:2] != query[0:2] or response[4:6] != query[4:6]:
        raise EncodeError("response id or question count mismatch")
    query_end = _reply_question_end(query, 1)
    end = _reply_question_end(response, 1)
    if (end is None or response[_MIN_MESSAGE_LEN:end]
            != query[_MIN_MESSAGE_LEN:query_end]):
        raise EncodeError("response question mismatch")
    ancount = int.from_bytes(response[6:8], "big")
    nscount = int.from_bytes(response[8:10], "big")
    arcount = int.from_bytes(response[10:12], "big")
    total = ancount + nscount + arcount
    pos = end
    opt = None  # (CLASS, TTL)，仅允许附加段末项恰一个
    for index in range(total):
        start = pos
        # 跳过 owner 名字（应答中可为压缩形式，仅界定不解码）。
        while True:
            if pos >= len(response):
                raise EncodeError("record name truncated")
            length = response[pos]
            kind = length & 0xC0
            if kind == 0xC0:
                if pos + 1 >= len(response):
                    raise EncodeError("record name truncated")
                pos += 2
                break
            if kind != 0x00:
                raise EncodeError("reserved label type")
            pos += 1
            if length == 0:
                break
            if pos + length > len(response):
                raise EncodeError("record name truncated")
            pos += length
        if pos + 10 > len(response):
            raise EncodeError("record truncated")
        rrtype = int.from_bytes(response[pos:pos + 2], "big")
        rrclass = int.from_bytes(response[pos + 2:pos + 4], "big")
        ttl = int.from_bytes(response[pos + 4:pos + 8], "big")
        rdlength = int.from_bytes(response[pos + 8:pos + 10], "big")
        pos += 10
        if pos + rdlength > len(response):
            raise EncodeError("record rdata truncated")
        rdata = pos
        pos += rdlength
        if rrtype != _TYPE_OPT:
            continue
        if opt is not None or index != total - 1 or index < ancount + nscount:
            raise EncodeError("OPT must be the last additional record")
        # OPT 字段契约同 _decode_edns_query，违例一律 EncodeError。
        if response[start] != 0:
            raise EncodeError("opt owner must be uncompressed root")
        if rrclass < _MIN_OPT_CLASS:
            raise EncodeError("opt class out of range")
        if ttl >> 24:
            raise EncodeError("opt extended rcode must be 0")
        if ttl & 0xFFFF & ~_FLAG_DO:
            raise EncodeError("opt flags must be DO only")
        opt_end = rdata + rdlength
        while rdata < opt_end:
            if rdata + 4 > opt_end:
                raise EncodeError("opt option truncated")
            opt_len = int.from_bytes(response[rdata + 2:rdata + 4], "big")
            rdata += 4
            if rdata + opt_len > opt_end:
                raise EncodeError("opt option data truncated")
            rdata += opt_len
        opt = (rrclass, ttl)
    if pos != len(response):
        raise EncodeError("trailing bytes")
    if opt is None:
        raise EncodeError("response must contain exactly one OPT")
    return opt


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


def _matching_edns_reply(query, reply, max_len):
    """EDNS 直转候选是否可用：问题一致、恰一合法末项 OPT 且不超有效上限。

    _decode_edns_response 已以 _reply_question_end 界定查询问题段（不含
    查询自身的 OPT），并统一校验长度范围、QR、ID、QDCOUNT、问题字节逐字
    节一致、恰一个合法附加段末项 OPT 与尾随字节；max_len 为 min(limit,
    OPT CLASS)。任何不符均按不可用应答处理（不抛异常）。不能复用
    _matching_reply：其以 query[12:]（EDNS 查询还含 OPT）比较问题段，
    对含 OPT 的查询恒不匹配。
    """
    try:
        _decode_edns_response(query, reply, max_len)
    except EncodeError:
        return False
    return True


def forward_edns(query, plan, now, timeout, max_len):
    """按 plan 顺序模拟向上游转发含 OPT 的 query，时序与 forward 一致。

    候选 reply 除 forward 的问题一致要求外，还须恰含一个合法末项 OPT
    且总长度不超 max_len，否则按不可用应答继续尝试；全部超时抛
    UpstreamTimeout，存在非超时失败但无可用应答抛 UpstreamError。
    成功返回 (reply, name, 结束时刻)。
    """
    _check_non_negative_int(now, "now")
    _check_int(timeout, "timeout")
    if not _MIN_TIMEOUT <= timeout <= _MAX_TIMEOUT:
        raise ValueError("timeout out of range")
    _check_int(max_len, "max_len")
    if max_len < 0:
        raise ValueError("max_len must be non-negative")
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
            if reply is not None and _matching_edns_reply(
                    query, reply, max_len):
                return reply, name, clock
            saw_other = True
    if saw_timeout and not saw_other:
        raise UpstreamTimeout("all upstream attempts timed out")
    raise UpstreamError("no usable upstream reply")


def _check_forward_config(config):
    """对已解析的 v0/v1 上游配置对象做完整结构校验，返回 (version, plan list)。

    v0 顶层键序仅 v,timeout,plan（v=0）；v1 顶层键序仅
    v,timeout,attempts,plan（v=1）。timeout 为 1..60、attempts 为 1..2
    的非 bool 整数（v0 迁移补 attempts=2，仅用于交叉约束）；plan 含
    1..16 项，项键序仅 name,events，name 为非空 str；events 含 0..2
    项，项键序仅 delay,reply，delay 为非负非 bool 整数，reply 为 null
    或解码后不超 65535 字节的偶长小写十六进制。某上游 events 多于
    attempts 抛 ConfigError。容器或字段类型、键序、版本、范围、十六
    进制错误统一抛 ConfigError；返回的 plan 为两层保持原序的配置列表
    （reply 保留原始 None/小写十六进制字符串）。
    """
    if not isinstance(config, dict):
        raise ConfigError("config must be an object")
    keys = list(config.keys())
    if keys == _FORWARD_CONFIG_KEYS_V0:
        version = 0
    elif keys == _FORWARD_CONFIG_KEYS_V1:
        version = 1
    else:
        raise ConfigError("invalid config key order")
    value = config["v"]
    if not isinstance(value, int) or isinstance(value, bool):
        raise ConfigError("v must be int")
    if value != version:
        raise ConfigError("unsupported v")
    timeout = config["timeout"]
    if not isinstance(timeout, int) or isinstance(timeout, bool):
        raise ConfigError("timeout must be int")
    if not _MIN_TIMEOUT <= timeout <= _MAX_TIMEOUT:
        raise ConfigError("timeout out of range")
    if version == 1:
        attempts = config["attempts"]
        if not isinstance(attempts, int) or isinstance(attempts, bool):
            raise ConfigError("attempts must be int")
        if not _FORWARD_MIN_ATTEMPTS <= attempts <= _FORWARD_MAX_ATTEMPTS:
            raise ConfigError("attempts out of range")
    else:
        attempts = _FORWARD_DEFAULT_ATTEMPTS
    plan = config["plan"]
    if not isinstance(plan, list):
        raise ConfigError("plan must be list")
    if not 1 <= len(plan) <= _MAX_PLAN_ITEMS:
        raise ConfigError("plan must contain 1..16 items")
    checked_plan = []
    for item in plan:
        if not isinstance(item, dict):
            raise ConfigError("plan item must be an object")
        if list(item.keys()) != _FORWARD_PLAN_ITEM_KEYS:
            raise ConfigError("plan item keys must be name,events")
        name = item["name"]
        if not isinstance(name, str):
            raise ConfigError("name must be str")
        if not name:
            raise ConfigError("name must be non-empty")
        events = item["events"]
        if not isinstance(events, list):
            raise ConfigError("events must be list")
        if not 0 <= len(events) <= _PLAN_EVENTS_USED:
            raise ConfigError("events must contain 0..2 items")
        if len(events) > attempts:
            raise ConfigError("events must not exceed attempts")
        checked_events = []
        for event in events:
            if not isinstance(event, dict):
                raise ConfigError("event must be an object")
            if list(event.keys()) != _FORWARD_EVENT_KEYS:
                raise ConfigError("event keys must be delay,reply")
            delay = event["delay"]
            if not isinstance(delay, int) or isinstance(delay, bool):
                raise ConfigError("delay must be int")
            if delay < 0:
                raise ConfigError("delay must be non-negative")
            reply = event["reply"]
            if reply is not None:
                if not isinstance(reply, str):
                    raise ConfigError("reply must be null or str")
                if (len(reply) % 2
                        or any(c not in _LOWER_HEXDIGITS for c in reply)):
                    raise ConfigError(
                        "reply must be even-length lowercase hex")
                if len(reply) // 2 > _MAX_REPLY_LEN:
                    raise ConfigError("reply exceeds 65535 bytes")
            checked_events.append({"delay": delay, "reply": reply})
        checked_plan.append({"name": name, "events": checked_events})
    return version, timeout, attempts, checked_plan


def migrate_forward(text: str) -> str:
    """把 v0/v1 上游配置文本完整校验、规范化并迁移为 v1 配置文本。

    v0 顶层键序仅 v,timeout,plan（v=0），迁移补 attempts=2；v1 顶层
    键序仅 v,timeout,attempts,plan（v=1）。timeout 为 1..60、attempts
    为 1..2 的非 bool 整数；plan 含 1..16 项，项键序仅 name,events，
    name 为非空 str；events 含 0..2 项，项键序仅 delay,reply，delay
    为非负非 bool 整数，reply 为 null 或解码后不超 65535 字节的偶长
    小写十六进制。先完整校验内容，再保持 plan 与 events 两层原序
    输出 v1；某上游 events 多于 attempts 抛 ConfigError。输出为固定
    键序（v,timeout,attempts,plan；项 name,events；事件 delay,reply）
    的紧凑 ASCII JSON，整数十进制、十六进制小写、末尾单换行。同输入
    逐字节一致，规范 v1 再次迁移逐字节不变。text 非 str 抛 TypeError；
    JSON 解析、重复键、键序、版本、容器或字段类型、范围、十六进制
    错误均抛 ConfigError（不泄漏 json 异常）。输入限 1048576 码点。
    """
    if not isinstance(text, str):
        raise TypeError("text must be str")
    if len(text) > _MAX_MIGRATE_TEXT_LEN:
        raise ConfigError("text exceeds 1048576 code points")
    try:
        config = json.loads(text, object_pairs_hook=_config_pairs)
    except ConfigError:
        # 重复键由 _config_pairs 抛 ConfigError，原样传播。
        raise
    except (json.JSONDecodeError, RecursionError, ValueError):
        # json 对超长整数抛非 JSONDecodeError 的 ValueError、对超深
        # 嵌套抛 RecursionError，统一归为 ConfigError，不泄漏 json 异常。
        raise ConfigError("invalid JSON") from None
    _version, timeout, attempts, plan = _check_forward_config(config)
    out = {"v": 1, "timeout": timeout, "attempts": attempts, "plan": plan}
    return json.dumps(out, ensure_ascii=True,
                      separators=(",", ":")) + "\n"


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


def _check_stale_window(value):
    """resolve_recursive 的 stale_window 校验：非 bool 整数、0..86400。"""
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError("stale_window must be int")
    if not 0 <= value <= _MAX_STALE_WINDOW:
        raise ValueError("stale_window out of range")


def _name_in_origin(question, origin, zone_class):
    """qclass 等于 zone 类且规范化 qname 在 origin 内（含 origin 自身）。"""
    qlabels = _normalize_name(question["name"])
    return (question["class"] == zone_class
            and len(qlabels) >= len(origin)
            and qlabels[len(qlabels) - len(origin):] == origin)


def _check_resolve_edns_inputs(query, now, limit, last_end):
    """resolve_edns 的入参/报文/OPT/ECS 校验，顺序同 PositiveCache.resolve_edns。

    返回 (msg, opt, ecs, badvers)：opt 为查询的 OPT 元组；版本 0 时
    ecs 为 None 或 (family, source, address)、badvers 为 None；版本
    1..255 时 badvers 为 BADVERS 应答、ecs 为 None——此时不校验 ECS、
    不做时钟回退判断，调用方须直接返回该应答且不访问区域、缓存、时钟、
    统计与上游。时钟单调性以 last_end 为准（仅版本 0 判断）。
    """
    if not isinstance(now, int) or isinstance(now, bool):
        raise TypeError("now must be int")
    if now < 0:
        raise CacheError("now must be non-negative and monotonic")
    if not isinstance(query, bytes):
        raise TypeError("query must be bytes")
    if not _MIN_MESSAGE_LEN <= len(query) <= _MAX_MESSAGE_LEN:
        raise EDNSError("bad message length")
    _check_int(limit, "limit")
    if (int.from_bytes(query[2:4], "big") & 0x8000
            or int.from_bytes(query[4:6], "big") != 1
            or not _MIN_LIMIT <= limit <= _MAX_LIMIT):
        raise EncodeError("query or limit not answerable")
    msg, opt = _decode_edns_query(query)
    if opt is None:
        raise EDNSError("query must contain exactly one OPT")
    if opt[1] != 0:
        # 版本协商先于时钟回退判断：直接返回 BADVERS，不校验 ECS，不访问
        # 区域、缓存、时钟、统计或上游。
        return msg, opt, None, _encode_badvers(msg, opt, limit)
    # 版本 0：ECS 校验先于缓存访问（含时钟回退判断）。
    ecs = _parse_query_ecs(opt[3])
    if last_end is not None and now < last_end:
        raise CacheError("now must be non-negative and monotonic")
    return msg, opt, ecs, None


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


def _upstream_forward_counts(plan, query, timeout, match=None):
    """按 forward 语义对 plan 逐上游统计一次直转的事件计数。

    返回与 plan 等长的 [a, s, to, e, bad, ms] 列表：每个上游仅取前 2
    个事件，尝试即 a 加 1；delay > timeout 时 to 加 1、ms 加 timeout，
    否则 ms 加 delay，reply 为 None 则 e 加 1，非空但未通过
    _matching_reply 则 bad 加 1，通过则 s 加 1 并停止。无事件的上游
    不计。match 非 None 时以 match(reply) 替代 _matching_reply 判定
    （EDNS 直转额外要求恰一个合法末项 OPT 与有效长度上限）。与
    forward/forward_edns 的时钟推进与停止点一致，本身不产生异常。
    """
    acceptable = (match if match is not None
                  else (lambda reply: _matching_reply(query, reply)))
    counts = [[0, 0, 0, 0, 0, 0] for _ in plan]
    for index, (_name, events) in enumerate(plan):
        entry = counts[index]
        for delay, reply in events[:_PLAN_EVENTS_USED]:
            entry[0] += 1  # a：尝试
            if delay > timeout:
                entry[2] += 1  # to：超时
                entry[5] += timeout
                continue
            entry[5] += delay
            if reply is None:
                entry[3] += 1  # e：无应答
            elif not acceptable(reply):
                entry[4] += 1  # bad：应答未通过匹配
            else:
                entry[1] += 1  # s：成功并停止
                return counts
    return counts


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


def _state_stats_text(h, m, x, u, c, l_buckets):
    """把 stats 计数六元组序列化为键序 h,m,x,u,c,l,r 的紧凑 JSON 对象文本。

    键序恰为 h,m,x,u,c,l,r；r 为按 h、m 重算的 6 位小数比值（分母 0
    写 0.000000）。与 stats() 及 dump_state 内嵌 stats 的编码一致。
    """
    return (
        '{"h":[' + ",".join(map(str, h)) + "]"
        + ',"m":' + str(m)
        + ',"x":' + str(x)
        + ',"u":[' + ",".join(map(str, u)) + "]"
        + ',"c":[' + ",".join(map(str, c)) + "]"
        + ',"l":[' + ",".join(map(str, l_buckets)) + "]"
        + ',"r":' + _ratio_six(sum(h), sum(h) + m) + "}"
    )


def _min_remaining_ttl(entries, now, negative, glue=False):
    """该类全部条目的最小剩余 TTL（下限 0），无条目为 -1。

    正条目值为 (插入时刻, 规范化 an) 或权威正缓存的
    (插入时刻, 规范化 an, 规范化 ar)；glue 为真时后者额外把地址附加
    段纳入最小原始 TTL。负条目值为 (插入时刻, rcode, SOA, 负 TTL)；
    正条目剩余值为 max(0, 插入时刻 + RR 最小 TTL - now)，负条目以负
    TTL 同算。读取不清除到期项，故到期条目贡献 0。
    """
    remaining = -1
    for value in entries.values():
        inserted = value[0]
        if negative:
            ttl = value[3]
        elif glue:
            ttl = min([rr[3] for rr in value[1]] + [rr[3] for rr in value[2]])
        else:
            ttl = min(rr[3] for rr in value[1])
        current = max(0, inserted + ttl - now)
        if remaining < 0 or current < remaining:
            remaining = current
    return remaining


def _cache_watermark(pos_entries, neg_entries, order, now, glue=False):
    """按 a/r 键序 p,nx,nd,total,capacity,ttl 构造缓存水位片段。

    前三项为正缓存、NXDOMAIN、NODATA 条目数，total 为合计，capacity
    固定 256；ttl 为同顺序三整数，各取该类最小剩余 TTL，无条目为 -1。
    glue 为真时正条目为权威正缓存三元组，其最小 TTL 同时计入地址
    附加段；递归正条目为二元组，恒传 False。
    """
    nx_keys = [key for key in neg_entries if key[0] == "nxdomain"]
    nx_entries = {key: neg_entries[key] for key in nx_keys}
    nd_entries = {key: neg_entries[key] for key in neg_entries
                  if key[0] != "nxdomain"}
    nx_count = len(nx_entries)
    nd_count = len(nd_entries)
    pos_count = len(pos_entries)
    ttl_pos = _min_remaining_ttl(pos_entries, now, False, glue)
    ttl_nx = _min_remaining_ttl(nx_entries, now, True)
    ttl_nd = _min_remaining_ttl(nd_entries, now, True)
    return (
        '{"p":' + str(pos_count)
        + ',"nx":' + str(nx_count)
        + ',"nd":' + str(nd_count)
        + ',"total":' + str(len(order))
        + ',"capacity":' + str(_CACHE_CAPACITY)
        + ',"ttl":[' + str(ttl_pos) + "," + str(ttl_nx) + ","
        + str(ttl_nd) + "]}"
    )


def _check_rec_config(config):
    """结构层校验递归缓存配置对象，返回 (clock, [(kind, 缓存键, 原始rr列表)])。

    仅做结构校验：顶层/项/rr 键序、v、clock、items 数量、k/q/t/c 字段、
    rr 数组形态（p 非空、nx/nd 恰一条）与重复缓存键；错误统一抛
    ConfigError。rr 元素字段值与 SOA 语义不在此校验
    （见 _validate_rec_item）。
    """
    if not isinstance(config, dict):
        raise ConfigError("config must be an object")
    if list(config.keys()) != _REC_DUMP_KEYS:
        raise ConfigError("config keys must be v,clock,items")
    version = config["v"]
    if not isinstance(version, int) or isinstance(version, bool):
        raise ConfigError("v must be int")
    if version != 1:
        raise ConfigError("unsupported v")
    clock = config["clock"]
    if not isinstance(clock, int) or isinstance(clock, bool):
        raise ConfigError("clock must be int")
    if clock < 0:
        raise ConfigError("clock must be non-negative")
    items = config["items"]
    if not isinstance(items, list):
        raise ConfigError("items must be list")
    if len(items) > _CACHE_CAPACITY:
        raise ConfigError("items must contain at most 256 items")
    parsed = []
    seen = set()
    for item in items:
        if not isinstance(item, dict):
            raise ConfigError("item must be an object")
        if list(item.keys()) != _REC_ITEM_KEYS:
            raise ConfigError("item keys must be k,q,t,c,rr")
        kind = item["k"]
        if not isinstance(kind, str):
            raise ConfigError("k must be str")
        if kind not in _REC_ITEM_KINDS:
            raise ConfigError("k must be p, nx or nd")
        qname = item["q"]
        if not isinstance(qname, str):
            raise ConfigError("q must be str")
        try:
            qlabels = _normalize_name(qname)
        except RecordError:
            raise ConfigError("q must be an absolute name") from None
        if _labels_to_name(qlabels) != qname:
            raise ConfigError("q must be a lowercase absolute name")
        qtype = item["t"]
        if kind == "nx":
            # NXDOMAIN 条目匹配任意 qtype：t 必须为 null。
            if qtype is not None:
                raise ConfigError("t must be null for nx")
        else:
            if not isinstance(qtype, int) or isinstance(qtype, bool):
                raise ConfigError("t must be int")
            if not 0 <= qtype <= 0xFFFF:
                raise ConfigError("t out of range")
        qclass = item["c"]
        if not isinstance(qclass, int) or isinstance(qclass, bool):
            raise ConfigError("c must be int")
        if not 0 <= qclass <= 0xFFFF:
            raise ConfigError("c out of range")
        rrs = item["rr"]
        if not isinstance(rrs, list):
            raise ConfigError("rr must be list")
        if kind == "p":
            if not rrs:
                raise ConfigError("p item requires non-empty rr")
            tag = "pos"
            key = (qname, qtype, qclass)
        else:
            if len(rrs) != 1:
                raise ConfigError("nx/nd item requires exactly one SOA")
            tag = "neg"
            if kind == "nx":
                key = ("nxdomain", qname, qclass)
            else:
                key = ("nodata", qname, qtype, qclass)
        for rr in rrs:
            if not isinstance(rr, dict):
                raise ConfigError("rr element must be an object")
            if list(rr.keys()) != _REC_RR_KEYS:
                raise ConfigError("rr keys must be n,t,c,ttl,d")
        marker = (tag, key)  # 与 _rec_order 元素同形
        if marker in seen:
            raise ConfigError("duplicate cache key")
        seen.add(marker)
        parsed.append((kind, key, rrs))
    return clock, parsed


def _validate_rec_rr(rr):
    """校验 rr 元素的字段值（沿用 RR 值域），返回规范化 RR 元组。

    d 为偶长小写十六进制；字段类型或值域错误统一抛 RecordError。
    """
    hextext = rr["d"]
    if not isinstance(hextext, str):
        raise RecordError("d must be str")
    if (len(hextext) % 2
            or any(c not in _LOWER_HEXDIGITS for c in hextext)):
        raise RecordError("d must be even-length lowercase hex")
    model = {"name": rr["n"], "type": rr["t"], "class": rr["c"],
             "ttl": rr["ttl"], "rdata": bytes.fromhex(hextext)}
    try:
        return _validate_rr(model)
    except TypeError as exc:
        # JSON 层无 bytes/int 类型保证：RR 字段类型错同样归为 RecordError。
        raise RecordError(str(exc)) from None


def _validate_rec_item(kind, rrs):
    """校验项的 rr 字段值并规范化，返回规范化 RR 元组列表（RecordError）。

    nx/nd 项的唯一 RR 须为 SOA，且其 rdata 完整为两个未压缩绝对名与
    五个网络序 uint32。
    """
    checked = [_validate_rec_rr(rr) for rr in rrs]
    if kind != "p":
        soa = checked[0]
        if soa[1] != _TYPE_SOA:
            raise RecordError("nx/nd item must hold exactly one SOA")
        if _parse_soa_uint32_offset(soa[4]) is None:
            raise RecordError("soa rdata must be two names and five uint32")
    return checked


def _validate_rec_load(config, now, last_end):
    """load_rec/load_state 共用的配置对象后半段校验。

    入参为 JSON 解析（重复键已拒）后的配置对象：先做结构校验
    （ConfigError），再做时钟校验（now 为负或早于上次成功结束时刻、
    早于 clock 抛 CacheError），最后做 RR 值域与 SOA 校验，并要求
    p 项 RR 的 ttl 在衰减前为正（RecordError）。返回
    (clock, [(kind,key,规范化rr)], elapsed)；不改变任何状态。
    """
    clock, items = _check_rec_config(config)
    # 时钟校验在全部结构校验之后、RR 值域校验之前；失败均无副作用。
    if now < 0 or (last_end is not None and now < last_end):
        raise CacheError("now must be non-negative and monotonic")
    if now < clock:
        raise CacheError("now must not be earlier than clock")
    entries = [(kind, key, _validate_rec_item(kind, rrs))
               for kind, key, rrs in items]
    # p 项 RR 的 ttl 必须为正：ttl<=0 属非法记录，须在按 now-clock
    # 衰减之前抛 RecordError（此时尚未触碰缓存、FIFO 与时钟）。
    for kind, _key, rrs in entries:
        if kind == "p" and any(rr[3] <= 0 for rr in rrs):
            raise RecordError("p rr ttl must be positive")
    return clock, entries, now - clock


def _age_rec_entries(entries, elapsed, now):
    """按 elapsed 衰减已校验的递归缓存条目并丢弃到期项。

    返回 (正缓存dict, 负缓存dict, FIFO deque)；正条目插入时刻记 now、
    TTL 为衰减后的正整数；负条目 SOA 与负 TTL 同算，剩余 <=0 丢弃。
    """
    new_pos = {}
    new_neg = {}
    new_order = deque()
    for kind, key, rrs in entries:
        if kind == "p":
            aged = [(labels, rrtype, rrclass, ttl - elapsed, rdata)
                    for labels, rrtype, rrclass, ttl, rdata in rrs]
            if min(rr[3] for rr in aged) <= 0:
                continue  # 衰减后到期项丢弃（原始 ttl 均为正）
            new_pos[key] = (now, aged)
            new_order.append(("pos", key))
        else:
            labels, rrtype, rrclass, ttl, rdata = rrs[0]
            remaining = ttl - elapsed
            if remaining <= 0:
                continue  # 到期项丢弃
            soa = (labels, rrtype, rrclass, remaining, rdata)
            rcode = _RCODE_NXDOMAIN if kind == "nx" else 0
            new_neg[key] = (now, rcode, soa, remaining)
            new_order.append(("neg", key))
    return new_pos, new_neg, new_order


def _check_state_stats(obj, rec_items):
    """结构与交叉校验 dump_state 内嵌 stats 的解码对象，返回计数六元组。

    键序须恰为 h,m,x,u,c,l,r：h/u/c/l 各为定长（4/3/3/4）非负非 bool
    整数组，m、x 为非负非 bool 整数；r 为 0..1 的有限数值（bool 除外）
    且等于按 h、m 重算的 6 位小数比值；c[2] 固定为 256，c[1] 固定
    等于 rec.items 长度。形态或交叉约束错误统一抛 ConfigError。返回
    (h, m, x, u, c, l)（均为拷贝/原始不可变整数值）。
    """
    if not isinstance(obj, dict) or list(obj.keys()) != _STATS_KEYS:
        raise ConfigError("stats keys must be h,m,x,u,c,l,r")

    def counts(value, size, field):
        if not isinstance(value, list) or len(value) != size:
            raise ConfigError(
                field + " must be a list of " + str(size) + " ints")
        for item in value:
            if (not isinstance(item, int) or isinstance(item, bool)
                    or item < 0):
                raise ConfigError(
                    field + " items must be non-negative ints")
        return list(value)

    h = counts(obj["h"], 4, "h")
    u = counts(obj["u"], 3, "u")
    c = counts(obj["c"], 3, "c")
    l = counts(obj["l"], 4, "l")
    for field in ("m", "x"):
        value = obj[field]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ConfigError(field + " must be a non-negative int")
    m, x = obj["m"], obj["x"]
    r = obj["r"]
    if isinstance(r, bool) or not isinstance(r, (int, float)):
        raise ConfigError("r must be a number")
    # json 默认解析接受 NaN/Infinity，须显式拒绝。
    if r != r or r == float("inf") or r == float("-inf"):
        raise ConfigError("r must be finite")
    if not 0 <= r <= 1:
        raise ConfigError("r out of range")
    if c[2] != _CACHE_CAPACITY:
        raise ConfigError("c[2] must be 256")
    if c[1] != rec_items:
        raise ConfigError("c[1] must equal rec items length")
    if float(r) != float(_ratio_six(sum(h), sum(h) + m)):
        raise ConfigError("r must equal the hits ratio of h and m")
    return h, m, x, u, c, l


def _zero_state_ru():
    """零值 ru 计数：(16 行 7 列全零 l, 长度 7 全零 t)。"""
    rows = [[0] * _RECURSIVE_UP_COLS
            for _ in range(_RECURSIVE_UP_ROWS)]
    totals = [0] * _RECURSIVE_UP_COLS
    return rows, totals


def _check_state_ru(obj):
    """结构与交叉校验 dump_state 内嵌 ru 的解码对象，返回 (l, t)。

    键序须恰为 l,t：l 固定含 16 个数组，每个数组恰含 7 个非负非 bool
    整数；t 为长度 7 的非负非 bool 整数数组且逐列等于 l 各行之和。
    键序、维度、值域（bool 不得作整数）或合计错误统一抛 ConfigError。
    返回的 l、t 均为全新拷贝。
    """
    if not isinstance(obj, dict) or list(obj.keys()) != _RECURSIVE_UP_KEYS:
        raise ConfigError("ru keys must be l,t")
    rows_obj = obj["l"]
    if not isinstance(rows_obj, list) or len(rows_obj) != _RECURSIVE_UP_ROWS:
        raise ConfigError("ru.l must contain 16 rows")
    rows = []
    for row in rows_obj:
        if not isinstance(row, list) or len(row) != _RECURSIVE_UP_COLS:
            raise ConfigError("ru.l rows must contain 7 ints")
        for item in row:
            if (not isinstance(item, int) or isinstance(item, bool)
                    or item < 0):
                raise ConfigError("ru.l items must be non-negative ints")
        rows.append(list(row))
    totals_obj = obj["t"]
    if (not isinstance(totals_obj, list)
            or len(totals_obj) != _RECURSIVE_UP_COLS):
        raise ConfigError("ru.t must contain 7 ints")
    for item in totals_obj:
        if (not isinstance(item, int) or isinstance(item, bool)
                or item < 0):
            raise ConfigError("ru.t items must be non-negative ints")
    totals = list(totals_obj)
    for col in range(_RECURSIVE_UP_COLS):
        if sum(row[col] for row in rows) != totals[col]:
            raise ConfigError("ru.t must equal the column sums of ru.l")
    return rows, totals


def _state_ru_text(rows, totals):
    """把 ru 计数二元组序列化为键序 l,t 的紧凑 JSON 对象文本（无尾换行）。

    l 保持 16 行 7 列原序，t 为同顺序七整数；与 recursive_upstream_stats()
    及 dump_state 内嵌 ru 的编码逐字节一致。
    """
    rows_text = ",".join(
        "[" + ",".join(map(str, row)) + "]" for row in rows)
    return ('{"l":[' + rows_text + '],"t":['
            + ",".join(map(str, totals)) + "]}")


def migrate_state(text: str) -> str:
    """把 v0/v1/v2 整解析器状态文本完整校验并迁移为规范 v2 状态文本。

    v2 顶层键序 v,zones,rec,stats,ru（v=2）；v1 顶层键序
    v,zones,rec,stats（v=1，无 ru）；v0 顶层键序 v,zones,rec（v=0，
    无 stats、ru）。zones、rec 分别沿用 dump_zones()、dump_rec(now)
    的对象契约（schema 0/1 区域历史与递归缓存配置，含全部结构校验与
    区域快照、递归 RR 的语义校验）。v0 迁移补 stats：键序
    h,m,x,u,c,l,r，值依次为 [0,0,0,0]、0、0、[0,0,0]、
    [0,rec.items 长度,256]、[0,0,0,0]、0.000000；v1 统计保持不变
    （r 按 h、m 重算重写为等值 6 位小数）。v0/v1 迁移补零值 ru：
    键序 l,t，l 为 16 个长度 7 的全零数组，t 为长度 7 全零；v2 的 ru
    完整校验后规范化重写（l 须恰含 16 个长度 7 的非负非 bool 整数
    数组，t 长度 7 且逐列等于 l 之和，bool 不得作整数）。输出为键序
    v,zones,rec,stats,ru 的 v2 文本：紧凑 ASCII JSON、整数十进制、
    r 六位小数、末尾单换行，最多 16777216 字节。text 非 str 抛
    TypeError；text 超 16777216 码点、JSON 解析、重复键、键序、
    未知 v 或结构错误（含 ru 键序、维度、值域或合计非法）抛
    ConfigError；区域或 RR 语义错误沿用 ZoneError、RecordError。
    同输入逐字节一致，规范 v2 再次迁移逐字节不变。
    """
    if not isinstance(text, str):
        raise TypeError("text must be str")
    if len(text) > _MAX_STATE_TEXT_LEN:
        raise ConfigError("text exceeds 16777216 code points")
    try:
        config = json.loads(text, object_pairs_hook=_config_pairs)
    except json.JSONDecodeError:
        raise ConfigError("invalid JSON") from None
    if not isinstance(config, dict):
        raise ConfigError("state must be an object")
    keys = list(config.keys())
    if keys == _STATE_DUMP_KEYS:
        expect = 2
    elif keys == _STATE_DUMP_KEYS_V1:
        expect = 1
    elif keys == _STATE_DUMP_KEYS_V0:
        expect = 0
    else:
        raise ConfigError("state keys must be v,zones,rec[,stats[,ru]]")
    version = config["v"]
    if not isinstance(version, int) or isinstance(version, bool):
        raise ConfigError("v must be int")
    if version != expect:
        raise ConfigError("unsupported v")
    zones_obj, rec_obj = config["zones"], config["rec"]
    if not isinstance(zones_obj, dict) or not isinstance(rec_obj, dict):
        raise ConfigError("zones and rec must be objects")
    # 各段结构层校验全部先于任何语义校验（与 load_state 同序）：
    # zones 的 JSON 结构、rec 的配置结构、stats 的形态及交叉约束与 v2
    # ru 的形态、维度、值域及合计错误统一为 ConfigError。
    zones_text = json.dumps(zones_obj, ensure_ascii=True,
                            separators=(",", ":"))
    schema, _zversion, history = _parse_zones_config(zones_text)
    _clock, rec_items = _check_rec_config(rec_obj)
    if expect >= 1:
        h, m, x, u, c, l_buckets = _check_state_stats(
            config["stats"], len(rec_items))
    else:
        # v0 无统计：补全为零值快照，c[1] 固定等于 rec.items 长度。
        h, m, x = [0, 0, 0, 0], 0, 0
        u, l_buckets = [0, 0, 0], [0, 0, 0, 0]
        c = [0, len(rec_items), _CACHE_CAPACITY]
    if expect == 2:
        ru_rows, ru_totals = _check_state_ru(config["ru"])
    else:
        # v0/v1 无递归逐层上游统计：补全为零值快照。
        ru_rows, ru_totals = _zero_state_ru()
    # 区域快照语义沿用 load_zones（RecordError、ZoneError），递归 RR
    # 值域与 SOA 语义沿用 load_rec（RecordError）；全部通过后才组装。
    snapshot_loader = (_load_zone_snapshot if schema == 1
                       else _load_zone_snapshot_any)
    for item in history:
        snapshot_loader(item["zone"])
    entries = [(kind, key, _validate_rec_item(kind, rrs))
               for kind, key, rrs in rec_items]
    for kind, _key, rrs in entries:
        if kind == "p" and any(rr[3] <= 0 for rr in rrs):
            raise RecordError("p rr ttl must be positive")
    out = ('{"v":2,"zones":' + zones_text
           + ',"rec":' + json.dumps(rec_obj, ensure_ascii=True,
                                     separators=(",", ":"))
           + ',"stats":' + _state_stats_text(h, m, x, u, c, l_buckets)
           + ',"ru":' + _state_ru_text(ru_rows, ru_totals)
           + '}\n')
    # 紧凑 ASCII 文本字节数与码点数一致；整快照超 16MiB 拒绝输出。
    if len(out.encode("ascii")) > _MAX_STATE_TEXT_LEN:
        raise ConfigError("state text exceeds 16777216 bytes")
    return out


def _check_bundle_v2_forward(forward_obj):
    """完整校验封包 v2 的 forward 包装并返回规范化结果。

    返回 (version, history, audit)：version 为非负非 bool 整数；
    history 为按原序的键序 version,config 项列表（config 为
    migrate_forward 规范化后的 v1 对象）；audit 为 {"v":1,"o":[...]}，
    五键项键序 k,x,e,r,a，k="l" 的 x 已规范化为规范 v1 文本。

    结构与关联规则（违例抛 ReplayError）：顶层键序仅
    version,history,audit；history 含 1..32 项，项 version 非负非
    bool、严格升序且末项等于顶层 version；audit 键序 v,o（v=1），o
    含 0..4096 个五键项，k 仅 l/r：l 的 x 为 str、r 的 x 为非负非
    bool 且 0<=x<=e；e、a 非负非 bool，r 仅 applied/unchanged，
    applied 须 a=e+1、unchanged 须 a=e；后一项 e 须等于前一项 a、
    末项 a 须等于 version（首项 e 可已淘汰，不核）。快照内容仅在
    相关版本仍保留于 history 时核对：l 项 applied 核 a 快照、
    unchanged 核 e 快照等于规范化 x；r 项 x 保留时核 applied 的 a
    快照或 unchanged 的 e 快照等于 x 快照；淘汰版本不核内容。
    history config 与 audit 中 l.x 的配置语义错误沿用 migrate_forward
    原样抛出（ConfigError 等），不归为 ReplayError。
    """
    if not isinstance(forward_obj, dict):
        raise ReplayError("forward must be an object")
    if list(forward_obj.keys()) != _BUNDLE_V2_FORWARD_KEYS:
        raise ReplayError("forward keys must be version,history,audit")
    version = forward_obj["version"]
    if (not isinstance(version, int) or isinstance(version, bool)
            or version < 0):
        raise ReplayError("version must be a non-negative int")
    history = forward_obj["history"]
    if not isinstance(history, list) or not 1 <= len(history) <= 32:
        raise ReplayError("history must contain 1..32 items")
    history_out = []
    config_texts = {}
    previous = -1
    for item in history:
        if (not isinstance(item, dict)
                or list(item.keys()) != _BUNDLE_V2_HISTORY_ITEM_KEYS):
            raise ReplayError("history item keys must be version,config")
        item_version = item["version"]
        if (not isinstance(item_version, int)
                or isinstance(item_version, bool) or item_version < 0):
            raise ReplayError("history version must be a non-negative int")
        if item_version <= previous:
            raise ReplayError(
                "history versions must be strictly ascending")
        previous = item_version
        # config 语义完整沿用 migrate_forward：规范化文本同时作为快照
        # 核对依据，ConfigError 等原样传播（同 replay_bundle 的 forward
        # 段错误归类），不归为 ReplayError。
        config_text = migrate_forward(
            json.dumps(item["config"], ensure_ascii=True,
                       separators=(",", ":")) + "\n")
        config_texts[item_version] = config_text
        history_out.append({"version": item_version,
                            "config": json.loads(config_text)})
    if history_out[-1]["version"] != version:
        raise ReplayError("last history version must equal version")
    audit = forward_obj["audit"]
    if not isinstance(audit, dict) or list(audit.keys()) != _BUNDLE_V2_AUDIT_KEYS:
        raise ReplayError("audit keys must be v,o")
    audit_version = audit["v"]
    if (not isinstance(audit_version, int) or isinstance(audit_version, bool)
            or audit_version != 1):
        raise ReplayError("unsupported audit v")
    items = audit["o"]
    if not isinstance(items, list) or not 0 <= len(items) <= 4096:
        raise ReplayError("audit o must contain 0..4096 items")
    audit_out = []
    previous_after = None
    for item in items:
        if (not isinstance(item, dict)
                or list(item.keys()) != _BUNDLE_V2_AUDIT_ITEM_KEYS):
            raise ReplayError("audit item keys must be k,x,e,r,a")
        kind = item["k"]
        if not isinstance(kind, str) or kind not in _REPLAY_FORWARD_OPS:
            raise ReplayError('k must be "l" or "r"')
        value = item["x"]
        before = item["e"]
        result = item["r"]
        after = item["a"]
        if (not isinstance(before, int) or isinstance(before, bool)
                or before < 0):
            raise ReplayError("e must be a non-negative int")
        if (not isinstance(after, int) or isinstance(after, bool)
                or after < 0):
            raise ReplayError("a must be a non-negative int")
        if (not isinstance(result, str)
                or result not in _REPLAY_FORWARD_RESULTS):
            raise ReplayError('r must be "applied" or "unchanged"')
        if kind == "l":
            if not isinstance(value, str):
                raise ReplayError("x must be str when k is l")
            # 配置语义错误沿用 migrate_forward 原样抛出。
            value_text = migrate_forward(value)
        else:
            if (not isinstance(value, int) or isinstance(value, bool)
                    or value < 0):
                raise ReplayError("x must be a non-negative int when k is r")
            if value > before:
                raise ReplayError("rollback target must not exceed e")
            value_text = None
        # 链式关联：后一项 e 须等于前一项 a；首项 e 可已淘汰。
        if previous_after is not None and before != previous_after:
            raise ReplayError("e must equal the previous a")
        if result == "applied":
            if after != before + 1:
                raise ReplayError("applied requires a = e + 1")
        elif after != before:
            raise ReplayError("unchanged requires a = e")
        # 快照内容仅核保留版本：l 项核新版本（a）或当前版本（e）的
        # 历史快照等于规范化配置；r 项 x 保留时核目标版本与新版本/当前
        # 版本快照相同。淘汰版本不核内容。
        target_version = after if result == "applied" else before
        target_snapshot = config_texts.get(target_version)
        if kind == "l":
            if (target_snapshot is not None
                    and target_snapshot != value_text):
                raise ReplayError(
                    "audit config must match the retained snapshot")
            value_out = value_text
        else:
            source_snapshot = config_texts.get(value)
            if (source_snapshot is not None
                    and target_snapshot is not None
                    and source_snapshot != target_snapshot):
                raise ReplayError(
                    "rollback snapshot must match the target version")
            value_out = value
        audit_out.append({"k": kind, "x": value_out, "e": before,
                          "r": result, "a": after})
        previous_after = after
    if audit_out and audit_out[-1]["a"] != version:
        raise ReplayError("last audit a must equal version")
    return version, history_out, {"v": 1, "o": audit_out}


def migrate_bundle(text: str) -> str:
    """把 v1/v2 重放封包完整校验并迁移为规范 v2 封包文本。

    v1 与 v2 顶层键序均仅 v,state,forward,log,result；v1 的 v=1、
    forward 为 migrate_forward 的 v1 配置对象，迁移为版本 0、单项
    历史（version=0、config=规范化 v1 配置）与空 audit
    （{"v":1,"o":[]}）；v2 的 v=2、forward 为键序
    version,history,audit 的包装，经 _check_bundle_v2_forward 完整
    校验关联并规范化。state 经 migrate_state 完整校验规范化；三段
    经与 replay_bundle 相同的隔离恢复路径重放 log，其输出须与
    result 逐字节相同。输出为 v=2 的紧凑 ASCII JSON、末尾单换行，
    不超过 16777216 字节；规范 v2 再次迁移逐字节不变。text 非 str
    抛 TypeError；超 16777216 码点、非 ASCII、JSON、重复键、顶层
    键序、v、forward 包装结构/关联、log/result 结构或结果不符抛
    ReplayError；state、forward 配置语义错误沿用 migrate_state、
    migrate_forward，操作异常原样传播。
    """
    if not isinstance(text, str):
        raise TypeError("text must be str")
    if len(text) > _MAX_REPLAY_BUNDLE_LEN:
        raise ReplayError("bundle exceeds 16777216 code points")
    if not text.isascii():
        raise ReplayError("bundle must be ASCII")
    try:
        bundle = json.loads(text, object_pairs_hook=_replay_log_pairs)
    except ReplayError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError):
        raise ReplayError("invalid JSON") from None
    if not isinstance(bundle, dict):
        raise ReplayError("bundle must be an object")
    if list(bundle.keys()) != _REPLAY_BUNDLE_KEYS:
        raise ReplayError("bundle keys must be v,state,forward,log,result")
    version = bundle["v"]
    if (not isinstance(version, int) or isinstance(version, bool)
            or version not in (1, 2)):
        raise ReplayError("unsupported v")
    state_obj, forward_obj = bundle["state"], bundle["forward"]
    log_obj, result_obj = bundle["log"], bundle["result"]
    # state 完整校验与规范化沿用 migrate_state（ConfigError/
    # ZoneError/RecordError/CacheError 等原样传播）；规范化对象同时作为
    # v2 输出的 state 段。
    state_text = json.dumps(state_obj, ensure_ascii=True,
                            separators=(",", ":"))
    state_norm_text = migrate_state(state_text)
    state_norm_obj = json.loads(state_norm_text)
    log_text = json.dumps(log_obj, ensure_ascii=True,
                          separators=(",", ":")) + "\n"
    # 与 replay_bundle 相同的隔离恢复路径完整校验 forward（v1 规范化、
    # v2 校验 version,history,audit 关联）并重放 log（恢复实例仅存在于
    # 本方法内）：forward 包装结构/关联与 log 结构错误抛 ReplayError，
    # 配置语义与操作异常原样传播；返回值直接给出规范化 v2 forward 包装。
    _resolver, out_text, forward_wrapper = Resolver._recover_bundle_resolver(
        state_text, version, forward_obj, log_text)
    expected_text = json.dumps(result_obj, ensure_ascii=True,
                               separators=(",", ":")) + "\n"
    if out_text != expected_text:
        raise ReplayError("replay result does not match bundle result")
    result_norm_obj = json.loads(out_text)
    out = json.dumps(
        {"v": 2, "state": state_norm_obj, "forward": forward_wrapper,
         "log": log_obj, "result": result_norm_obj},
        ensure_ascii=True, separators=(",", ":")) + "\n"
    if len(out) > _MAX_REPLAY_BUNDLE_LEN:
        raise ReplayError("migrated bundle exceeds 16777216 bytes")
    return out


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

    resolve_edns(query, now, limit=65535)：处理恰含一个合法末项 OPT 的
    单问题查询，返回与 resolve 同形的四元组
    (应答报文, 来源, 结束时刻, 是否命中)。报文、OPT、ECS、now、limit
    的范围及异常类型与 PositiveCache.resolve_edns 一致，有效长度上限
    取 min(limit, OPT CLASS)。OPT 版本 1..255 在访问区域、缓存、时钟、
    统计与上游前直接返回 (BADVERS 应答, "edns", now, False)，不校验
    ECS 也不做时钟回退判断。版本 0 区内查询使用现有权威正/负缓存与
    ECS 分区，来源为 "authority"：无 ECS 时与现有权威 EDNS 输出逐字节
    一致，有 ECS 时应答 OPT 仅回写规范 ECS，TTL 衰减、NXDOMAIN、
    NODATA、截断与命中标记沿用当前契约；区外查询按当前上游顺序、
    attempts 与 timeout 转发，来源为成功上游名，结束时刻累加事件延迟，
    命中恒为 False。候选应答还须问题一致、恰含一个合法末项 OPT 且总
    长度不超有效上限，否则按不可用应答继续尝试；全部超时抛
    UpstreamTimeout，存在非超时失败但无可用应答抛 UpstreamError。
    成功的区内解析按现有 authority 口径更新命中、未中、到期、水位与
    最后时刻；成功或耗尽的区外转发按普通 resolve 的口径原子更新逐上游
    结果、失败分类与耗时分桶。BADVERS、参数或报文错误、时钟回退与
    编码失败均不改变缓存、FIFO、时钟或统计；相同初态、查询、显式时钟
    与上游计划必须产生逐字节相同的应答与统计，单次调用最多检查现有
    上游及其允许的事件数，不新增无界状态。

    resolve_authorized(query, client, rules, now, limit=512,
    default="deny")：授权匹配、TypeError 与 PolicyError 沿用 authorize，
    其余校验及异常沿用 resolve，全部校验通过后方可改变状态。放行时
    行为等同 resolve。拒绝时不访问上游，返回
    (应答, "policy", now, False)，应答保留 ID 并重编码问题，flags 为
    0x8400|(查询 flags&0x7910)|5，QDCOUNT=1，其余计数为 0；超 limit
    抛 EncodeError。拒绝与任何失败都不改变区域、正/负缓存、FIFO、递归
    缓存、时钟或统计。

    resolve_limited(query, client, policy, limiter, now, limit=512,
    default="deny")：ACL、每客户端限流与解析的组合入口，返回五元组
    (应答报文, 来源, 结束时刻, 是否命中, 余量)。limiter 非
    RateLimiter 抛 TypeError；其余校验与异常依次沿用 authorize、
    resolve、limiter.allow。授权拒绝复用 resolve_authorized 的拒绝
    应答且不调用 limiter/上游，后四值为 "policy",now,False,-1。
    授权后仅调用一次 limiter.allow(query, client, now, "query")：
    放行时调用 resolve 并追加余量（resolve 异常仍耗额度，失败语义
    不变）；限流拒绝不调用 resolve/上游，返回同形 REFUSED 报文及
    "rate",now,False,0，仅提交 limiter 的 deny、清理、时钟与统计。
    拒绝报文超 limit 抛 EncodeError 且解析器与 limiter 均不变。
    IP 规范、固定窗、4096 键与 CacheError 沿用 RateLimiter。

    resolve_rated(query, client, policy, limiter, now, limit=512,
    default="deny", truncate=True)：ACL、查询/响应两维限流与解析的
    组合入口，返回六元组 (应答报文或 None, 来源, 结束时刻, 是否命中,
    查询余量, 响应余量)。limiter 非 RateLimiter、truncate 非 bool
    抛 TypeError；其余校验与异常依次沿用 authorize、resolve、
    limiter.allow/respond，前置失败不改变任何状态。ACL 拒绝后五值
    为 "policy",now,False,-1,-1，查询限流拒绝为 "rate",now,False,
    0,-1，均不解析。查询放行只调用一次 resolve（异常保留查询计数、
    响应不计数）；解析成功再以应答与结束时刻调用一次
    limiter.respond：放行保留原 source/end/hit 并返回两维余量，
    拒绝时解析器已提交，不回滚、不重算、不再访上游，来源为
    "response-rate"，end/hit 保留，truncate 真返回 TC、假返回
    None，响应余量 0。两维各计数；同初态同序列逐字节一致。

    rated_stats(reset=False)：resolve_rated 的确定性统计，返回仅含
    键序 o,e,l 的紧凑 ASCII JSON（末尾单换行），值为非负十进制整数
    数组。o 四项依次计 policy 拒绝、query-rate 拒绝、response-rate
    拒绝与响应放行；e 两项依次计查询放行后 resolve 异常、解析成功
    后 limiter.respond 异常（异常仍传播，原子计一次，既有双方状态
    语义不变）；l 四项按实际上游耗时 0、1..timeout、
    timeout+1..2*timeout、>2*timeout 分桶，仅实际上游成功或耗尽时
    各记一桶，权威、缓存及未访问上游不计。每次 resolve_rated 调用
    只增加一个 o 或 e；前置参数、授权、查询限流或拒绝报文编码异常
    不计。reset 非 bool 抛 TypeError 且状态不变；False 只读，重复
    调用逐字节相同；True 先返回旧快照再清零十项计数，其余状态与
    stats() 不变。

    resolve_recursive(query, levels, now, limit=512, stale_window=0)：
    域内查询沿用 resolve（stale_window 不校验、不影响）；域外查询先完整
    校验 query、levels、now、limit 与 stale_window（非 bool 整数，
    0..86400，类型错抛 TypeError、越界抛 ValueError；默认与显式 0 与原
    行为逐字节兼容），再查独立的递归缓存（键、正/负 TTL、容量 256、FIFO
    同 PositiveCache），新鲜命中返回 (应答报文, "cache", now, True)，
    未命中（含命中已过期条目）不删除、不立即返回，再按 1–16 层转介计划
    逐层模拟 forward（顺序、前 2 事件、时钟、timeout、耗尽异常均同
    forward，末层转介抛 UpstreamError）。终态按原序与本次 query、limit
    编码后写入递归缓存，返回 (应答报文, 终态上游名, 结束时刻, False)。
    仅当最终结果原本应为 UpstreamTimeout 或 UpstreamError、stale_window
    大于 0，且上游耗尽时刻减该条目到期时刻不超过窗口时，命中过期正答案、
    NXDOMAIN 或 NODATA 的查询改返 (陈旧应答, "stale", 耗尽时刻, True)：
    陈旧正答案 ANSWER TTL 全为 0，陈旧负答案保留原 RCODE、问题段与 SOA
    数据仅把授权段 SOA 的 RR TTL 置 0，压缩、记录顺序、长度上限与 RRset
    原子截断规则不变；陈旧返回不刷新插入时刻与 TTL、不改 FIFO、不删除或
    重写过期项（cache_stats 剩余 TTL 仍为 0，dump_rec 与状态导出仍跳过
    它），按原耗尽类别计未命中、到期、上游失败与耗时桶，不增命中计数，
    最后成功时刻推进到耗尽时刻；窗口外仍抛原异常。陈旧应答因 limit 无法
    编码抛 EncodeError，缓存、FIFO、最后时刻与全部统计均不改变。

    任何其他失败都原样传播且不改变缓存与上次成功结束时刻；成功后时钟
    单调性以该结束时刻为准。

    stats()：只读统计，返回键序 h,m,x,u,c,l,r 的紧凑 ASCII JSON（末尾
    换行）；仅成功返回、上游耗尽或陈旧返回时原子更新（c[0] 随提交与
    权威缓存同步），参数/计划/编码/时钟异常不更新，耗尽（未返陈旧时）
    不改缓存与最后时刻。

    upstream_stats(reset=False)：构造 plan 直转的逐上游统计，返回顶层
    键序仅 p,t 的紧凑 ASCII JSON（末尾单换行）。p 按 plan 位置列对象
    （重名不合并），键序仅 i,n,a,s,to,e,bad,ms：i 为从 0 起的位置
    序号，n 为原上游名，其余为非负整数（a 尝试、s 成功、to 超时、
    e 无应答、bad 应答未通过匹配、ms 模拟耗时累计；每个上游仅取前
    2 个事件，无事件不计）。t 省略 i、n，余键同序并为逐项和。仅经
    resolve 或 resolve_edns 进入该 plan 的直转计数（权威、缓存与
    resolve_recursive 的 levels 不计），直转成功或耗尽抛
    UpstreamTimeout/UpstreamError 时原子提交，其他异常不提交。
    resolve_edns 的候选除问题一致外还须恰含一个合法末项 OPT 且不超
    有效上限，否则记 bad；reset 非 bool 抛 TypeError 且无变化；
    False 只读，True 先返回旧快照再清零上述计数，plan、缓存、时钟
    及其他统计不变。

    recursive_upstream_stats(reset=False)：resolve_recursive 逐层转发
    的按深度统计，返回顶层键序仅 l,t 的紧凑 ASCII JSON（末尾单换行）。
    l 固定含 16 个数组，索引对应递归深度 0..15，每项为七个非负整数
    [a,r,s,to,e,bad,ms]：a 尝试数、r 接受的非末层转介数、s
    kind=1/2/3 终态数、to delay>timeout 数、e reply=None 数、bad 末层
    kind=0 数、ms 模拟耗时累计；超时仅给 ms 加 timeout，其余事件加
    delay；每个上游仅取前 2 个事件，转介或终态后的事件不计。t 为同
    顺序七整数数组，逐项等于 l 各行之和。仅域外递归缓存未命中且
    levels 全量校验通过后暂存本次已访问事件，成功返回、耗尽抛
    UpstreamTimeout/UpstreamError 或返回陈旧应答时原子提交；查询、
    levels、stale_window、编码、缓存写入或其他异常以及权威、缓存命中
    均不提交。reset 非 bool 抛 TypeError 且无变化；False 只读、重复
    调用逐字节相同；True 先返回旧快照再清零本统计，缓存、时钟、区域、
    plan 及其他统计不变。

    dump_forward()：导出当前上游转发配置，返回键序仅 version,config
    的紧凑 ASCII JSON（末尾单换行）。version 为从 0 起的热加载版本号；
    config 为 migrate_forward 的 v1 对象（键序 v,timeout,attempts,
    plan，初始 attempts=2，plan 保持原序、每上游仅取前 attempts 个
    事件）。只读：同状态逐字节相同。

    reload_forward(text, expected)：带版本检查的原子上游配置热加载，
    返回键序仅 version,result 的紧凑 ASCII JSON 报告（末尾单换行）。
    expected 非 int（含 bool）抛 TypeError，负值抛 ConfigError；
    expected 不等于当前版本号时不解析 text，报告 conflict 且状态
    不变（不入审计）。相符时 text 非 str 抛 TypeError，否则复用
    migrate_forward 完整校验并规范化（输入限 1048576 码点）。候选与
    当前生效配置相同报告 unchanged（版本号不变）；否则原子替换
    timeout、attempts 与 plan，版本号加 1 并报告 applied。applied 后
    域外 resolve 依新 plan 原序、每上游取前 attempts 个事件并用新
    timeout；upstream_stats 按新 plan 清零，缓存、时钟与其他统计
    保留，除此之外无副作用。result 仅 "applied"、"unchanged" 或
    "conflict"；unchanged 与 applied 在 expected 匹配且无异常时按
    提交序记入 forward_audit（x 为规范化配置文本），conflict 与任何
    异常均不改变任何状态且不入账。

    构造时初始上游配置存为版本 0；reload_forward 或 rollback_forward
    报告 applied 时按新版本号归档规范化快照，历史容量 32、超量淘汰
    最小版本号，版本号单调递增不复用。

    forward_versions()：只读返回保留的上游配置版本号，为严格升序
    元组；不改变任何状态。

    forward_audit()：只读导出已提交上游配置变更的提交序审计，输出
    紧凑 ASCII JSON、末尾单换行，顶层键序仅 v,o（v 恒为 1），o 至多
    4096 项、项键序仅 k,x,e,r,a：k 取 "l"/"r"，k="l" 时 x 为
    migrate_forward 规范化文本、k="r" 时 x 为非负目标版本，e、a 为
    该步前、后版本号，r 取 "applied"/"unchanged"。仅 expected 匹配
    且未抛异常的 reload_forward、rollback_forward 及成功
    replay_forward 内的各步入账；conflict、异常与整批失败不入账。
    完整输出超 16777216 字节或项数超 4096 时淘汰最早项；空队列输出
    {"v":1,"o":[]} 加换行。只读：同状态重复调用逐字节一致，其文本可
    直接作为 replay_forward 的 log 重放。

    rollback_forward(target, expected)：带版本检查的原子上游配置
    回滚，返回键序 version,result,target 的紧凑 ASCII JSON 报告
    （末尾单换行）。target/expected 非 int（含 bool）抛 TypeError，
    负值抛 ConfigError；expected 不等于当前版本号时不查 target，
    报告 conflict（不入审计）；相等且 target 未保留抛 ConfigError；
    目标为当前版本或与当前配置等价报告 unchanged；否则恢复
    timeout、attempts 与 plan，版本号加 1 并按新版本号归档，报告
    applied。applied 后 upstream_stats 按恢复 plan 清零，缓存、时钟、
    区域、递归状态与其他统计不变；unchanged 与 applied 在 expected
    匹配且无异常时按提交序记入 forward_audit（x 为目标版本号），
    conflict 与任何异常均不改变任何状态且不入账。

    replay_forward(log, expected)：确定性原子重放上游配置操作序列，
    返回键序 v,r 的紧凑 ASCII JSON 报告（末尾单换行）。log 限
    1048576 码点 ASCII JSON，顶层键序 v,o（v=1），o 含 0..4096 项
    （空 o 合法、结果恒 unchanged），兼容旧三键项 k,x,e 与
    forward_audit 五键项 k,x,e,r,a（同一日志可混用）：k="l" 时 x
    为 migrate_forward 配置文本，k="r" 时 x 为非负非 bool 目标
    版本；e 为非负非 bool 的步骤前预期版本，五键项的 r 须为该步实际
    结果、a 须为步骤后版本。log/expected 类型错抛 TypeError，
    expected<0 抛 ConfigError；expected 不等于当前版本号时不解析
    log，报告 conflict（v 为当前版本号）且状态不变。相符时先规范化
    全部项，再无副作用推演配置、历史与版本（整批核对通过前不调用
    reload_forward/rollback_forward）：每步调用前核对 e、调用后核对
    五键项 r、a，不符均抛 ReplayError；rollback 目标未保留抛
    ConfigError，任一失败不执行、不提交、不入账。全序列核对通过后
    才隔离执行，随后一次原子提交配置、直转统计、版本号、32 项历史与
    forward_audit 队列（成功序列各步按提交序入账），其余状态不变；
    v 为提交后版本号，r 为出现 applied 则 "applied"，否则
    "unchanged"。提交后状态等同逐步调用，同初态同序列逐字节一致。

    cache_stats(now, reset=False)：缓存水位快照，返回顶层键序仅 a,r,x,v
    的紧凑 ASCII JSON（末尾单换行）。a、r 为权威、递归缓存，键序均为
    p,nx,nd,total,capacity,ttl：前三类为正缓存、NXDOMAIN、NODATA 条目
    数，total 为合计，capacity 固定 256；ttl 为同顺序三整数，各取该类
    最小剩余 TTL（正条目 = max(0, 插入时刻 + RR 最小 TTL - now)，负条目
    以负 TTL 同算），无条目为 -1，读取不清除到期项。x、v 为 [权威,递归]
    非负整数数组，累计构造或重置后成功解析实际删除的到期条目数与容量
    FIFO 淘汰数；换区、更新、回滚的清空不计，既有累计随这些操作保留，
    计数随成功缓存变更原子提交。now 非 int 或为 bool、reset 非 bool 抛
    TypeError；now<0 或早于上次成功结束时刻抛 CacheError，均无副作用。
    reset=False 只读；True 先返回按 now 计算的旧快照再清零 x、v，保留
    缓存、FIFO、时钟及统计；同参逐字节一致。

    dump_rec(now)：把此刻仍有效的递归缓存条目按 FIFO 插入次序导出为
    确定性配置文本，只读。顶层键序仅 v,clock,items：v 恒为 1，clock
    为入参 now；items 不超过 256 项，项键序仅 k,q,t,c,rr：k 为
    "p"（正缓存）、"nx"（NXDOMAIN）或 "nd"（NODATA），q 为小写绝对
    qname，t、c 为 qtype、qclass（nx 匹配任意 qtype，t 为 null）；
    rr 元素键序 n,t,c,ttl,d，沿用 RR 值域，d 为偶长小写十六进制。
    p 的 rr 非空，ttl 为各 RR 的剩余正整数；nx/nd 恰一条 SOA，ttl
    为负缓存剩余值。到期项跳过但不删除。输出为紧凑 ASCII JSON、
    整数十进制、末尾单换行。now 非 int 或为 bool 抛 TypeError；
    now<0 或早于上次成功结束时刻抛 CacheError，均无副作用；同状态
    同参逐字节相同。

    load_rec(text, now)：校验递归缓存配置文本并原子替换递归缓存，
    返回保留的条目数。text 非 str 或 now 非 int（含 bool）抛
    TypeError；text 超 1048576 码点、JSON 解析、重复键、键序、非
    RR 字段（v/clock/items/k/q/t/c 与 rr 数组形态）或重复缓存键
    错误抛 ConfigError；now 为负、回退（早于上次成功结束时刻）或
    小于 clock 抛 CacheError；RR 字段值或 SOA 错误抛 RecordError，
    p 项 RR 的 ttl<=0 在衰减前即抛 RecordError。全部结构校验先于
    时钟校验，时钟校验先于 RR 值域校验。全部通过后按 now-clock
    衰减各 ttl、丢弃到期项，原子替换递归正负缓存与 FIFO 并置成功
    时刻为 now；权威缓存、统计与清理计数不变。任何失败都无副
    作用；同初态同参逐字节一致。

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

    reload_zone_serial_tx(text, expected, force=False)：带修订号检查与
    SOA 序列号比较的原子换区事务，返回键序 version,result,serial 的
    紧凑 ASCII JSON 报告（末尾换行）。text 非 str、expected 非 int
    （含 bool）或 force 非 bool 抛 TypeError，expected<0 抛
    ConfigError；验参后 expected 不等于当前修订号时不解析 text，报告
    conflict（serial 为 null）且状态不变。相等时经 import_zone 导入并
    构造候选 PositiveCache，失败沿用 ConfigError、RecordError、
    ZoneError 且状态不变。新旧两区的 SOA rdata 均须完整为两个未压缩
    绝对名与五个网络序 uint32 且无尾随，否则抛 ZoneError。候选与当前
    区域相同报告 unchanged；否则比较新旧 SOA 序列号：force=False 时
    仅新序列号比当前为 newer 才换区并报告 applied，equal/older 报告
    stale，ambiguous 报告 ambiguous；force=True 时一律换区并报告
    applied。applied 原子换区、清空权威缓存、修订号加 1 并按新修订号
    归档，保留递归缓存、时钟、plan 与统计（提交当下 stats() 逐字节
    不变）；serial 为候选序列号（conflict 时为 null）。unchanged、
    stale、ambiguous、conflict 或任何异常均不改变任何状态。

    构造时把规范化初始区域存为修订 0；每次 reload_zone 成功或
    reload_zone_tx 报告 applied，按新当前修订号保存区域深拷贝，
    unchanged、conflict 与异常不保存。历史容量 32：超量后淘汰最小修订
    号的快照，修订号不复用。

    rollback_zone_tx(target, expected)：带修订号检查的原子回滚事务，
    返回键序 version,result,target 的紧凑 ASCII JSON 报告（末尾换行）。
    target/expected 非 int（含 bool）抛 TypeError，负值抛 ConfigError；
    两参数校验完成后先比较 expected：不等于当前修订号时不得查询
    target，报告 conflict；相等且 target 为当前修订号报告 unchanged；
    target 未保留（含已淘汰）报告 missing。命中时先以快照构造
    PositiveCache，成功后原子换区、清空权威缓存，修订号加 1 并把恢复
    区域按新修订号归档，报告 applied；递归缓存、时钟、plan 与统计均
    保留，提交当下 stats() 逐字节不变。非 applied 结果或任何异常均不
    改变任何状态。

    update_zone_tx(changes, serial, expected)：带修订号与 SOA 序列号
    检查的原子区域更新事务，返回键序 version,result,serial 的紧凑
    ASCII JSON 报告（末尾换行）。changes 为 1..256 项，项键序
    op,record，op 为 "add"/"delete"，record 同 zone.records 契约且
    type 为 6（SOA）抛 ZoneError；serial 为 uint32，expected 非负。
    类型错（含 bool 整数）抛 TypeError；数量、项键、op 值或整数
    范围错抛 ConfigError。验参后先比 expected：不等于当前修订号报告
    conflict 且不验项；再验项；当前 SOA rdata 须完整为两个未压缩
    绝对名与五个 uint32 且无尾随，否则 ZoneError；serial 与当前序列号
    经 compare_serial 比较为 newer 才更新，equal、older、ambiguous
    均报告 stale。隔离
    执行：add 无同五字段 RR 才尾加，delete 删尽同 RR；记录列表不变
    报告 unchanged，否则把 SOA 序列号改为 serial，经 PositiveCache
    完整验证后原子换区（清空权威缓存，保留递归缓存、时钟、plan 与
    统计），修订号加 1 并按新修订号归档，报告 applied。version 取
    操作后修订号，serial 原样；非 applied 或任何异常均不改变任何
    状态。

    transfer_zone(from_serial, limit=65535)：只读区域传送，返回键序
    version,serial,mode,delete,add 的紧凑 ASCII JSON（末尾单换行）。
    version 为当前修订号，serial 为当前 SOA 序列号，delete/add 为 RR
    数组（RR 键序 name,type,class,ttl,rdata；名称为小写绝对名，整数
    十进制，rdata 为偶长小写十六进制）。from_serial 为 uint32、limit
    为 1..65535 的非 bool int；from_serial 与当前序列号经
    compare_serial 比较：equal 或 newer 时 mode 为 "none" 且两列表
    空；ambiguous 抛 TransferError。older 时取历史中 SOA 序列号等于
    from_serial 的最大
    修订，按 RR 五字段与重复次数求差：delete 依旧区原序，add 依当前区
    原序；delete+add 总数不超 limit 用 mode "ixfr"。无匹配修订或差异
    超 limit 时改用 mode "axfr"：delete 为空、add 为当前全部 RR 原序；
    仍超 limit 抛 TransferError。非 int 或 bool 抛 TypeError，整数越界
    抛 ConfigError；所读 SOA 不符两个未压缩绝对名加五个 uint32 格式
    抛 ZoneError。只读：同状态同参逐字节一致，不改变任何状态。

    dump_zones()：把区域修订历史导出为 schema=1 的确定性配置文本，
    只读且同状态逐字节相同；load_zones(text, plan, timeout=5) 类
    方法先校验全部快照再恢复实例（schema 0/1，schema=0 旧格式历史
    限 1..256 项、zone 接受 v0/v1/v2，仅留 revision 最大的 32 项），
    末项区域为当前区，历史与修订号一并恢复（后续成功变更从
    version+1 继续），新实例缓存为空、时钟未设、统计清零；两者详见
    各自文档。

    save_zones(path)：把 dump_zones() 字节写入与目标同目录的临时
    文件，flush 并 fsync 后以 os.replace 原子替换目标，返回写入字节
    数；任何失败都删除临时文件、保留旧目标文件，解析器不发生改变
    （dump_zones 只读）。

    reload_zones_file(path, expected)：带修订号检查地从区域文件校验
    整份快照并原子换区，返回键序仅 version,result 的紧凑 ASCII JSON
    报告（末尾单换行）。path 非 str 或 expected 非 int（含 bool）抛
    TypeError；path 为空串或含 NUL、expected 为负抛 ConfigError。
    expected 不等于当前修订号时冲突且不读文件，报告 conflict
    （version 为当前修订号）。相符时读取文件：缺失抛
    FileNotFoundError，其余 I/O 错抛 OSError；内容上限
    16777216 字节，超限或含非 ASCII 字节抛 ConfigError。随后以当前
    plan、timeout 按 load_zones 校验全快照并构造候选解析器，异常原样
    传播且解析器不变。候选规范化内容与当前相同报告 unchanged（版本、
    状态不变）；不同时文件 version 必须大于当前修订号，否则抛
    ConfigError。成功后原子替换权威缓存（候选缓存为空）、修订历史与
    修订号，保留递归缓存、时钟、plan 与统计（提交当下 stats() 逐字节
    不变）；version 为操作后修订号，result 为 "applied"、"unchanged"
    或 "conflict"。

    dump_state(now)：导出区域历史、递归缓存、统计与递归逐层上游统计
    的整解析器快照，只读。顶层键序仅 v,zones,rec,stats,ru：v 恒为 2，
    zones、rec、stats 分别为 dump_zones()、dump_rec(now)、stats() 的
    解码对象，ru 为 recursive_upstream_stats(False)（只读、不重置）
    的解码对象（stats 的 c[1] 固定等于 rec.items 长度）。紧凑 ASCII
    JSON、末尾单换行，最多 16777216 字节，超限抛 ConfigError。now
    异常沿用 dump_rec（TypeError/CacheError）且只读；同状态同参逐
    字节相同。

    load_state(text, plan, now, timeout=5)：类方法，接受 v0/v1/v2
    状态文本，先经 migrate_state 完整校验并迁移为 v2 再恢复实例。
    zones 沿用 load_zones（schema 0/1），rec 沿用 load_rec（按
    now-rec.clock 衰减并丢弃到期项），stats 为 stats() 解码对象：
    键序 h,m,x,u,c,l,r，c[2] 固定 256、c[1] 固定等于 rec.items 长度
    且加载后按实际恢复条目数重算，r 须等于按 h、m 重算的 6 位小数
    比值；ru 为 recursive_upstream_stats() 的解码对象，l 固定 16 行
    7 列非负非 bool 整数、t 长度 7 且逐列等于 l 之和，加载后恢复
    递归逐层上游计数；其余沿用各自契约；v0（顶层键序 v,zones,rec，
    无 stats、ru）补零值统计与零值 ru，v1（无 ru）补零值 ru。恢复
    区域修订历史与修订号、stats 计数、递归正负缓存、FIFO、最后成功
    时刻（now）与 ru 计数；权威缓存为空，plan/timeout 取参数。
    text 非 str 或 now 非 int（含 bool）抛 TypeError；text 超
    16777216 码点、JSON、重复键、键序、未知 v 或交叉约束错（含 ru
    的键序、维度、值域或合计）抛 ConfigError；区域或 RR 语义错沿用
    ZoneError、RecordError，余错沿用 load_zones、load_rec 及构造器。
    任何失败都不产生实例；同态同参逐字节一致。

    save_state(path, now)：把 dump_state(now) 字节逐字节原子落盘，
    返回写入字节数。path 非 str 抛 TypeError；path 为空串或含 NUL 抛
    ConfigError；now 异常沿用 dump_state（TypeError/CacheError）。在
    目标同目录建唯一临时文件，循环 write 至全部字节写完（write 返回
    None、非 int 或非正数抛 OSError），flush、fsync 后 os.replace
    原子替换目标；任一步 I/O 失败抛 OSError，删除本次临时项、保留
    旧目标，解析器状态不变。成功也不改变任何状态，同态同参重复保存
    逐字节相同。

    load_state_file(path, plan, now, timeout=5)：类方法，从状态文件
    恢复等价解析器。path 非 str 抛 TypeError；path 为空串或含 NUL 抛
    ConfigError。最多读 16777217 字节：文件缺失抛 FileNotFoundError，
    其余 I/O 错抛 OSError；内容超过 16777216 字节或含非 ASCII 字节抛
    ConfigError。解码后完全复用 load_state 的协议（接受 v0/v1/v2
    文本并经 migrate_state 迁移为规范 v2；截断 JSON、重复键、未知 v
    或状态结构错抛 ConfigError，区域或 RR 语义错抛 ZoneError、
    RecordError）、plan/timeout 校验、时钟衰减与其余异常；任何失败
    都不产生实例，成功恢复区域历史与修订号、递归正负缓存、FIFO、
    统计、ru 计数与最后成功时刻（now），权威缓存为空。
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
        # resolve_rated 的确定性统计：o 依次计 policy 拒绝、query-rate
        # 拒绝、response-rate 拒绝、响应放行；e 依次计查询放行后
        # resolve 异常、解析成功后 limiter.respond 异常；l 按实际上游
        # 耗时分桶（0、1..timeout、timeout+1..2*timeout、>2*timeout）。
        self._rated_o = [0, 0, 0, 0]
        self._rated_e = [0, 0]
        self._rated_l = [0, 0, 0, 0]
        # upstream_stats 的逐上游计数：与 plan 位置一一对应（重名不合并），
        # 每项为 [a, s, to, e, bad, ms]，仅经 resolve/resolve_edns 的直转
        # 在成功返回或耗尽（UpstreamTimeout/UpstreamError）时原子提交。
        self._upstream_stats = [[0, 0, 0, 0, 0, 0] for _ in self._plan]
        # recursive_upstream_stats 的按深度计数：固定 16 行，索引对应递归
        # 深度 0..15，每行七整数 [a, r, s, to, e, bad, ms]，依次为尝试数、
        # 接受的非末层转介数、kind=1/2/3 终态数、delay>timeout 数、
        # reply=None 数、末层 kind=0 数、模拟耗时累计。仅域外递归缓存
        # 未命中且 levels 全量校验通过后暂存本次已访问事件，成功返回或
        # 耗尽抛 UpstreamTimeout/UpstreamError 时原子提交；权威、缓存命中
        # 及任何异常均不提交；t 在快照时由 l 逐项求和。
        self._recursive_up = [
            [0, 0, 0, 0, 0, 0, 0] for _ in range(_MAX_RECURSION_LEVELS)]
        # 上游转发配置热加载状态：attempts 初始为 2（构造 plan 沿用
        # forward 的前 2 事件语义），版本号初始为 0，仅 reload_forward
        # 报告 applied 时替换 timeout/attempts/plan 并加 1。
        self._attempts = _FORWARD_DEFAULT_ATTEMPTS
        self._forward_version = 0
        # 上游配置历史：版本号 -> (timeout, attempts, 截断 plan) 规范化
        # 快照。构造时初始配置存为版本 0，仅 reload_forward 与
        # rollback_forward 报告 applied 时按新版本号归档；容量 32，
        # 超量淘汰最小版本号，版本号单调递增不复用。快照元素均不可变
        # 且列表不原地改，与生效配置及外部改动隔离。
        self._forward_history = {}
        self._archive_forward(0)
        # forward_audit 的提交序入账队列：元素为已渲染的五键审计项文本
        # （键序 k,x,e,r,a），_forward_audit_bytes 为各项 len(文本)+1
        # 之和（项间逗号预算），非空完整输出长度 = 该值 + 14（空队列
        # 固定输出 {"v":1,"o":[]} 加换行）。仅成功的 reload_forward、
        # rollback_forward 与成功 replay_forward 的各步入账；与对应配置
        # 变更在同一原子步骤增减，副本推演时随之隔离演化，整批失败不
        # 影响真实解析器。
        self._forward_audit = deque()
        self._forward_audit_bytes = 0
        # stats 的 c[0]（权威条目数）：仅随统计提交与缓存同步，reload_zone
        # 替换缓存不提交统计，故换区后保持旧值直至下次解析提交。
        self._stats_c0 = 0
        # cache_stats 的清理事件累计：[权威, 递归] 各两个非负整数，依次为
        # 成功解析实际删除的到期条目数与容量 FIFO 淘汰数；换区、更新、
        # 回滚的清空不计。权威缓存被替换时其已提交事件经 fold 保留。
        self._clean_expired = [0, 0]
        self._clean_evicted = [0, 0]
        self._revision = 0  # 当前区域修订号；成功换区/回滚后加 1，不复用
        # 修订历史：修订号 -> 规范化区域深拷贝。构造时初始区域存为
        # 修订 0，仅成功换区/回滚按新修订号归档；容量 32，超量淘汰
        # 最小修订号。
        self._zone_history = {}
        self._archive_revision(0, self._cache)

    def _forward_plan(self):
        """当前生效的直转 plan：依 plan 原序，每上游仅取前 attempts 个事件。"""
        if self._attempts >= _PLAN_EVENTS_USED:
            return self._plan
        return [(name, events[:self._attempts])
                for name, events in self._plan]

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
            self._fold_authority_cleanup()
            if hit:
                self._stats_h[0] += 1
            else:
                self._stats_m += 1
                if expired:
                    self._stats_x += 1
            self._sync_stats_c0()
            self._last_end = now
            return response, "authority", now, hit
        # 直转的逐上游事件计数与 forward 共用同一确定性模拟，仅在成功
        # 返回或耗尽（UpstreamTimeout/UpstreamError）时随统计原子提交。
        # 生效 plan 每上游仅取前 attempts 个事件（reload_forward 热加载
        # 后依新 plan 原序与新 timeout）。
        plan = self._forward_plan()
        upstream_counts = _upstream_forward_counts(
            plan, query, self._timeout)
        try:
            reply, name, end = forward(query, plan, now, self._timeout)
        except UpstreamTimeout:
            self._commit_upstream_counts(upstream_counts)
            self._stats_u[1] += 1
            self._stats_l[_duration_bucket(
                _plan_total_elapsed(plan, self._timeout),
                self._timeout)] += 1
            self._sync_stats_c0()
            raise
        except UpstreamError:
            self._commit_upstream_counts(upstream_counts)
            self._stats_u[2] += 1
            self._stats_l[_duration_bucket(
                _plan_total_elapsed(plan, self._timeout),
                self._timeout)] += 1
            self._sync_stats_c0()
            raise
        self._commit_upstream_counts(upstream_counts)
        self._stats_u[0] += 1
        self._stats_l[_duration_bucket(end - now, self._timeout)] += 1
        self._sync_stats_c0()
        self._last_end = end
        return reply, name, end, False

    def resolve_edns(self, query: bytes, now: int,
                     limit: int = 65535) -> tuple[bytes, str, int, bool]:
        """EDNS 查询沿 resolve 同一路径完成校验、权威缓存或模拟转发。

        返回与 resolve 同形的四元组 (应答报文, 来源, 结束时刻, 是否命中)。
        报文、OPT、ECS、now、limit 的范围及异常类型与
        PositiveCache.resolve_edns 一致；有效长度上限取 min(limit,
        OPT CLASS)。OPT 版本 1..255 时在访问区域、缓存、时钟、统计与
        上游前直接返回 (BADVERS 应答, "edns", now, False)。版本 0 的
        区内查询使用现有权威正/负缓存与 ECS 分区，来源为 "authority"：
        无 ECS 时与现有权威 EDNS 输出逐字节一致，有 ECS 时仅回写规范
        ECS，TTL 衰减、NXDOMAIN、NODATA、截断与命中标记沿用当前契约，
        并按现有 authority 口径更新命中、未中、到期、水位与最后时刻。
        区外查询按当前上游顺序、attempts 与 timeout 转发，候选应答还
        须问题一致、恰含一个合法末项 OPT 且总长度不超有效上限，否则按
        不可用应答继续尝试；全部超时抛 UpstreamTimeout，存在非超时失败
        但无可用应答抛 UpstreamError。成功或耗尽均按普通 resolve 的口径
        原子更新逐上游结果、失败分类与耗时分桶，命中恒为 False，来源为
        成功上游名，结束时刻累加事件延迟。BADVERS、参数或报文错误、
        时钟回退与编码失败均不改变缓存、FIFO、时钟或统计。
        """
        msg, opt, ecs, badvers = _check_resolve_edns_inputs(
            query, now, limit, self._last_end)
        if badvers is not None:
            # 版本协商：不访问区域、缓存、时钟、统计与上游，命中为 False。
            return badvers, "edns", now, False
        question = msg["questions"][0]
        origin = self._cache._origin
        effective_limit = min(limit, opt[0])
        if _name_in_origin(question, origin, self._cache._zone_class):
            # 区内：权威正/负缓存与 ECS 分区完全沿用 PositiveCache
            # 的 resolve_edns；解析器侧统计提交口径与 resolve 相同。
            expired = self._authority_miss_expired(question, now, ecs)
            response, hit = self._cache.resolve_edns(query, now, limit)
            self._fold_authority_cleanup()
            if hit:
                self._stats_h[0] += 1
            else:
                self._stats_m += 1
                if expired:
                    self._stats_x += 1
            self._sync_stats_c0()
            self._last_end = now
            return response, "authority", now, hit
        # 区外：候选须问题一致、恰含一个合法末项 OPT 且不超有效上限；
        # 逐上游事件计数、失败分类与耗时分桶口径同 resolve 直转，仅成功
        # 返回或耗尽（UpstreamTimeout/UpstreamError）时原子提交。
        plan = self._forward_plan()
        upstream_counts = _upstream_forward_counts(
            plan, query, self._timeout,
            match=lambda reply: _matching_edns_reply(
                query, reply, effective_limit))
        try:
            reply, name, end = forward_edns(
                query, plan, now, self._timeout, effective_limit)
        except UpstreamTimeout:
            self._commit_upstream_counts(upstream_counts)
            self._stats_u[1] += 1
            self._stats_l[_duration_bucket(
                _plan_total_elapsed(plan, self._timeout),
                self._timeout)] += 1
            self._sync_stats_c0()
            raise
        except UpstreamError:
            self._commit_upstream_counts(upstream_counts)
            self._stats_u[2] += 1
            self._stats_l[_duration_bucket(
                _plan_total_elapsed(plan, self._timeout),
                self._timeout)] += 1
            self._sync_stats_c0()
            raise
        self._commit_upstream_counts(upstream_counts)
        self._stats_u[0] += 1
        self._stats_l[_duration_bucket(end - now, self._timeout)] += 1
        self._sync_stats_c0()
        self._last_end = end
        return reply, name, end, False

    def resolve_authorized(self, query: bytes, client: str, rules: list,
                           now: int, limit: int = 512,
                           default: str = "deny"
                           ) -> tuple[bytes, str, int, bool]:
        """先按授权规则判定，再以 resolve 语义解析。

        授权匹配与规则、client、default 的 TypeError 及 PolicyError 沿用
        authorize（规则全部校验通过后才解码 query）；query、now、limit
        的其余校验及异常沿用 resolve（含时钟以上次成功结束时刻为准的
        单调性）；全部校验完成前不得改变任何状态。放行时行为与 resolve
        完全相同（权威缓存或上游转发，返回其来源、结束时刻与命中标记）。
        拒绝时不访问上游，返回 (拒绝应答, "policy", now, False)：应答
        保留 query 的 ID 并重编码问题段，flags 为
        0x8400|(查询 flags & 0x7910)|5，QDCOUNT=1，
        ANCOUNT/NSCOUNT/ARCOUNT 均为 0（不回显 OPT）；仅头部与问题超
        limit 抛 EncodeError。拒绝应答编码失败或任何校验异常均不改变
        区域、正/负缓存、FIFO、递归缓存、时钟与统计；拒绝本身也不更新
        时钟与统计。同初态同调用序列逐字节一致。
        """
        # 授权优先：其 TypeError、PolicyError 与报文/可应答性异常原样传播。
        allowed = authorize(query, client, rules, default)
        # 其余入参、时钟与 limit 校验完全沿用 resolve；此处不产生状态变更。
        _check_resolve_inputs(query, now, limit, self._last_end)
        if allowed:
            return self.resolve(query, now, limit)
        # 拒绝：先编码成功（超 limit 抛 EncodeError），且不改任何状态。
        response = _encode_policy_refusal(query, limit)
        return response, "policy", now, False

    def resolve_limited(self, query: bytes, client: str, policy: list,
                        limiter, now: int, limit: int = 512,
                        default: str = "deny"
                        ) -> tuple[bytes, str, int, bool, int]:
        """组合 ACL、每客户端限流与解析，返回 (应答, 来源, 结束, 命中, 余量)。

        limiter 非 RateLimiter 抛 TypeError（最先校验）。授权匹配与
        policy、client、default 的 TypeError 及 PolicyError 沿用
        authorize；query、now、limit 的其余校验及异常沿用 resolve
        （含时钟以上次成功结束时刻为准的单调性）；limiter 的 IP 规范、
        固定窗、4096 键与 CacheError 沿用 limiter.allow。全部校验
        通过前不改变解析器与 limiter 的任何状态。

        授权拒绝时复用 resolve_authorized 的拒绝应答（flags 为
        0x8400|(查询 flags&0x7910)|5，QDCOUNT=1，其余计数为 0），不
        调用 limiter 也不访问上游，后四值为 "policy",now,False,-1。
        授权放行后仅调用一次 limiter.allow(query, client, now,
        "query")：限流拒绝时不调用 resolve/上游，返回同形 REFUSED
        报文及 "rate",now,False,0，仅提交 limiter 的 deny、清理、
        时钟与统计；限流放行时调用 resolve，成功返回 (*resolve 结果,
        余量)。可能的限流拒绝应答在调用 allow 前先编码：超 limit 抛
        EncodeError 且 limiter 尚未调用、解析器亦未改变（双方不变）。
        resolve 失败也已耗额度：其异常原样传播，解析器失败语义同
        resolve（不改变其缓存、时钟与统计），limiter 的提交不回滚。
        同初态同调用序列逐字节一致。
        """
        # limiter 类型最先判定；其后异常依次沿用 authorize、resolve、
        # limiter.allow。
        if not isinstance(limiter, RateLimiter):
            raise TypeError("limiter must be a RateLimiter")
        # 授权优先：其 TypeError、PolicyError 与报文/可应答性异常原样传播，
        # 此时不触碰 limiter。
        allowed = authorize(query, client, policy, default)
        # resolve 的入参、时钟与 limit 校验须先于 limiter 计数完成，
        # 保证校验失败不消耗限流额度。
        _check_resolve_inputs(query, now, limit, self._last_end)
        if not allowed:
            # ACL 拒绝：复用 resolve_authorized 应答，不调用 limiter/上游，
            # 编码失败（超 limit）时双方均未改变。
            response = _encode_policy_refusal(query, limit)
            return response, "policy", now, False, -1
        # 限流可能返回的 REFUSED 应答只取决于 query 与 limit：先编码成功
        # 再调用 allow，保证超 limit 抛 EncodeError 时 limiter 未被调用、
        # 解析器未改变（双方不变）。
        refusal = _encode_policy_refusal(query, limit)
        # 授权后仅此一次 limiter 调用；其 deny、过期清理、淘汰、时钟与
        # 统计随返回原子提交。
        permitted, remaining = limiter.allow(query, client, now, "query")
        if not permitted:
            # 限流拒绝：不解析、不转发；仅 limiter 提交，解析器不变。
            return refusal, "rate", now, False, 0
        # 放行：resolve 异常仍耗额度（limiter 提交不回滚），失败语义同
        # resolve；成功时追加 allow 返回的余量。
        response, source, end, hit = self.resolve(query, now, limit)
        return response, source, end, hit, remaining

    def resolve_rated(self, query: bytes, client: str, policy: list,
                      limiter, now: int, limit: int = 512,
                      default: str = "deny", truncate: bool = True
                      ) -> tuple[bytes | None, str, int, bool, int, int]:
        """组合 ACL、查询/响应两维限流与解析，返回六元组。

        返回 (应答报文或 None, 来源, 结束时刻, 是否命中, 查询余量,
        响应余量)。limiter 非 RateLimiter、truncate 非 bool 均抛
        TypeError（最先校验）；其余校验与异常依次沿用 authorize、
        resolve、limiter.allow/respond，前置失败不改变解析器与
        limiter 的任何状态。

        授权拒绝时复用 resolve_authorized 的拒绝应答，不调用 limiter
        也不访问上游，后五值为 "policy",now,False,-1,-1。授权放行后
        仅调用一次 limiter.allow(query, client, now, "query")：查询
        配额拒绝时不解析、不转发，返回同形 REFUSED 报文及
        "rate",now,False,0,-1（拒绝报文超 limit 抛 EncodeError 时
        limiter 尚未调用、解析器亦未改变）。查询放行只调用一次
        resolve：其异常保留查询计数、响应不计数，原样传播。

        解析成功再以应答报文与结束时刻调用一次
        limiter.respond(query, wire, client, end, truncate)：放行
        保留原 source/end/hit 并返回两维余量；拒绝时解析器已提交，
        不回滚、不重算、不再访上游，来源改为 "response-rate"，end
        与 hit 保留，truncate 为真返回 TC 截断报文、为假返回 None，
        响应余量为 0。查询与响应两维各自计数；同初态同调用序列
        逐字节一致。每次调用的出口、异常与实际上游耗时按 rated_stats
        规则确定性地计数。
        """
        # limiter 与 truncate 的类型最先判定；其后异常依次沿用
        # authorize、resolve、limiter.allow/respond。
        if not isinstance(limiter, RateLimiter):
            raise TypeError("limiter must be a RateLimiter")
        if not isinstance(truncate, bool):
            raise TypeError("truncate must be bool")
        # 授权优先：其 TypeError、PolicyError 与报文/可应答性异常原样
        # 传播，此时不触碰 limiter。
        allowed = authorize(query, client, policy, default)
        # resolve 的入参、时钟与 limit 校验须先于 limiter 计数完成，
        # 保证校验失败不消耗限流额度。
        _check_resolve_inputs(query, now, limit, self._last_end)
        if not allowed:
            # ACL 拒绝：复用 resolve_authorized 应答，不调用 limiter，
            # 编码失败（超 limit）时双方均未改变。
            response = _encode_policy_refusal(query, limit)
            self._rated_o[0] += 1
            return response, "policy", now, False, -1, -1
        # 查询限流可能返回的 REFUSED 应答只取决于 query 与 limit：先编码
        # 成功再调用 allow，保证超 limit 抛 EncodeError 时 limiter 未被
        # 调用、解析器未改变（双方不变）。
        refusal = _encode_policy_refusal(query, limit)
        # 授权后仅此一次查询限流调用；其 deny、过期清理、淘汰、时钟与
        # 统计随返回原子提交。
        qpermitted, qleft = limiter.allow(query, client, now, "query")
        if not qpermitted:
            # 查询配额拒绝：不解析、不转发；仅 limiter 提交，解析器不变。
            self._rated_o[1] += 1
            return refusal, "rate", now, False, 0, -1
        # 查询放行：仅此一次 resolve；其异常仍耗查询额度（limiter 提交
        # 不回滚），响应维度不计数，失败语义同 resolve。resolve 仅在
        # 实际访问上游（成功或耗尽）时推进 _stats_l，故其增量即本次
        # 应记的实际上游耗时桶；权威、缓存及未访问上游时增量为零。
        before_l = list(self._stats_l)
        try:
            response, source, end, hit = self.resolve(query, now, limit)
        except Exception:
            # resolve 异常原子计一次 e[0] 后原样传播；上游耗尽的耗时
            # 桶（resolve 已按模拟总时长记入 _stats_l）一并补记。
            for i in range(4):
                self._rated_l[i] += self._stats_l[i] - before_l[i]
            self._rated_e[0] += 1
            raise
        for i in range(4):
            self._rated_l[i] += self._stats_l[i] - before_l[i]
        # 解析成功：仅此一次响应限流调用，时钟取解析结束时刻；其校验
        # 异常保留查询计数、响应不计数，原样传播。
        try:
            wire, rleft = limiter.respond(query, response, client, end,
                                          truncate)
        except Exception:
            # respond 异常原子计一次 e[1] 后原样传播。
            self._rated_e[1] += 1
            raise
        if wire is response:
            # 响应配额放行：来源、结束时刻与命中标记均保留，返回两维余量。
            self._rated_o[3] += 1
            return response, source, end, hit, qleft, rleft
        # 响应配额拒绝：解析器已提交，不回滚、不重算、不再访上游；来源
        # 改为 "response-rate"，end/hit 保留，truncate 真为 TC 报文、
        # 假为 None，响应余量为 0。
        self._rated_o[2] += 1
        return wire, "response-rate", end, hit, qleft, 0

    def _sync_stats_c0(self):
        """统计提交点：c[0] 与当前权威缓存条目数同步。"""
        self._stats_c0 = len(self._cache._order)

    def _commit_upstream_counts(self, counts):
        """把一次直转的逐上游事件计数原子并入 upstream_stats 累计。"""
        for index, entry in enumerate(counts):
            acc = self._upstream_stats[index]
            for kind in range(6):
                acc[kind] += entry[kind]

    def _fold_authority_cleanup(self):
        """把权威缓存自上次折叠以来的清理事件并入解析器累计。

        权威缓存仅在成功解析时提交其到期删除与 FIFO 淘汰计数，此处紧随
        成功的 _cache.resolve 折叠，故编码或上游异常不会带入事件；换区
        替换缓存时新缓存自 0 起计，历史已折叠部分继续保留。
        """
        cache = self._cache
        self._clean_expired[0] += cache._clean_expired
        self._clean_evicted[0] += cache._clean_evicted
        cache._clean_expired = 0
        cache._clean_evicted = 0

    def _authority_miss_expired(self, question, now, ecs=None):
        """本次权威缓存查找若未中，是否源于到期条目（查找顺序同 PositiveCache）。

        ecs 非 None 时键追加 (family,source,address) 分区，与
        PositiveCache.resolve_edns 的分区一致；普通 resolve/
        resolve_recursive 恒为 None（无 ECS 分区）。
        """
        cache = self._cache
        partition = None if ecs is None else (ecs[0], ecs[1], ecs[2])
        key = (question["name"], question["type"], question["class"],
               partition)
        entry = cache._entries.get(key)
        if entry is not None:
            inserted, an, ar_glue = entry
            # 与 PositiveCache 的正条目到期口径一致：取 ANSWER 与
            # ADDITIONAL 全部记录的最小原始 TTL。
            min_ttl = min([rr[3] for rr in an]
                          + [rr[3] for rr in ar_glue])
            return now - inserted >= min_ttl
        neg_key = ("nodata",) + key
        neg = cache._neg_entries.get(neg_key)
        if neg is None:
            neg_key = ("nxdomain", key[0], key[2], partition)
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

    def _encode_stale_recursive(self, query, expired, end, window, limit):
        """上游耗尽时刻 end 为到期条目编码陈旧应答；不在窗口内返回 None。

        窗口判定取上游耗尽时刻减条目到期时刻：正条目到期时刻为插入时刻 +
        ANSWER 最小原始 TTL，负条目为插入时刻 + 负 TTL；差值不超过 window
        才应答。陈旧正答案 ANSWER 各 RR 的 TTL 全为 0；陈旧负答案保留原
        RCODE 与 SOA 的 owner/type/class/rdata，仅把授权段唯一 SOA 的 RR
        TTL 置 0。编码沿用 _encode_plan 的名字压缩、记录顺序、长度上限与
        RRset 原子截断规则。仅读缓存、不做任何写入或统计提交；编码失败
        （超 limit）原样抛 EncodeError，由调用方保证不提交任何状态。
        """
        tag, ekey = expired
        if tag == "pos":
            inserted, an = self._rec_pos[ekey]
            expiry = inserted + min(rr[3] for rr in an)
            if end - expiry > window:
                return None
            stale_an = [(labels, rrtype, rrclass, 0, rdata)
                        for labels, rrtype, rrclass, _ttl, rdata in an]
            return _encode_plan(query, 0, stale_an, [], limit)
        inserted, rcode, soa, neg_ttl = self._rec_neg[ekey]
        expiry = inserted + neg_ttl
        if end - expiry > window:
            return None
        stale_soa = (soa[0], soa[1], soa[2], 0, soa[4])
        return _encode_plan(query, rcode, [], [stale_soa], limit)

    def _store_recursive_terminal(self, question, now, rcode, an, ns, expired):
        """终态按 PositiveCache 规则写入递归缓存（容量 256、FIFO）。

        先清理到期旧条目（编码已成功），再按正/负规则写入并按需淘汰；
        到期删除与 FIFO 淘汰各累计入递归清理事件计数。
        """
        if expired is not None:
            tag, ekey = expired
            del (self._rec_pos if tag == "pos" else self._rec_neg)[ekey]
            self._rec_order.remove(expired)
            self._clean_expired[1] += 1  # 成功解析实际删除的到期条目
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
            self._clean_evicted[1] += 1  # 容量 FIFO 淘汰

    def resolve_recursive(self, query: bytes, levels, now: int,
                          limit: int = 512,
                          stale_window: int = 0
                          ) -> tuple[bytes, str, int, bool]:
        """按 1–16 层转介计划递归解析域外查询。

        query/now/limit 的异常沿用 resolve；levels 为逐层 forward 式
        plan（1–16 层，每层 1–16 个上游，仅前 2 事件），reply 为 None
        或 (kind, an, ns)：0 转介、1 答案、2 NXDOMAIN、3 NODATA。
        时钟、timeout 与耗尽异常（全超时 UpstreamTimeout，其余
        UpstreamError）沿用 forward；末层仍为转介（kind 0）抛 UpstreamError。
        终态（kind 1/2/3）按原序与本次 query、limit 编码并按
        PositiveCache 键与正/负 TTL 规则缓存（256 项 FIFO，source 取
        上游名、hit=False）；递归缓存命中返回 (应答, "cache", now, True)。

        stale_window 为可选非 bool 整数（0..86400，默认 0）：类型错抛
        TypeError、越界抛 ValueError，仅域外查询在 query/levels/now/limit
        全量校验之后、递归缓存查找之前校验；域内权威查询不校验、不受其
        影响，默认 0 与显式 0 的报文、异常、统计及状态变化与原行为逐字节
        一致。域外查找命中已过期的正答案、NXDOMAIN 或 NODATA 时不立即
        返回或删除，仍照常完成全部递归层与上游尝试：仅当最终结果原本应为
        UpstreamTimeout 或 UpstreamError、stale_window 大于 0，且上游耗尽
        时刻减去该条目到期时刻不超过窗口时，返回 (陈旧应答, "stale",
        耗尽时刻, True)；否则抛原耗尽异常。陈旧正答案 ANSWER 各 RR TTL
        全为 0；陈旧负答案保留原 RCODE、问题段与 SOA 数据，仅把授权段
        唯一 SOA 的 RR TTL 置 0；名字压缩、记录顺序、长度上限与 RRset
        原子截断规则不变。陈旧返回不刷新插入时刻与 TTL、不改变 FIFO、
        不删除或重写过期条目（cache_stats 剩余 TTL 仍为 0，dump_rec 与
        状态导出仍跳过它）；本次 recursive_upstream_stats 仍提交，stats
        按原耗尽类别增加未命中、到期、上游失败与耗时计数，不增加命中
        计数，最后成功时刻推进到耗尽时刻。陈旧应答因 limit 无法编码时抛
        EncodeError，缓存、FIFO、最后时刻与全部统计均不改变。
        任何其他失败都不改变缓存与上次成功结束时刻。
        """
        msg = _check_resolve_inputs(query, now, limit, self._last_end)
        question = msg["questions"][0]
        origin = self._cache._origin
        if _name_in_origin(question, origin, self._cache._zone_class):
            # 域内沿用 resolve：经权威正/负缓存应答，source 为 "authority"。
            # stale_window 不参与域内路径：域内权威查询行为完全不变。
            expired = self._authority_miss_expired(question, now)
            response, hit = self._cache.resolve(query, now, limit)
            self._fold_authority_cleanup()
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
        # 入参非法不得呈现为命中，也不得改变任何状态。stale_window 紧随
        # 其后校验：两者均先于递归缓存查找与全部状态变化。
        plans = _validate_levels(levels)
        _check_stale_window(stale_window)
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
        # 仅当存在到期正/负条目且窗口大于 0 时，本次耗尽才可能改返陈旧
        # 应答；stale 标记只持有缓存键，不复制或改写条目内容。
        stale = expired if stale_window > 0 else None
        # levels 已全量校验且递归缓存确认未命中：本次各层已访问事件先暂存于
        # 本地 staged（固定 16 行，行索引即递归深度 0..15），仅成功返回、
        # 耗尽抛 UpstreamTimeout/UpstreamError 或返回陈旧应答时才原子并入
        # _recursive_up；查询、levels、编码、缓存写入或其他异常，以及权威
        # 路径与缓存命中，均不提交（staged 随栈丢弃）。
        staged = [[0, 0, 0, 0, 0, 0, 0]
                  for _ in range(_MAX_RECURSION_LEVELS)]
        # 逐层按 forward 时序模拟；终态先编码成功再记 end 与写缓存。
        clock = now
        result = None
        for depth, plan in enumerate(plans):
            result, clock, saw_timeout, saw_other = self._attempt_recursive_level(
                plan, clock, depth == len(plans) - 1, staged[depth])
            if result is None:
                # 该层所有上游均未给出可用应答：耗尽时刻即 clock。
                # 先尝试陈旧应答编码（窗口判定在其中）：编码因 limit 失败
                # 抛 EncodeError 时缓存、FIFO、最后时刻与全部统计均不变；
                # 窗口外返回 None，走原耗尽提交流程并抛原异常。
                if stale is not None:
                    stale_response = self._encode_stale_recursive(
                        query, stale, clock, stale_window, limit)
                    if stale_response is not None:
                        # 窗口内陈旧应答：不删除/重写过期条目、不动 FIFO；
                        # 按原耗尽类别提交 m/x、逐深度事件、u 与耗时分桶，
                        # 不计命中，最后成功时刻推进到耗尽时刻后原子返回。
                        self._stats_m += m_inc
                        self._stats_x += x_inc
                        self._commit_recursive_up(staged)
                        self._sync_stats_c0()
                        if saw_timeout and not saw_other:
                            self._stats_u[1] += 1
                        else:
                            self._stats_u[2] += 1
                        self._stats_l[_duration_bucket(
                            clock - now, self._timeout)] += 1
                        self._last_end = clock
                        return stale_response, "stale", clock, True
                # 窗口外或无到期条目：统计随耗尽提交，缓存与（非陈旧时）
                # 最后时刻不变，异常类型沿用 forward。
                self._stats_m += m_inc
                self._stats_x += x_inc
                self._commit_recursive_up(staged)
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
        self._commit_recursive_up(staged)
        self._sync_stats_c0()
        self._last_end = end
        return response, name, end, False

    def _commit_recursive_up(self, staged):
        """把一次递归解析暂存的逐深度事件计数原子并入 recursive 累计。"""
        for depth, entry in enumerate(staged):
            acc = self._recursive_up[depth]
            for kind in range(7):
                acc[kind] += entry[kind]

    def _attempt_recursive_level(self, plan, clock, is_last, counts):
        """模拟单层转发，返回 (result, clock, saw_timeout, saw_other)。

        result 为 None（整层耗尽）、("referral",) 或
        ("terminal", rcode, an, ns, name, clock)。顺序、前 2 事件、时钟与
        timeout 推进沿用 forward；首个可用转介/终态立即结束本层。
        末层转介（kind 0）按普通失败计并继续尝试后续事件/上游。

        counts 为本层深度的七整数行 [a, r, s, to, e, bad, ms]，按访问的
        每个事件原地累计：尝试即 a 加 1；delay>timeout 计 to 且 ms 加
        timeout；其余 ms 加 delay 后按 reply=None、末层 kind=0、非末层
        kind=0（接受转介）、kind=1/2/3（终态）分别计 e、bad、r、s，转介
        或终态后的事件不访问故不计。
        """
        saw_timeout = False
        saw_other = False
        for name, events in plan:
            for delay, parsed in events[:_PLAN_EVENTS_USED]:
                counts[0] += 1  # a：尝试
                if delay > self._timeout:
                    saw_timeout = True
                    clock += self._timeout
                    counts[3] += 1  # to：delay>timeout
                    counts[6] += self._timeout  # ms：超时仅加 timeout
                    continue
                clock += delay
                counts[6] += delay  # ms：其余事件加 delay
                if parsed is None:
                    saw_other = True
                    counts[4] += 1  # e：reply=None
                    continue
                kind, rcode, an, ns = parsed
                if kind == 0:  # 转介
                    if is_last:
                        saw_other = True
                        counts[5] += 1  # bad：末层 kind=0
                        continue
                    counts[1] += 1  # r：接受的非末层转介
                    return ("referral",), clock, saw_timeout, saw_other
                counts[2] += 1  # s：kind=1/2/3 终态
                return (("terminal", rcode, an, ns, name, clock),
                        clock, saw_timeout, saw_other)
        return None, clock, saw_timeout, saw_other

    def reload_zone(self, text: str) -> int:
        """导入配置文本并原子换区，返回从 0 递增的修订号。

        先 import_zone 再以新 zone 构造 PositiveCache，全部成功后才
        提交：替换权威缓存（清空缓存条目），保留时钟、plan、统计与递归
        缓存；统计不随换区提交，stats() 逐字节不变，c[0] 于下次解析
        提交时与新缓存同步。任何失败（TypeError、ConfigError、
        RecordError、ZoneError）都回滚：不改变任何状态，修订历史不变。
        """
        zone = import_zone(text)
        cache = PositiveCache(zone)
        # 全部成功后原子提交：换区、修订号加 1，并按新当前修订号归档。
        self._cache = cache
        revision = self._revision
        self._revision += 1
        self._archive_revision(self._revision, cache)
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
        时钟、plan 与统计），修订号加 1、按新修订号归档区域深拷贝并
        报告 applied（version 为新修订号，提交当下 stats() 逐字节不变）。
        unchanged 与 conflict 不写历史。修订号与 reload_zone 共用，初始
        为 0。报告为紧凑 ASCII JSON、十进制数字、末尾单换行，
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
        current_text = export_zone(self._zone_model(self._cache))
        if candidate_text == current_text:
            # 候选与当前区域规范化后等价：不换区、不加修订号、不归档。
            return self._tx_report(self._revision, "unchanged")
        self._cache = cache
        self._revision += 1
        self._archive_revision(self._revision, cache)
        return self._tx_report(self._revision, "applied")

    def reload_zone_serial_tx(self, text: str, expected: int,
                              force: bool = False) -> str:
        """带修订号检查与 SOA 序列号比较的原子换区事务，返回键序
        version,result,serial 的报告。

        text 非 str、expected 非 int（含 bool）或 force 非 bool 抛
        TypeError；expected<0 抛 ConfigError。验参后 expected 不等于
        当前修订号时不解析 text，报告 conflict（version 为当前修订号，
        serial 为 null），不改变任何状态。相等时先由 import_zone 解析并
        以候选 zone 构造 PositiveCache，失败沿用 ConfigError、
        RecordError、ZoneError 且状态不变。新旧两区 SOA 的 rdata 均须
        完整为两个未压缩绝对名与五个网络序 uint32 且无尾随，否则抛
        ZoneError。候选的 export_zone 文本等于当前区域时报告 unchanged
        （版本、缓存不变）；否则经 compare_serial 比较新旧序列号：
        force=False 时仅候选序列号比当前为 newer 才换区并报告 applied，
        equal、older 报告 stale，ambiguous 报告 ambiguous；force=True
        时无论比较结果一律换区并报告 applied。换区原子提交：清空权威
        缓存，保留递归缓存、时钟、plan 与统计，修订号加 1、按新修订号
        归档区域深拷贝（提交当下 stats() 逐字节不变）。version 取操作
        后修订号（非 applied 取当前修订号），serial 为候选 SOA 序列号
        （conflict 时为 null）。unchanged、stale、ambiguous、conflict
        与任何异常均不写历史、不改变任何状态。报告为紧凑 ASCII JSON
        （十进制整数、末尾单换行），result 为 "applied"、"unchanged"、
        "stale"、"ambiguous" 或 "conflict"。
        """
        if not isinstance(text, str):
            raise TypeError("text must be str")
        if not isinstance(expected, int) or isinstance(expected, bool):
            raise TypeError("expected must be int")
        if not isinstance(force, bool):
            raise TypeError("force must be bool")
        if expected < 0:
            raise ConfigError("expected revision must be non-negative")
        if expected != self._revision:
            # 修订号不匹配：不得解析 text，冲突本身不改变任何状态。
            return self._update_report(self._revision, "conflict", None)
        zone = import_zone(text)
        cache = PositiveCache(zone)
        # 新旧两区 SOA rdata 均须为两个未压缩绝对名加五个 uint32；
        # 先取序列号（兼格式校验），再判定同区与序列号新旧。
        candidate_serial = _zone_soa_serial(cache._records, cache._origin)
        if candidate_serial is None:
            raise ZoneError("soa rdata must be two names and five uint32")
        current_serial = _zone_soa_serial(
            self._cache._records, self._cache._origin)
        if current_serial is None:
            raise ZoneError("soa rdata must be two names and five uint32")
        candidate_text = export_zone(zone)
        current_text = export_zone(self._zone_model(self._cache))
        if candidate_text == current_text:
            # 候选与当前区域规范化后等价：不换区、不加修订号、不归档。
            return self._update_report(
                self._revision, "unchanged", candidate_serial)
        if not force:
            # 仅 newer 才提交；equal/older 为 stale，ambiguous 单列。
            relation = compare_serial(candidate_serial, current_serial)
            if relation == "ambiguous":
                return self._update_report(
                    self._revision, "ambiguous", candidate_serial)
            if relation != "newer":
                return self._update_report(
                    self._revision, "stale", candidate_serial)
        # force=True 或序列号更新：全部校验成功后原子提交。
        self._cache = cache
        self._revision += 1
        self._archive_revision(self._revision, cache)
        return self._update_report(
            self._revision, "applied", candidate_serial)

    @staticmethod
    def _zone_model(cache):
        """从权威缓存导出规范化 zone 模型（origin,records）。"""
        return {"origin": _labels_to_name(cache._origin, wildcard=False),
                "records": [_rr_to_model(rr) for rr in cache._records]}

    def _archive_revision(self, revision, cache):
        """按修订号保存当前规范化区域深拷贝；超容量 32 淘汰最小修订号。

        归档仅在换区成功提交时进行，修订号单调递增、不复用。
        """
        self._zone_history[revision] = copy.deepcopy(self._zone_model(cache))
        if len(self._zone_history) > _ZONE_HISTORY_CAPACITY:
            oldest = min(self._zone_history)
            del self._zone_history[oldest]

    def rollback_zone_tx(self, target: int, expected: int) -> str:
        """带修订号检查的原子回滚事务，返回键序 version,result,target。

        target 或 expected 非 int（含 bool）抛 TypeError；任一为负抛
        ConfigError。两参数校验完成后先比较 expected：不等于当前修订号
        时不得查询 target，报告 conflict（version 为当前修订号）；
        相等且 target 为当前修订号报告 unchanged；target 未保留（含已
        淘汰）报告 missing。命中保留时先以目标快照构造 PositiveCache，
        成功后才原子提交：换区、清空权威缓存，修订号加 1 并把恢复
        区域按新修订号归档，报告 applied（version 为新修订号）。递归
        缓存、时钟、plan 与统计均保留，提交当下 stats() 逐字节不变。
        非 applied 结果或任何异常都不改变任何状态。报告为紧凑 ASCII
        JSON（十进制整数、末尾单换行），result 为 "applied"、
        "unchanged"、"missing" 或 "conflict"。
        """
        if not isinstance(target, int) or isinstance(target, bool):
            raise TypeError("target must be int")
        if not isinstance(expected, int) or isinstance(expected, bool):
            raise TypeError("expected must be int")
        if target < 0:
            raise ConfigError("target revision must be non-negative")
        if expected < 0:
            raise ConfigError("expected revision must be non-negative")
        # 两参数校验完成后才比较 expected；冲突时不得查询 target。
        if expected != self._revision:
            return self._rollback_report(self._revision, "conflict", target)
        if target == self._revision:
            return self._rollback_report(self._revision, "unchanged", target)
        snapshot = self._zone_history.get(target)
        if snapshot is None:
            return self._rollback_report(self._revision, "missing", target)
        # 先用快照构造候选缓存，成功后才提交，保证失败不改任何状态。
        cache = PositiveCache(snapshot)
        self._cache = cache
        self._revision += 1
        self._archive_revision(self._revision, cache)
        return self._rollback_report(self._revision, "applied", target)

    def update_zone_tx(self, changes: list, serial: int,
                       expected: int) -> str:
        """带修订号与 SOA 序列号检查的原子区域更新事务。

        changes 为 1..256 项，项键序 op,record，op 为 "add"/"delete"，
        record 同 zone.records 契约（名称允许通配，CNAME rdata 按 zone
        规则规范化）且 type 为 6（SOA）抛 ZoneError；serial 为 uint32，
        expected 非负。类型错（含 bool 整数）抛 TypeError；数量、项键、
        op 值或整数范围错抛 ConfigError。验参后先比 expected：不等于
        当前修订号时不验项，报告 conflict（version 为当前修订号）且
        不改变任何状态。相等时再验项；当前区域 SOA 的 rdata 须完整为
        两个未压缩绝对名与五个网络序 uint32 且无尾随，否则 ZoneError。
        serial 与当前 SOA 序列号经 compare_serial 比较为 newer 才更新，
        equal、older、ambiguous 均报告 stale。隔离执行：在记录副本上按序应用，add 无同五字段
        （名称、类型、类、TTL、rdata）RR 才尾加，delete 删尽同 RR；
        记录列表不变报告 unchanged（版本、缓存不变），否则把 SOA 序列号
        改为 serial，以候选区域构造 PositiveCache 完整验证，成功后才
        原子提交：换区、清空权威缓存、修订号加 1 并按新修订号归档，
        报告 applied（version 为新修订号）；递归缓存、时钟、plan 与
        统计均保留，提交当下 stats() 逐字节不变。serial 按入参原样
        报告；非 applied 结果或任何异常均不改变任何状态。报告为紧凑
        ASCII JSON（十进制整数、末尾单换行），result 为 "applied"、
        "unchanged"、"stale" 或 "conflict"。
        """
        if not isinstance(changes, list):
            raise TypeError("changes must be list")
        if not 1 <= len(changes) <= _MAX_UPDATE_CHANGES:
            raise ConfigError("changes must contain 1..256 items")
        if not isinstance(serial, int) or isinstance(serial, bool):
            raise TypeError("serial must be int")
        if not isinstance(expected, int) or isinstance(expected, bool):
            raise TypeError("expected must be int")
        if not 0 <= serial <= _MAX_TTL:
            raise ConfigError("serial out of range")
        if expected < 0:
            raise ConfigError("expected revision must be non-negative")
        # 验参完成后才比较 expected；冲突不验项，且不改变任何状态。
        if expected != self._revision:
            return self._update_report(self._revision, "conflict", serial)
        # 再验项：键序 op,record，op 为 add/delete，record 同
        # zone.records 契约且不得为 SOA；CNAME rdata 按 zone 规则规范化。
        parsed = []
        for change in changes:
            if not isinstance(change, dict):
                raise TypeError("change must be dict")
            if list(change.keys()) != _UPDATE_CHANGE_KEYS:
                raise ConfigError("change keys must be op,record")
            op = change["op"]
            if not isinstance(op, str):
                raise TypeError("op must be str")
            if op not in _UPDATE_OPS:
                raise ConfigError("op must be add or delete")
            labels, rrtype, rrclass, ttl, rdata = _validate_rr(
                change["record"], allow_wildcard=True)
            if rrtype == _TYPE_SOA:
                raise ZoneError("change record must not be SOA")
            if rrtype in _NAME_BEARING_TYPES:
                rdata = _canonical_rdata(rrtype, rdata)
            parsed.append((op, (labels, rrtype, rrclass, ttl, rdata)))
        # 当前区域 SOA 的 rdata 须完整为两个未压缩绝对名与五个 uint32。
        origin = self._cache._origin
        records = self._cache._records
        soa = [rr for rr in records
               if rr[0] == origin and rr[1] == _TYPE_SOA][0]
        soa_offset = _parse_soa_uint32_offset(soa[4])
        if soa_offset is None:
            raise ZoneError("soa rdata must be two names and five uint32")
        current_serial = int.from_bytes(
            soa[4][soa_offset:soa_offset + 4], "big")
        # 按 compare_serial 比较 serial 与当前序列号，仅 newer 才更新，
        # equal、older、ambiguous 均报告 stale。
        if compare_serial(serial, current_serial) != "newer":
            return self._update_report(self._revision, "stale", serial)
        # 隔离执行：在副本上按序应用，add 无同五字段 RR 才尾加，
        # delete 删尽同 RR；任何失败都在提交前发生，真实状态不变。
        updated = list(records)
        for op, rr in parsed:
            if op == "add":
                if rr not in updated:
                    updated.append(rr)
            else:
                updated = [existing for existing in updated if existing != rr]
        if updated == list(records):
            # 记录列表不变：不换区、不加修订号、不归档。
            return self._update_report(self._revision, "unchanged", serial)
        # 改 SOA 序列号（五个 uint32 之首），其余字段原样保留。
        new_soa_rdata = (soa[4][:soa_offset] + serial.to_bytes(4, "big")
                         + soa[4][soa_offset + 4:])
        bumped = [(rr[0], rr[1], rr[2], rr[3], new_soa_rdata)
                  if rr[0] == origin and rr[1] == _TYPE_SOA else rr
                  for rr in updated]
        candidate = {"origin": _labels_to_name(origin, wildcard=False),
                     "records": [_rr_to_model(rr) for rr in bumped]}
        # 经 PositiveCache 完整验证，成功后才原子提交，失败无副作用。
        cache = PositiveCache(candidate)
        self._cache = cache
        self._revision += 1
        self._archive_revision(self._revision, cache)
        return self._update_report(self._revision, "applied", serial)

    def transfer_zone(self, from_serial: int,
                      limit: int = 65535) -> str:
        """只读区域传送，返回键序 version,serial,mode,delete,add 的紧凑
        ASCII JSON（末尾单换行）。

        from_serial 为 uint32、limit 为 1..65535 的非 bool int；非 int
        或 bool 抛 TypeError，越界抛 ConfigError。from_serial 与当前
        SOA 序列号经 compare_serial 比较：equal 或 newer 时 mode 为
        "none"，delete/add 均空；ambiguous 抛 TransferError。older 时
        取修订历史中 SOA 序列号等于 from_serial 的最大修订（须仍保留）：按 RR 五字段
        （name,type,class,ttl,rdata）及重复次数求差，delete 依旧区原序、
        add 依当前区原序，差异总数不超 limit 用 mode "ixfr"。无匹配修订
        或差异超 limit 时改用 mode "axfr"：delete 为空、add 为当前全部
        RR 原序；仍超 limit 抛 TransferError。version 取当前修订号，
        serial 取当前 SOA 序列号。所读历史或当前 SOA rdata 不符两个未
        压缩绝对名加五个 uint32 格式抛 ZoneError。只读：不改变任何状态，
        同状态同参逐字节一致。
        """
        if not isinstance(from_serial, int) or isinstance(from_serial, bool):
            raise TypeError("from_serial must be int")
        if not isinstance(limit, int) or isinstance(limit, bool):
            raise TypeError("limit must be int")
        if not 0 <= from_serial <= _MAX_TTL:
            raise ConfigError("from_serial out of range")
        if not _MIN_TRANSFER_LIMIT <= limit <= _MAX_TRANSFER_LIMIT:
            raise ConfigError("limit out of range")
        # 当前区域序列号：SOA rdata 不符格式抛 ZoneError。
        cur_origin = self._cache._origin
        cur_records = self._cache._records
        current_serial = _zone_soa_serial(cur_records, cur_origin)
        if current_serial is None:
            raise ZoneError("soa rdata must be two names and five uint32")
        relation = compare_serial(from_serial, current_serial)
        if relation == "ambiguous":
            raise TransferError("serial comparison ambiguous")
        if relation != "older":
            # equal 或 newer：无更旧差异可传，mode 为 none，两列表为空。
            mode = "none"
            delete = []
            add = []
        else:
            # 取历史中 SOA 序列号等于 from_serial 的最大修订（须仍保留）。
            match_records = None
            for revision in sorted(self._zone_history, reverse=True):
                snapshot = self._zone_history[revision]
                hist_origin, hist_records = _snapshot_records(snapshot)
                hist_serial = _zone_soa_serial(hist_records, hist_origin)
                if hist_serial is None:
                    raise ZoneError(
                        "soa rdata must be two names and five uint32")
                if hist_serial == from_serial:
                    match_records = hist_records
                    break
            if match_records is None:
                # 无匹配修订：降级 AXFR。
                delete = []
                add = list(cur_records)
                if len(add) > limit:
                    raise TransferError("zone transfer exceeds limit")
                mode = "axfr"
            else:
                # 按五字段及重复次数求差：先统计两侧各 RR 出现次数。
                old_counts = {}
                for rr in match_records:
                    key = _rr_diff_key(rr)
                    old_counts[key] = old_counts.get(key, 0) + 1
                new_counts = {}
                for rr in cur_records:
                    key = _rr_diff_key(rr)
                    new_counts[key] = new_counts.get(key, 0) + 1
                # delete 依旧区原序输出超出当前区的重复份数。
                delete_left = {
                    key: max(0, old_counts[key] - new_counts.get(key, 0))
                    for key in old_counts}
                delete = []
                for rr in match_records:
                    key = _rr_diff_key(rr)
                    if delete_left.get(key, 0) > 0:
                        delete.append(rr)
                        delete_left[key] -= 1
                # add 依当前区原序输出超出旧区的重复份数。
                add_left = {
                    key: max(0, new_counts[key] - old_counts.get(key, 0))
                    for key in new_counts}
                add = []
                for rr in cur_records:
                    key = _rr_diff_key(rr)
                    if add_left.get(key, 0) > 0:
                        add.append(rr)
                        add_left[key] -= 1
                if len(delete) + len(add) <= limit:
                    mode = "ixfr"
                else:
                    # 差异超限：降级 AXFR；仍超 limit 抛 TransferError。
                    delete = []
                    add = list(cur_records)
                    if len(add) > limit:
                        raise TransferError("zone transfer exceeds limit")
                    mode = "axfr"
        payload = {
            "version": self._revision,
            "serial": current_serial,
            "mode": mode,
            "delete": [_transfer_rr_model(rr) for rr in delete],
            "add": [_transfer_rr_model(rr) for rr in add],
        }
        return json.dumps(payload, ensure_ascii=True,
                          separators=(",", ":")) + "\n"

    def dump_zones(self) -> str:
        """把区域修订历史导出为确定性配置文本（schema=1），只读。

        顶层键序仅 schema,version,history：schema 恒为 1，version 为
        当前修订号；history 按 revision 严格升序，项键序仅
        revision,zone，zone 为 migrate_zone 的 v2 配置对象（键序
        version,origin,class,records，记录键序 name,type,ttl,rdata，
        记录保持原序）。输出为紧凑 ASCII JSON，整数十进制、rdata 为
        偶长小写十六进制，末尾单换行；不改变任何状态，同状态逐字节
        相同，load_zones(dump_zones()) 得到区域、修订号与历史等价的
        实例。
        """
        history = []
        for revision in sorted(self._zone_history):
            history.append({
                "revision": revision,
                "zone": _zone_model_to_v2(self._zone_history[revision]),
            })
        config = {"schema": 1, "version": self._revision,
                  "history": history}
        return json.dumps(config, ensure_ascii=True,
                          separators=(",", ":")) + "\n"

    @classmethod
    def load_zones(cls, text: str, plan: list,
                   timeout: int = 5) -> "Resolver":
        """从 dump_zones 配置文本恢复解析器实例（schema 0/1）。

        先校验全部快照（任何失败都不产生实例），末项区域为当前区，
        恢复修订历史与修订号（之后成功变更从 version+1 继续）；新
        实例缓存为空、时钟未设、统计清零。text 非 str 抛 TypeError；
        JSON 解析、重复键、键序、schema、版本关系或历史数量错误抛
        ConfigError；zone 结构错误抛 ConfigError，语义错误沿用
        RecordError、ZoneError；plan、timeout 的校验与异常沿用
        Resolver 构造。

        配置为 JSON 对象，顶层键序仅 schema,version,history：schema
        为非 bool 整数 0 或 1，version 为非负非 bool 整数；history
        项键序仅 revision,zone，revision 为严格递增的非负非 bool
        整数且末项等于顶层 version；zone 为 migrate_zone 的 v2 配置
        对象（schema=0 旧格式接受 v0/v1/v2，按 migrate_zone 契约
        迁移）。schema=1 的 history 限 1..32 项；schema=0 限
        1..256 项，全部快照校验通过后仅保留 revision 最大的 32 项
        恢复历史（末项必在其中）。
        """
        schema, version, history = _parse_zones_config(text)
        # 先校验全部快照：schema=1 的 zone 必须为 v2，旧格式接受
        # v0/v1/v2；结构错误抛 ConfigError，语义错误沿用
        # RecordError、ZoneError；全部通过后才截断与构造实例。
        snapshot_loader = (_load_zone_snapshot if schema == 1
                           else _load_zone_snapshot_any)
        snapshots = [(item["revision"], snapshot_loader(item["zone"]))
                     for item in history]
        kept = snapshots[-_ZONE_HISTORY_CAPACITY:]
        # 构造沿用 Resolver：timeout、plan 与末项区域按构造规则校验，
        # 新实例缓存为空、时钟未设、统计清零。
        instance = cls(kept[-1][1], plan, timeout)
        instance._revision = version
        instance._zone_history = {
            revision: copy.deepcopy(zone) for revision, zone in kept}
        return instance

    def save_zones(self, path: str) -> int:
        """把 dump_zones() 字节原子落盘，返回写入字节数。

        先取只读的 dump_zones() 文本编码为 ASCII 字节，在目标同目录
        创建临时文件，写入并 flush、fsync 后 os.replace 原子替换目标。
        任何失败都删除临时文件、保留目标旧文件，解析器不发生任何改变
        （dump_zones 只读，失败异常原样传播）。path 非 str 抛 TypeError。
        """
        if not isinstance(path, str):
            raise TypeError("path must be str")
        data = self.dump_zones().encode("ascii")
        # 临时文件必须与目标同目录，os.replace 才能在同一文件系统内
        # 原子改名；path 无目录成分时（""）以当前目录为同目录。
        directory = os.path.dirname(path) or os.curdir
        fd, tmp_path = tempfile.mkstemp(prefix=".dns-zones-",
                                        suffix=".tmp", dir=directory)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp_path, path)
        except BaseException:
            # 失败：临时文件绝不残留；目标未被 replace 触碰，旧文件保留。
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
        return len(data)

    def reload_zones_file(self, path: str, expected: int) -> str:
        """从区域文件校验整份快照并原子换区，返回 version,result 报告。

        path 非 str 或 expected 非 int（含 bool）抛 TypeError；path 为
        空串或含 NUL、expected 为负抛 ConfigError。验参后 expected 不
        等于当前修订号时不读文件，报告 conflict（version 为当前修订号），
        不改变任何状态。相符时读取文件：缺失抛 FileNotFoundError，其余
        I/O 错抛 OSError；内容上限 16777216 字节，超限或含非 ASCII 字节
        抛 ConfigError。随后以当前 plan、timeout 按 load_zones
        （schema 0/1，旧格式历史仅留 revision 最大的 32 项）校验整份
        快照并构造候选解析器，异常原样不变且解析器不变。候选规范化导出
        与当前 dump_zones() 相同报告 unchanged（版本与状态不变）；不同
        时文件 version 必须大于当前修订号，否则抛 ConfigError。成功后
        原子替换权威缓存（候选缓存为空）、修订历史与修订号，保留递归
        缓存、时钟、plan 与统计（stats() 提交当下逐字节不变）。报告键
        序仅 version,result（version 为操作后修订号，result 为
        "applied"、"unchanged" 或 "conflict"），紧凑 ASCII JSON、十
        进制整数、末尾单换行。
        """
        if not isinstance(path, str):
            raise TypeError("path must be str")
        if not isinstance(expected, int) or isinstance(expected, bool):
            raise TypeError("expected must be int")
        if path == "" or "\x00" in path:
            raise ConfigError("path must be non-empty and without NUL")
        if expected < 0:
            raise ConfigError("expected revision must be non-negative")
        # 冲突不读文件：任何文件访问都必须在修订号检查之后。
        if expected != self._revision:
            return self._tx_report(self._revision, "conflict")
        # 缺失与 I/O 错原样传播（FileNotFoundError/OSError）；仅多读
        # 一字节即可判定超限，避免把超限文件整体读入内存。
        with open(path, "rb") as stream:
            data = stream.read(_MAX_ZONES_FILE_BYTES + 1)
        if len(data) > _MAX_ZONES_FILE_BYTES:
            raise ConfigError("zones file exceeds 16777216 bytes")
        if not data.isascii():
            raise ConfigError("zones file must be ASCII")
        text = data.decode("ascii")
        # 按 load_zones 校验全快照并构造候选实例；其缓存为空、时钟未设、
        # 统计清零，仅取其权威缓存、修订号与历史。
        candidate = Resolver.load_zones(text, self._plan, self._timeout)
        if candidate.dump_zones() == self.dump_zones():
            # 规范化后内容一致：不换区、不改版本与任何状态。
            return self._tx_report(self._revision, "unchanged")
        # 内容不同只允许向前恢复到更大的修订号；同号或更旧一律拒绝。
        if candidate._revision <= self._revision:
            raise ConfigError("file version must be greater than current")
        # 全部校验成功后原子提交：区域、历史与修订号一并替换，权威缓存
        # 随候选为空；递归缓存、时钟、plan 与统计全部保留。
        self._cache = candidate._cache
        self._revision = candidate._revision
        self._zone_history = candidate._zone_history
        return self._tx_report(self._revision, "applied")

    def _rollback_batch(self, expected, steps):
        """在隔离状态依序执行 reload/rollback 暂存步，整体原子提交。

        expected 不等于当前修订号即为冲突：不解析任何 text，返回
        ("conflict", 当前修订号, -1) 且不改变任何状态。相符时在解析器
        深拷贝上逐暂存修订号执行各步：reload 沿用 reload_zone 语义（等价
        文本同样新增修订），rollback 可指向本批刚产生的修订；rollback
        目标未保留返回 ("missing", 原修订号, 零基下标)。任一步抛异常则
        放弃整批，临时副本随异常丢弃，真实解析器的区域、修订号、历史、
        权威与递归缓存、时钟及统计全部保持原样；异常原样传播。全部成功
        后才原子提交暂存缓存、修订号与历史（其余状态不变）：含 applied
        步返回 ("applied", 新修订号, len(steps))，全 unchanged 返回
        ("unchanged", 原修订号, len(steps))。
        """
        if expected != self._revision:
            # 冲突：不解析 text，冲突本身不改变任何状态。
            return "conflict", self._revision, -1
        # 隔离状态：全部步骤在深拷贝上执行，任何失败放弃整批，真实
        # 解析器（区域、版本、历史、缓存、时钟、统计）均不受影响。
        batch = copy.deepcopy(self)
        applied = False
        for index, step in enumerate(steps):
            if step[0] == "reload":
                batch.reload_zone(step[1])
                applied = True
            else:
                report = json.loads(
                    batch.rollback_zone_tx(step[1], batch._revision))
                result = report["result"]
                if result == "missing":
                    return "missing", self._revision, index
                if result == "applied":
                    applied = True
                # expected 恒为暂存当前号，故无 conflict；target 为当前
                # 号时 unchanged，二者均继续下一步。
        if not applied:
            return "unchanged", self._revision, len(steps)
        # 全部步骤成功后原子提交：仅替换权威缓存、修订号与历史，保留
        # 递归缓存、时钟、plan 与统计（提交当下 stats() 逐字节不变）。
        self._cache = batch._cache
        self._revision = batch._revision
        self._zone_history = batch._zone_history
        return "applied", self._revision, len(steps)

    @staticmethod
    def _tx_report(version, result):
        """构造键序 version,result 的紧凑 ASCII JSON 报告（末尾单换行）。"""
        return json.dumps({"version": version, "result": result},
                          ensure_ascii=True, separators=(",", ":")) + "\n"

    @staticmethod
    def _rollback_report(version, result, target):
        """构造键序 version,result,target 的紧凑 ASCII JSON（末尾换行）。"""
        return json.dumps(
            {"version": version, "result": result, "target": target},
            ensure_ascii=True, separators=(",", ":")) + "\n"

    @staticmethod
    def _update_report(version, result, serial):
        """构造键序 version,result,serial 的紧凑 ASCII JSON（末尾换行）。"""
        return json.dumps(
            {"version": version, "result": result, "serial": serial},
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
        return _state_stats_text(h, m, x, u, c, elapsed_buckets) + "\n"

    def upstream_stats(self, reset: bool = False) -> str:
        """返回构造 plan 直转的逐上游统计（顶层键序仅 p,t，末尾单换行）。

        输出为紧凑 ASCII JSON。p 按 plan 位置列对象（重名不合并），键序
        仅 i,n,a,s,to,e,bad,ms：i 为从 0 起的位置序号，n 为原上游名，
        其余为非负整数——a 尝试次数、s 成功、to 超时、e 无应答、bad
        应答未通过匹配、ms 模拟耗时累计；每个上游仅取前 2 个事件，尝试
        即 a 加 1，delay>timeout 时 to 加 1、ms 加 timeout，否则 ms 加
        delay 后按 reply 为 None/未通过匹配/通过分别计 e/bad/s（通过即
        停），无事件的上游不计。t 省略 i、n，余键同序并为逐项和。
        仅经 resolve 或 resolve_edns 进入该 plan 的直转计数（权威、
        缓存与 resolve_recursive 的 levels 不计），直转成功或耗尽抛
        UpstreamTimeout/UpstreamError 时原子提交，其他异常不提交；
        resolve_edns 候选须额外通过恰一合法末项 OPT 与有效长度上限
        校验，否则记 bad。
        reset 非 bool 抛 TypeError 且无变化；False 只读，重复调用逐
        字节相同；True 先返回旧快照再清零上述计数，plan、缓存、时钟
        及其他统计不变。同初态同调用序列逐字节一致。
        """
        if not isinstance(reset, bool):
            raise TypeError("reset must be bool")
        per = []
        totals = [0, 0, 0, 0, 0, 0]
        for index, (name, _events) in enumerate(self._plan):
            acc = self._upstream_stats[index]
            for kind in range(6):
                totals[kind] += acc[kind]
            per.append({"i": index, "n": name, "a": acc[0], "s": acc[1],
                        "to": acc[2], "e": acc[3], "bad": acc[4],
                        "ms": acc[5]})
        payload = {"p": per,
                   "t": {"a": totals[0], "s": totals[1], "to": totals[2],
                         "e": totals[3], "bad": totals[4], "ms": totals[5]}}
        text = json.dumps(payload, ensure_ascii=True,
                          separators=(",", ":")) + "\n"
        if reset:
            # 先返回旧快照再清零；plan、缓存、时钟与其他统计均保留。
            self._upstream_stats = [[0, 0, 0, 0, 0, 0] for _ in self._plan]
        return text

    def recursive_upstream_stats(self, reset: bool = False) -> str:
        """返回 resolve_recursive 逐层转发的按深度统计（键序仅 l,t，末尾换行）。

        输出为紧凑 ASCII JSON。l 固定含 16 个数组，索引对应递归深度
        0..15；每项为七个非负整数 [a, r, s, to, e, bad, ms]，依次为
        尝试数、接受的非末层转介数、kind=1/2/3 终态数、delay>timeout
        数、reply=None 数、末层 kind=0 数、模拟耗时累计。超时仅给 ms
        加 timeout，其余事件加 delay；每个上游仍只取前 2 个事件，转介或
        终态后的事件不计。t 为同顺序七整数数组，逐项等于 l 各行之和。

        仅域外递归缓存未命中且 levels 全量校验通过后暂存本次访问事件，
        成功返回或耗尽抛 UpstreamTimeout/UpstreamError 时原子提交；查询、
        levels、编码、缓存写入或其他异常以及权威、缓存命中均不提交。
        reset 非 bool 抛 TypeError 且无变化；False 只读、重复调用逐字节
        相同；True 先返回旧快照再清零本统计，缓存、时钟、区域、plan 及
        其他统计不变。同初态同调用序列逐字节一致。
        """
        if not isinstance(reset, bool):
            raise TypeError("reset must be bool")
        rows = [list(row) for row in self._recursive_up]
        totals = [0, 0, 0, 0, 0, 0, 0]
        for row in rows:
            for kind in range(7):
                totals[kind] += row[kind]
        text = json.dumps({"l": rows, "t": totals}, ensure_ascii=True,
                          separators=(",", ":")) + "\n"
        if reset:
            # 先返回旧快照再清零本统计；其余状态全部保留。
            self._recursive_up = [
                [0, 0, 0, 0, 0, 0, 0] for _ in range(_MAX_RECURSION_LEVELS)]
        return text

    def _forward_config(self):
        """当前生效上游配置的 migrate_forward v1 对象。

        键序 v,timeout,attempts,plan；plan 保持原序，项键序
        name,events，每上游仅取前 attempts 个事件，事件键序
        delay,reply，reply 为 null 或偶长小写十六进制。
        """
        return {
            "v": 1, "timeout": self._timeout, "attempts": self._attempts,
            "plan": [
                {"name": name,
                 "events": [
                     {"delay": delay,
                      "reply": reply.hex() if reply is not None else None}
                     for delay, reply in events[:self._attempts]]}
                for name, events in self._plan],
        }

    def dump_forward(self) -> str:
        """导出当前上游转发配置（只读）。

        返回键序仅 version,config 的紧凑 ASCII JSON（末尾单换行）：
        version 为从 0 起的热加载版本号（reload_forward 报告 applied
        后加 1），config 为 migrate_forward 的 v1 对象（初始
        attempts=2）。只读：不改变任何状态，同状态逐字节相同。
        """
        return json.dumps(
            {"version": self._forward_version,
             "config": self._forward_config()},
            ensure_ascii=True, separators=(",", ":")) + "\n"

    def reload_forward(self, text: str, expected: int) -> str:
        """带版本检查的原子上游配置热加载，返回键序 version,result 的报告。

        expected 非 int（含 bool）抛 TypeError，负值抛 ConfigError；
        expected 不等于当前版本号时不解析 text，报告 conflict（version
        为当前版本号）且状态不变。相符时 text 非 str 抛 TypeError，
        否则复用 migrate_forward 完整校验并规范化（输入限 1048576
        码点，解析与结构错误抛 ConfigError）。候选与当前生效配置相同
        报告 unchanged（版本号与状态不变）；否则原子替换 timeout、
        attempts 与 plan，版本号加 1 并报告 applied。applied 后域外
        resolve 依新 plan 原序、每上游取前 attempts 个事件并用新
        timeout；upstream_stats 按新 plan 清零，缓存、时钟与其他统计
        保留，除此之外无副作用。报告为紧凑 ASCII JSON（末尾单换行），
        result 仅 "applied"、"unchanged" 或 "conflict"；unchanged、
        conflict 与任何异常均不改变任何状态。
        """
        if not isinstance(expected, int) or isinstance(expected, bool):
            raise TypeError("expected must be int")
        if expected < 0:
            raise ConfigError("expected version must be non-negative")
        if expected != self._forward_version:
            # 版本号不匹配：不得解析 text，冲突本身不改变任何状态。
            return self._tx_report(self._forward_version, "conflict")
        if not isinstance(text, str):
            raise TypeError("text must be str")
        migrated = migrate_forward(text)
        current = json.dumps(self._forward_config(), ensure_ascii=True,
                             separators=(",", ":")) + "\n"
        if migrated == current:
            # 候选与当前生效配置等价：不替换、不加版本号；版本匹配且
            # 校验全过，按提交序记一笔 unchanged 审计。
            self._append_forward_audit(
                "l", migrated, self._forward_version,
                "unchanged", self._forward_version)
            return self._tx_report(self._forward_version, "unchanged")
        # migrate_forward 已完整校验，其输出可安全解析并直转内部 plan。
        config = json.loads(migrated)
        plan = [
            (item["name"],
             [(event["delay"],
               None if event["reply"] is None
               else bytes.fromhex(event["reply"]))
              for event in item["events"]])
            for item in config["plan"]]
        # 全部成功后原子提交：替换 timeout、attempts 与 plan，版本号
        # 加 1 并按新版本号归档快照，upstream_stats 按新 plan 清零；
        # 缓存、时钟与其他统计保留。
        before = self._forward_version
        self._timeout = config["timeout"]
        self._attempts = config["attempts"]
        self._plan = plan
        self._upstream_stats = [[0, 0, 0, 0, 0, 0] for _ in plan]
        self._forward_version += 1
        self._archive_forward(self._forward_version)
        # 审计与配置同一原子步骤入账（x 为规范化 v1 文本）。
        self._append_forward_audit("l", migrated, before,
                                   "applied", self._forward_version)
        return self._tx_report(self._forward_version, "applied")

    def _forward_snapshot(self):
        """当前生效上游配置的规范化快照：(timeout, attempts, 截断 plan)。

        plan 保持原序，每上游仅取前 attempts 个事件（与 _forward_config
        同一规范化）；名称、事件元组与 reply 字节均不可变，列表不原地改。
        """
        return (self._timeout, self._attempts,
                [(name, list(events[:self._attempts]))
                 for name, events in self._plan])

    def _archive_forward(self, version):
        """把当前生效配置按 version 归档；容量 32，超量淘汰最小版本号。"""
        self._forward_history[version] = self._forward_snapshot()
        if len(self._forward_history) > _FORWARD_HISTORY_CAPACITY:
            oldest = min(self._forward_history)
            del self._forward_history[oldest]

    def forward_versions(self) -> tuple[int, ...]:
        """只读返回保留的上游配置版本号，为严格升序元组。

        初始配置为版本 0；reload_forward 与 rollback_forward 报告
        applied 时按新版本号归档，历史容量 32、超量淘汰最小版本号，
        版本号单调递增不复用。只读：不改变任何状态，同状态结果相同。
        """
        return tuple(sorted(self._forward_history))

    def _append_forward_audit(self, kind, value, before, result, after):
        """把一笔已提交的上游配置变更按提交序入 forward_audit 队列。

        渲染为键序仅 k,x,e,r,a 的紧凑 ASCII JSON 项文本后入队，并按
        FIFO 淘汰最早项直至项数不超过 4096 且完整 forward_audit 输出
        不超过 16777216 字节（新项自身远小于上限，循环必终止）。调用
        仅限已原子提交成功的变更（applied/unchanged），与状态变更在
        同一原子步骤执行；副本推演时本队列随之隔离演化。
        """
        item = json.dumps(
            {"k": kind, "x": value, "e": before, "r": result, "a": after},
            ensure_ascii=True, separators=(",", ":"))
        self._forward_audit.append(item)
        self._forward_audit_bytes += len(item) + 1
        while (len(self._forward_audit) > _MAX_FORWARD_AUDIT_OPS
               or (self._forward_audit
                   and self._forward_audit_bytes
                   + _FORWARD_AUDIT_FIXED_BYTES
                   > _MAX_FORWARD_AUDIT_BYTES)):
            oldest = self._forward_audit.popleft()
            self._forward_audit_bytes -= len(oldest) + 1

    def forward_audit(self) -> str:
        """只读导出自构造以来已提交上游配置变更的提交序审计文本。

        输出为紧凑 ASCII JSON、末尾单换行，顶层键序仅 "v","o"：
        v 恒为 1；o 按提交序列出至多 4096 个审计项，项键序仅
        "k","x","e","r","a"——k 取 "l"（reload_forward）或 "r"
        （rollback_forward）；k="l" 时 x 为 migrate_forward 规范化
        后的配置文本，k="r" 时 x 为非负目标版本；e、a 为该步执行
        前、后的版本号；r 取 "applied" 或 "unchanged"。仅
        expected 匹配且未抛异常的 reload_forward、rollback_forward
        以及成功 replay_forward 内的各步入账；conflict、任何异常与
        整批失败的 replay_forward 均不入账。完整输出超过 16777216
        字节（或项数超过 4096）时在入账时淘汰最早项；本方法只读，
        不改变任何状态，同状态重复调用逐字节一致。空队列输出
        {"v":1,"o":[]} 加换行。审计文本可直接作为 replay_forward 的
        log 重放：其 r、a 与各步实际结果一致，故核对通过。
        """
        if not self._forward_audit:
            return '{"v":1,"o":[]}\n'
        return ('{"v":1,"o":['
                + ",".join(self._forward_audit) + "]}\n")

    def rollback_forward(self, target: int, expected: int) -> str:
        """带版本检查的原子上游配置回滚，返回键序 version,result,target。

        target 或 expected 非 int（含 bool）抛 TypeError；任一为负抛
        ConfigError。两参数校验完成后先比较 expected：不等于当前版本号
        时不得查询 target，报告 conflict（version 为当前版本号）且状态
        不变。相等且 target 未保留（含已淘汰）抛 ConfigError；目标为
        当前版本或快照与当前生效配置等价报告 unchanged（版本号与状态
        不变）。否则原子恢复该快照的 timeout、attempts 与 plan，版本号
        加 1 并把恢复配置按新版本号归档，报告 applied（version 为新
        版本号）。applied 后域外 resolve 依恢复 plan 原序、每上游取前
        attempts 个事件并用恢复的 timeout；upstream_stats 按恢复 plan
        清零，缓存、时钟、区域、递归状态与其他统计均保留。报告为紧凑
        ASCII JSON（十进制整数、末尾单换行），result 为 "applied"、
        "unchanged" 或 "conflict"；unchanged、conflict 与任何异常均不
        改变任何状态。
        """
        if not isinstance(target, int) or isinstance(target, bool):
            raise TypeError("target must be int")
        if not isinstance(expected, int) or isinstance(expected, bool):
            raise TypeError("expected must be int")
        if target < 0:
            raise ConfigError("target version must be non-negative")
        if expected < 0:
            raise ConfigError("expected version must be non-negative")
        # 两参数校验完成后才比较 expected；冲突时不得查询 target。
        if expected != self._forward_version:
            return self._rollback_report(self._forward_version, "conflict",
                                         target)
        snapshot = self._forward_history.get(target)
        if snapshot is None:
            raise ConfigError("target version not retained")
        if snapshot == self._forward_snapshot():
            # 目标为当前版本或与当前生效配置等价：不替换、不加版本号；
            # 版本匹配且校验全过，按提交序记一笔 unchanged 审计。
            self._append_forward_audit(
                "r", target, self._forward_version,
                "unchanged", self._forward_version)
            return self._rollback_report(self._forward_version, "unchanged",
                                         target)
        # 全部校验通过后原子提交：恢复 timeout、attempts 与 plan（重建
        # 列表以与快照隔离），upstream_stats 按恢复 plan 清零，版本号
        # 加 1 并按新版本号归档；缓存、时钟、区域、递归状态与其他统计
        # 均保留。
        before = self._forward_version
        timeout, attempts, plan = snapshot
        self._timeout = timeout
        self._attempts = attempts
        self._plan = [(name, list(events)) for name, events in plan]
        self._upstream_stats = [[0, 0, 0, 0, 0, 0] for _ in plan]
        self._forward_version += 1
        self._archive_forward(self._forward_version)
        # 审计与配置同一原子步骤入账（x 为目标版本号）。
        self._append_forward_audit("r", target, before,
                                   "applied", self._forward_version)
        return self._rollback_report(self._forward_version, "applied",
                                     target)

    def replay_forward(self, log: str, expected: int) -> str:
        """确定性原子重放上游配置操作序列：整体预检、隔离推演、一次提交。

        log 为不超过 1048576 码点的 ASCII JSON：顶层键序仅 v,o，v 恒为
        1；o 含 0..4096 项（空 o 为合法空操作，结果恒 unchanged）。项
        有两种形态且可混用：旧三键项键序仅 k,x,e；forward_audit 导出的
        五键项键序仅 k,x,e,r,a。k 仅 "l"/"r"，k="l" 时 x 为
        migrate_forward 配置文本（预检阶段先对全部 "l" 项运行
        migrate_forward 完整校验，含 1048576 码点长度限制，规范化文本
        供隔离推演复用），k="r" 时 x 为非负非 bool 的 rollback 目标
        版本；e 为非负非 bool 整数，须等于该步骤执行前暂存版本号；
        五键项的 r 须为该步实际结果（"applied"/"unchanged"），a 须为
        该步执行后的暂存版本号。log 非 str 或 expected 非 int（含
        bool）抛 TypeError；expected<0 抛 ConfigError；expected 不等于
        当前版本号时不解析 log，返回键序 v,r 的报告（v 为当前版本号、
        r="conflict"），不改变任何状态。

        相符时先规范化全部项，再无副作用纯推演每步的配置、32 项历史、
        版本号与结果（整批核对通过前不调用 reload_forward 或
        rollback_forward，也不触碰任何暂存副本）：每步先核对 e 等于
        步骤前暂存版本号（不符抛 ReplayError），五键项随后核对 r、a
        与推演结果一致（不符抛 ReplayError），使 forward_audit 文本可
        直接重放；rollback 目标未保留抛 ConfigError（原样，不转
        ReplayError）。任一预检或推演失败均不执行、不提交，真实解析器
        （含审计队列）不变，整批失败不入账。

        全序列核对通过后才在深拷贝上隔离执行各步（入参为规范化 v1
        文本或已核对的目标版本，不再失败；执行异常不提交），随后一次
        原子提交：timeout、attempts、plan、upstream_stats、版本号、
        32 项历史与 forward_audit 队列均取自暂存副本（成功序列的各步
        按提交序入账，受 4096 项与 16777216 字节淘汰），其余状态不变。
        返回键序 v,r 的紧凑 ASCII JSON（末尾单换行）：v 为提交后版本
        号，r 为序列中出现 applied 则 "applied"，否则 "unchanged"。
        提交后配置、版本号、32 项历史及直转统计须等同以同一版本序列
        逐步调用 reload_forward/rollback_forward，其余状态不变。同初
        态同序列逐字节一致。
        """
        if not isinstance(log, str):
            raise TypeError("log must be str")
        if not isinstance(expected, int) or isinstance(expected, bool):
            raise TypeError("expected must be int")
        if expected < 0:
            raise ConfigError("expected version must be non-negative")
        # 冲突不解析 log：任何解析都必须在版本号检查之后。
        if expected != self._forward_version:
            return json.dumps(
                {"v": self._forward_version, "r": "conflict"},
                ensure_ascii=True, separators=(",", ":")) + "\n"
        if len(log) > _MAX_REPLAY_LOG_TEXT_LEN:
            raise ReplayError("log exceeds 1048576 code points")
        if not log.isascii():
            raise ReplayError("log must be ASCII")
        # 结构预检：仅校验日志形态与字段类型（兼容旧三键项与五键审计项、
        # 空 o），不触碰任何配置内容；k="l" 的配置内容随后由规范化阶段
        # 收口。
        checked = _parse_replay_forward_log(log)
        # 规范化全部项（先于一切副本推演）：对每个 k="l" 项的配置文本
        # 运行纯函数 migrate_forward，长度、解析、结构等配置错误统一为
        # ReplayError；规范 v1 文本再次迁移逐字节不变，规范化结果直接
        # 供隔离推演复用，使推演阶段不可能再冒出配置类 ConfigError。
        migrated = {}
        for index, (kind, value, _e, _r, _a) in enumerate(checked):
            if kind == "l":
                try:
                    migrated[index] = migrate_forward(value)
                except ConfigError:
                    raise ReplayError("forward config is invalid") from None
        # 无副作用纯推演：以 (timeout, attempts, 截断 plan) 快照、暂存
        # 32 项历史与暂存版本号逐步模拟每步结果，逐步核对 e 与五键项的
        # r、a。整批核对通过前不调用 reload_forward/rollback_forward、
        # 不构造暂存副本，真实解析器（配置、版本、历史、审计、直转统计、
        # 缓存、时钟与其他统计）均不受影响。
        staged_config = self._forward_snapshot()
        staged_history = dict(self._forward_history)
        staged_version = self._forward_version
        applied = False
        for index, (kind, value, step_expected,
                    claim_result, claim_after) in enumerate(checked):
            # 调用前核对 e：与结构错误同级，整序列拒绝、不入账。
            if step_expected != staged_version:
                raise ReplayError("e must equal the staged version")
            if kind == "l":
                # 规范 v1 文本已经 migrate_forward 完整校验（每上游事件
                # 不超过 attempts），其 (timeout, attempts, plan) 快照与
                # 生效配置的比较等价于 reload_forward 的规范文本比较。
                config = json.loads(migrated[index])
                snapshot = (
                    config["timeout"], config["attempts"],
                    [(item["name"],
                      [(event["delay"],
                        None if event["reply"] is None
                        else bytes.fromhex(event["reply"]))
                       for event in item["events"]])
                     for item in config["plan"]])
            else:
                # 目标未保留抛 ConfigError（原样，不转 ReplayError）。
                snapshot = staged_history.get(value)
                if snapshot is None:
                    raise ConfigError("target version not retained")
            if snapshot == staged_config:
                result = "unchanged"
            else:
                # applied：暂存配置替换、版本号加 1 并按新版本号归档，
                # 历史容量 32、超量淘汰最小版本号（同 _archive_forward）。
                result = "applied"
                applied = True
                staged_config = snapshot
                staged_version += 1
                staged_history[staged_version] = snapshot
                if len(staged_history) > _FORWARD_HISTORY_CAPACITY:
                    del staged_history[min(staged_history)]
            # 五键审计项：r、a 必须与推演结果逐项一致，保证审计文本可
            # 直接重放。
            if claim_result is not None and claim_result != result:
                raise ReplayError("r must match the replayed result")
            if claim_after is not None and claim_after != staged_version:
                raise ReplayError("a must match the replayed version")
        # 全序列核对通过后才隔离执行：在深拷贝上按序调用
        # reload_forward/rollback_forward（入参均已预检核对，只会
        # unchanged/applied），副本的审计队列随各步真实入账并自行淘汰；
        # 执行万一抛异常则不提交，真实解析器不变。
        candidate = copy.deepcopy(self)
        for index, (kind, value, _e, _r, _a) in enumerate(checked):
            if kind == "l":
                candidate.reload_forward(migrated[index],
                                         candidate._forward_version)
            else:
                candidate.rollback_forward(value, candidate._forward_version)
        # 全部成功后一次原子提交：仅替换上游配置、直转统计、版本号、
        # 历史与审计队列（含本序列各步入账及淘汰结果），缓存、时钟、
        # 区域、递归状态与其他统计全部保留。
        self._timeout = candidate._timeout
        self._attempts = candidate._attempts
        self._plan = candidate._plan
        self._upstream_stats = candidate._upstream_stats
        self._forward_version = candidate._forward_version
        self._forward_history = candidate._forward_history
        self._forward_audit = candidate._forward_audit
        self._forward_audit_bytes = candidate._forward_audit_bytes
        return json.dumps(
            {"v": self._forward_version,
             "r": "applied" if applied else "unchanged"},
            ensure_ascii=True, separators=(",", ":")) + "\n"

    def cache_stats(self, now: int, reset: bool = False) -> str:
        """缓存水位快照：返回键序仅 a,r,x,v 的紧凑 ASCII JSON（末尾单换行）。

        a、r 分别为权威、递归缓存，键序均为 p,nx,nd,total,capacity,ttl：
        前三项为正缓存、NXDOMAIN、NODATA 条目数，total 为合计，capacity
        固定 256；ttl 为同顺序三整数，各取该类最小剩余 TTL，无条目为
        -1。正条目剩余值 = max(0, 插入时刻 + RR 最小 TTL - now)，负条目
        以负 TTL 同算；读取不清除到期项。x、v 各为 [权威, 递归] 非负
        整数数组，分别累计自构造或重置后成功解析实际删除的到期条目数、
        容量 FIFO 淘汰数；换区、更新、回滚的清空不计。计数随成功缓存
        变更原子提交，编码或上游异常不改变它们。

        now 非 int 或为 bool、reset 非 bool 抛 TypeError；now<0 或早于
        上次成功结束时刻抛 CacheError，均无副作用。reset=False 只读；
        True 先返回按 now 计算的旧计数快照，再清零 x、v，保留缓存、
        FIFO、时钟及统计。同参逐字节一致。
        """
        if not isinstance(now, int) or isinstance(now, bool):
            raise TypeError("now must be int")
        if not isinstance(reset, bool):
            raise TypeError("reset must be bool")
        if now < 0 or (self._last_end is not None and now < self._last_end):
            raise CacheError("now must be non-negative and monotonic")
        authority = _cache_watermark(
            self._cache._entries, self._cache._neg_entries,
            self._cache._order, now, glue=True)
        recursive = _cache_watermark(
            self._rec_pos, self._rec_neg, self._rec_order, now)
        text = (
            '{"a":' + authority
            + ',"r":' + recursive
            + ',"x":[' + str(self._clean_expired[0]) + ","
            + str(self._clean_expired[1]) + "]"
            + ',"v":[' + str(self._clean_evicted[0]) + ","
            + str(self._clean_evicted[1]) + "]}\n"
        )
        if reset:
            # 先返回按 now 计算的旧快照再清零；缓存、FIFO、时钟与统计保留。
            self._clean_expired = [0, 0]
            self._clean_evicted = [0, 0]
            # 权威缓存尚未折叠的待并入事件一并归零（成功解析后已同步折叠，
            # 此处通常为 0），保证重置后仅累计新发生的清理事件。
            self._cache._clean_expired = 0
            self._cache._clean_evicted = 0
        return text

    def dump_rec(self, now: int) -> str:
        """把有效递归缓存按 FIFO 次序导出为确定性配置文本（只读）。

        顶层键序仅 v,clock,items：v 恒为 1，clock 为入参 now；items
        按递归缓存 FIFO 插入次序列出此刻仍有效的条目（到期项跳过但
        不删除），不超过 256 项。项键序仅 k,q,t,c,rr：k 为 "p"（正
        缓存）、"nx"（NXDOMAIN）或 "nd"（NODATA）；q 为小写绝对
        qname；t、c 为 qtype、qclass（nx 匹配任意 qtype，t 为
        null）；rr 元素键序 n,t,c,ttl,d，沿用 RR 值域，d 为偶长小写
        十六进制。p 的 rr 非空，ttl 为各 RR 的剩余正整数；nx/nd 恰
        一条 SOA，ttl 为负缓存剩余值。输出为紧凑 ASCII JSON、整数
        十进制、末尾单换行。now 非 int 或为 bool 抛 TypeError；
        now<0 或早于上次成功结束时刻抛 CacheError，均无副作用。
        只读：不改变任何状态，同状态同参逐字节相同。
        """
        if not isinstance(now, int) or isinstance(now, bool):
            raise TypeError("now must be int")
        if now < 0 or (self._last_end is not None and now < self._last_end):
            raise CacheError("now must be non-negative and monotonic")
        items = []
        for tag, key in self._rec_order:
            if tag == "pos":
                inserted, an = self._rec_pos[key]
                elapsed = now - inserted
                if elapsed >= min(rr[3] for rr in an):
                    continue  # 到期项不导出（只读，不删除）
                items.append({
                    "k": "p", "q": key[0], "t": key[1], "c": key[2],
                    "rr": [{"n": _labels_to_name(labels), "t": rrtype,
                            "c": rrclass, "ttl": ttl - elapsed,
                            "d": rdata.hex()}
                           for labels, rrtype, rrclass, ttl, rdata in an],
                })
            else:
                inserted, _rcode, soa, neg_ttl = self._rec_neg[key]
                remaining = neg_ttl - (now - inserted)
                if remaining <= 0:
                    continue  # 到期项不导出（只读，不删除）
                if key[0] == "nxdomain":
                    kind, qname, qtype, qclass = "nx", key[1], None, key[2]
                else:
                    kind = "nd"
                    qname, qtype, qclass = key[1], key[2], key[3]
                items.append({
                    "k": kind, "q": qname, "t": qtype, "c": qclass,
                    "rr": [{"n": _labels_to_name(soa[0]), "t": soa[1],
                            "c": soa[2], "ttl": remaining,
                            "d": soa[4].hex()}],
                })
        config = {"v": 1, "clock": now, "items": items}
        return json.dumps(config, ensure_ascii=True,
                          separators=(",", ":")) + "\n"

    def load_rec(self, text: str, now: int) -> int:
        """校验递归缓存配置文本并原子替换递归缓存，返回保留的条目数。

        文本须为 dump_rec 的 v=1 配置：顶层键序 v,clock,items，项键序
        k,q,t,c,rr，rr 元素键序 n,t,c,ttl,d。校验顺序为：text/now 类型
        （TypeError）；文本长度、JSON 解析、重复键、键序、非 RR 字段与
        重复缓存键（ConfigError）；now 为负、回退或小于 clock
        （CacheError）；RR 字段值与 SOA（RecordError）。p 项 RR 的
        ttl 必须为正，ttl<=0 在按 now-clock 衰减之前即抛 RecordError；
        nx/nd 的负 TTL 允许衰减后为零，到期丢弃。全部通过后按
        now-clock 衰减各 ttl、丢弃到期项，原子替换递归正负缓存与
        FIFO 并置成功时刻为 now；权威缓存、统计与清理计数不变。任何
        失败都无副作用；同初态同参逐字节一致。
        """
        if not isinstance(text, str):
            raise TypeError("text must be str")
        if not isinstance(now, int) or isinstance(now, bool):
            raise TypeError("now must be int")
        if len(text) > _MAX_REC_TEXT_LEN:
            raise ConfigError("text exceeds 1048576 code points")
        try:
            config = json.loads(text, object_pairs_hook=_config_pairs)
        except json.JSONDecodeError:
            raise ConfigError("invalid JSON") from None
        clock, entries, elapsed = _validate_rec_load(
            config, now, self._last_end)
        # 全部校验完成后按 now-clock 衰减、丢弃到期项并原子提交：整体
        # 替换递归正负缓存与 FIFO，成功时刻置为 now。
        new_pos, new_neg, new_order = _age_rec_entries(entries, elapsed, now)
        self._rec_pos = new_pos
        self._rec_neg = new_neg
        self._rec_order = new_order
        self._last_end = now
        return len(new_order)

    def dump_state(self, now: int) -> str:
        """导出区域历史、递归缓存、统计与递归逐层上游统计的整解析器快照。

        顶层键序仅 v,zones,rec,stats,ru：v 恒为 2；zones、rec、stats
        分别为 dump_zones()、dump_rec(now)、stats() 文本的解码对象，
        ru 为 recursive_upstream_stats(False) 文本的解码对象（stats 的
        c[1] 固定等于 rec.items 长度）。输出为紧凑 ASCII JSON、整数
        十进制、末尾单换行，最多 16777216 字节，超限抛 ConfigError。
        now 非 int 或为 bool 抛 TypeError；now<0 或早于上次成功结束
        时刻抛 CacheError（沿用 dump_rec 的 now 异常），均无副作用。
        只读：不改变任何状态（含 recursive_upstream_stats 的 reset 恒
        为 False），同状态同参逐字节相同；load_state 用同参 plan、
        timeout 与同一 now 加载得到等价实例，且再次导出逐字节一致。
        """
        # now 异常沿用 dump_rec：先经其完成类型与时钟校验（只读）。
        rec_text = self.dump_rec(now)
        zones_obj = json.loads(self.dump_zones())
        rec_obj = json.loads(rec_text)
        stats_obj = json.loads(self.stats())
        # ru 直接取 recursive_upstream_stats(False) 的解码对象，保证与
        # 该只读统计输出同构、同序（l 16 行 7 列、t 为逐列和）。
        ru_obj = json.loads(self.recursive_upstream_stats(False))
        # stats 的 c[1] 固定等于 rec.items 长度：dump_rec 跳过期项但不
        # 删除（stats() 的 c[1] 仍计全部 FIFO 条目），故内嵌对象以此
        # 为准改写；加载时该值再按实际恢复条目数重算。
        stats_obj["c"][1] = len(rec_obj["items"])
        config = {"v": 2, "zones": zones_obj, "rec": rec_obj,
                  "stats": stats_obj, "ru": ru_obj}
        text = json.dumps(config, ensure_ascii=True,
                          separators=(",", ":")) + "\n"
        # 紧凑 ASCII 文本字节数与码点数一致；整快照超 16MiB 拒绝导出。
        if len(text.encode("ascii")) > _MAX_STATE_TEXT_LEN:
            raise ConfigError("state text exceeds 16777216 bytes")
        return text

    @classmethod
    def load_state(cls, text: str, plan: list, now: int,
                   timeout: int = 5) -> "Resolver":
        """从 dump_state 快照校验全部内容后恢复等价解析器实例。

        接受 v2（顶层键序 v,zones,rec,stats,ru，v=2）、v1（顶层键序
        v,zones,rec,stats，v=1，无 ru）与 v0（顶层键序 v,zones,rec，
        v=0，无 stats、ru）文本：先经 migrate_state 完整校验并迁移为
        v2（zones 沿用 load_zones 契约，rec 沿用 load_rec 结构契约，
        区域快照与递归 RR 语义、stats 形态及交叉约束、ru 键序/维度/
        值域/合计均在其中校验；v0 补零值统计、c[1] 等于 rec.items
        长度，v0/v1 补零值 ru），再按 now 规则恢复：rec 按
        now-rec.clock 衰减并丢弃到期项，stats 键序 h,m,x,u,c,l,r、
        c[2]=256、c[1] 固定等于 rec.items 长度且加载后按实际恢复
        条目数重算，r 须等于按 h、m 重算的 6 位小数比值，ru 恢复
        递归逐层上游计数。先校验全部内容再构造实例：恢复区域修订
        历史与修订号、stats 各计数、递归正负缓存、FIFO、最后成功
        时刻（按 now 恢复）与 ru 计数；权威缓存为空，plan、timeout
        取参数，rated、逐上游与清理计数清零。text 非 str 或 now 非
        int（含 bool）抛 TypeError；text 超 16777216 码点、JSON 解析、
        重复键、键序、未知 v 或交叉约束错误（含 ru 非法）抛
        ConfigError；区域或 RR 语义错误沿用 ZoneError、RecordError，
        时钟错误抛 CacheError，plan/timeout 错误沿用构造器
        （TypeError/ValueError）。任何失败都不产生实例；同态同参
        逐字节一致。
        """
        if not isinstance(text, str):
            raise TypeError("text must be str")
        if not isinstance(now, int) or isinstance(now, bool):
            raise TypeError("now must be int")
        # 与 load_state_file 共用迁移：v0/v1/v2 文本先经 migrate_state
        # 完整校验（结构、区域快照、递归 RR 语义与 ru 形态及交叉约束）
        # 并规范化为 v2 文本，此处的结构重校验恒通过；随后仅按 now 规则
        # 做时钟校验、衰减与恢复。
        config = json.loads(migrate_state(text),
                            object_pairs_hook=_config_pairs)
        zones_obj, rec_obj, stats_obj, ru_obj = (
            config["zones"], config["rec"], config["stats"], config["ru"])
        # 各段结构层校验全部先于任何语义校验：zones 的 JSON 结构、rec 的
        # 配置结构、stats 的形态及交叉约束与 ru 的形态/合计错误统一为
        # ConfigError。
        zones_text = json.dumps(zones_obj, ensure_ascii=True,
                                separators=(",", ":"))
        schema, _zversion, history = _parse_zones_config(zones_text)
        clock, rec_items = _check_rec_config(rec_obj)
        h, m, x, u, c, l_buckets = _check_state_stats(
            stats_obj, len(rec_items))
        ru_rows, _ru_totals = _check_state_ru(ru_obj)
        # zones 快照语义沿用 load_zones：先校验全部快照再恢复（结构错误
        # 已在上一步排除，语义错误沿用 RecordError、ZoneError）。
        snapshot_loader = (_load_zone_snapshot if schema == 1
                           else _load_zone_snapshot_any)
        snapshots = [(item["revision"], snapshot_loader(item["zone"]))
                     for item in history]
        kept = snapshots[-_ZONE_HISTORY_CAPACITY:]
        # 时钟校验（CacheError）先于 rec RR 值域校验（RecordError）：新
        # 实例时钟未设，仅要求 now 非负且不早于 rec.clock。
        if now < 0:
            raise CacheError("now must be non-negative")
        if now < clock:
            raise CacheError("now must not be earlier than clock")
        entries = [(kind, key, _validate_rec_item(kind, rrs))
                   for kind, key, rrs in rec_items]
        for kind, _key, rrs in entries:
            if kind == "p" and any(rr[3] <= 0 for rr in rrs):
                raise RecordError("p rr ttl must be positive")
        # 全部校验通过后才构造实例（plan、timeout 异常沿用构造器）并提交。
        instance = cls(kept[-1][1], plan, timeout)
        instance._revision = _zversion
        instance._zone_history = {
            revision: copy.deepcopy(zone) for revision, zone in kept}
        new_pos, new_neg, new_order = _age_rec_entries(
            entries, now - clock, now)
        instance._rec_pos = new_pos
        instance._rec_neg = new_neg
        instance._rec_order = new_order
        instance._last_end = now
        # stats 计数恢复；c[0] 沿用快照（权威缓存为空，待下次解析提交时
        # 同步），c[1] 不赋值而由 stats() 按实际递归条目数重算。
        instance._stats_h = h
        instance._stats_m = m
        instance._stats_x = x
        instance._stats_u = u
        instance._stats_l = l_buckets
        instance._stats_c0 = c[0]
        # ru 计数恢复为快照 l（t 为派生合计，不单独存储）；v0/v1 经
        # migrate_state 补零，等价于全新解析器的递归逐层统计。
        instance._recursive_up = ru_rows
        return instance

    def save_state(self, path: str, now: int) -> int:
        """把 dump_state(now) 字节逐字节原子落盘，返回写入字节数。

        path 非 str 抛 TypeError；path 为空串或含 NUL 抛 ConfigError；
        now 异常沿用 dump_state（TypeError/CacheError）。落盘内容与
        dump_state(now) 逐字节相同：在目标同目录创建唯一临时文件，循环
        write 至全部字节写完（write 返回 None、非 int 或非正数抛
        OSError），flush、fsync 后以 os.replace 原子替换目标。任一步
        I/O 失败抛 OSError，删除本次临时文件、保留旧目标文件；
        dump_state 只读，任何失败与成功都不改变解析器状态，同态同参
        重复保存逐字节相同。
        """
        if not isinstance(path, str):
            raise TypeError("path must be str")
        if path == "" or "\x00" in path:
            raise ConfigError("path must be non-empty and without NUL")
        # dump_state 只读且先于任何文件操作完成：其 TypeError/
        # CacheError/ConfigError 原样传播，此时尚无临时文件。
        data = self.dump_state(now).encode("ascii")
        # 原子落盘与 export_log 共用同一路径：同目录临时文件、循环写、
        # flush、fsync 后 os.replace；失败删除临时项、保留旧目标。
        _atomic_write_file(path, data, ".dns-state-")
        return len(data)

    @classmethod
    def load_state_file(cls, path: str, plan: list, now: int,
                        timeout: int = 5) -> "Resolver":
        """从状态文件恢复等价解析器实例（协议完全复用 load_state）。

        path 非 str 抛 TypeError；path 为空串或含 NUL 抛 ConfigError。
        最多读取 16777217 字节：文件缺失抛 FileNotFoundError，其余 I/O
        错抛 OSError；内容超过 16777216 字节或含非 ASCII 字节抛
        ConfigError。解码后完全沿用 load_state：接受 v0/v1/v2 状态
        文本并经 migrate_state 迁移为规范 v2（截断 JSON、重复键、
        键序、未知 v、状态结构错或 ru 非法抛 ConfigError，区域或 RR
        语义错抛 ZoneError、RecordError），plan/timeout 校验、时钟
        衰减与其余异常（CacheError 及构造器 TypeError/ValueError）
        均与其一致；任何失败都不产生实例。成功恢复区域修订历史与
        修订号、递归正负缓存、FIFO、统计、ru 计数与最后成功时刻，
        权威缓存为空。
        """
        if not isinstance(path, str):
            raise TypeError("path must be str")
        if path == "" or "\x00" in path:
            raise ConfigError("path must be non-empty and without NUL")
        # 缺失与 I/O 错原样传播（FileNotFoundError/OSError）；仅多读一字节
        # 即可判定超限，避免把超限文件整体读入内存。
        with open(path, "rb") as stream:
            data = stream.read(_MAX_STATE_TEXT_LEN + 1)
        if len(data) > _MAX_STATE_TEXT_LEN:
            raise ConfigError("state file exceeds 16777216 bytes")
        if not data.isascii():
            raise ConfigError("state file must be ASCII")
        text = data.decode("ascii")
        # 解码后的全部协议、plan/timeout、时钟衰减与异常均复用 load_state。
        return cls.load_state(text, plan, now, timeout)

    def reload_state(self, text: str, now: int, expected: int) -> str:
        """从状态文本校验整份快照并原子热加载，返回 version,result 报告。

        text 非 str 或 now、expected 非 int（含 bool）抛 TypeError；
        expected 为负抛 ConfigError；now 为负或早于上次成功结束时刻抛
        CacheError。验参后 expected 不等于当前修订号时不解析 text，
        报告 conflict（version 为当前修订号），不改变任何状态。相符时
        完全沿用 load_state 的契约与异常（迁移、结构、区域与 RR 语义、
        时钟衰减等）以当前 plan、timeout 与入参 now 构造候选实例，异常
        原样传播且解析器不变。候选提交与 reload_state_file 共用同一路径：
        候选修订号小于当前修订号抛 ConfigError；候选 dump_state(now) 与
        当前 dump_state(now) 相同报告 unchanged（版本与状态不变）；不同
        则原子替换区域修订历史、修订号、递归正负缓存、FIFO、最后成功
        时刻、统计与 ru 计数，权威缓存清空（随候选为空），rated 与清理
        计数归零，保留 plan 与 timeout，报告 applied。报告键序仅
        version,result（version 为操作后修订号，result 为 "applied"、
        "unchanged" 或 "conflict"），紧凑 ASCII JSON、十进制整数、末尾
        单换行。异常与非 applied 结果均不改变任何状态。
        """
        if not isinstance(text, str):
            raise TypeError("text must be str")
        if not isinstance(now, int) or isinstance(now, bool):
            raise TypeError("now must be int")
        if not isinstance(expected, int) or isinstance(expected, bool):
            raise TypeError("expected must be int")
        if expected < 0:
            raise ConfigError("expected revision must be non-negative")
        if now < 0 or (self._last_end is not None and now < self._last_end):
            raise CacheError("now must be non-negative and monotonic")
        # 冲突不解析 text：任何解析都必须在修订号检查之后。
        if expected != self._revision:
            return self._tx_report(self._revision, "conflict")
        candidate = Resolver.load_state(text, self._plan, now, self._timeout)
        return self._commit_state_candidate(candidate, now)

    def reload_state_file(self, path: str, now: int, expected: int) -> str:
        """从状态文件校验整份快照并原子热加载（协议复用 reload_state）。

        path 非 str 或 now、expected 非 int（含 bool）抛 TypeError；
        expected 为负、path 为空串或含 NUL 抛 ConfigError；now 为负或
        早于上次成功结束时刻抛 CacheError。验参后 expected 不等于当前
        修订号时不读文件，报告 conflict（version 为当前修订号），不改
        变任何状态。相符时完全沿用 load_state_file 的契约与异常（缺失
        抛 FileNotFoundError，其余 I/O 错抛 OSError，超限或非 ASCII 抛
        ConfigError，余同 load_state）以当前 plan、timeout 与入参 now
        构造候选实例；候选提交与 reload_state 共用同一路径：候选修订号
        小于当前修订号抛 ConfigError，候选 dump_state(now) 与当前相同
        报告 unchanged，否则原子替换区域修订历史、修订号、递归正负
        缓存、FIFO、最后成功时刻、统计与 ru 计数，清空权威缓存，
        rated 与清理计数归零，保留 plan 与 timeout，报告 applied。
        报告键序仅 version,result，紧凑 ASCII JSON、末尾单换行；异常
        与非 applied 结果均不改变任何状态。
        """
        if not isinstance(path, str):
            raise TypeError("path must be str")
        if not isinstance(now, int) or isinstance(now, bool):
            raise TypeError("now must be int")
        if not isinstance(expected, int) or isinstance(expected, bool):
            raise TypeError("expected must be int")
        if expected < 0:
            raise ConfigError("expected revision must be non-negative")
        if path == "" or "\x00" in path:
            raise ConfigError("path must be non-empty and without NUL")
        if now < 0 or (self._last_end is not None and now < self._last_end):
            raise CacheError("now must be non-negative and monotonic")
        # 冲突不读文件：任何文件访问都必须在修订号检查之后。
        if expected != self._revision:
            return self._tx_report(self._revision, "conflict")
        candidate = Resolver.load_state_file(path, self._plan, now,
                                             self._timeout)
        return self._commit_state_candidate(candidate, now)

    def _commit_state_candidate(self, candidate, now):
        """共用候选提交路径：校验候选修订号、比较快照并原子提交或报 unchanged。"""
        # 只允许不回退的修订号；候选号更旧一律拒绝（同号允许）。
        if candidate._revision < self._revision:
            raise ConfigError("state revision must not be less than current")
        if candidate.dump_state(now) == self.dump_state(now):
            # 规范化后内容一致：不替换、不改版本与任何状态。
            return self._tx_report(self._revision, "unchanged")
        # 全部校验成功后原子提交：区域历史、修订号、递归正负缓存、FIFO、
        # 最后成功时刻、统计与 ru 计数随候选一并替换；权威缓存随候选为
        # 空；rated、逐上游与清理计数归零；plan 与 timeout 保留。
        self._cache = candidate._cache
        self._revision = candidate._revision
        self._zone_history = candidate._zone_history
        self._rec_pos = candidate._rec_pos
        self._rec_neg = candidate._rec_neg
        self._rec_order = candidate._rec_order
        self._last_end = candidate._last_end
        self._stats_h = candidate._stats_h
        self._stats_m = candidate._stats_m
        self._stats_x = candidate._stats_x
        self._stats_u = candidate._stats_u
        self._stats_l = candidate._stats_l
        self._stats_c0 = candidate._stats_c0
        self._rated_o = [0, 0, 0, 0]
        self._rated_e = [0, 0]
        self._rated_l = [0, 0, 0, 0]
        self._upstream_stats = [[0, 0, 0, 0, 0, 0] for _ in self._plan]
        # ru 计数已随 dump_state 持久化，热加载按候选快照恢复（旧版
        # v0/v1 文本经迁移补零，等价于归零）；rated/逐上游仍为不入
        # dump_state 的操作性计数，照旧归零。
        self._recursive_up = candidate._recursive_up
        self._clean_expired = [0, 0]
        self._clean_evicted = [0, 0]
        return self._tx_report(self._revision, "applied")

    def replay_log(self, text: str, expected: int) -> str:
        """确定性原子日志重放：整体预检、隔离执行、全部成功后一次提交。

        text 为不超过 1048576 码点的 ASCII JSON：顶层键序仅 v,now,ops，
        v 恒为 1，now 为非负非 bool 整数，ops 为 1..4096 项并沿用
        replay 的输入协议（reload/reload_tx/reload_serial/migrate/
        migrate_tx/
        restore_zones/resolve/transfer/recursive/rollback/rollback_batch/
        update/cache_stats，全部操作在隔离执行前完成预检）。text 非
        str 或 expected 非 int（含 bool）抛 TypeError；expected<0、
        text 超长或非 ASCII、JSON 解析、重复键、键序、v 非法、now<0
        （在预检 ops 与执行之前）或操作非法抛 ReplayError。expected
        不等于当前修订号时不解析 text，报告
        conflict（ops 为空、state 为 null），不改变任何状态。相符时
        在解析器深拷贝上依次执行各操作：任一步抛出的异常原样传播并
        放弃全部暂存状态（真实解析器不变）。全部成功后 now 沿用
        dump_state 的时钟契约且不得早于各步 end（违反抛 CacheError，
        同样不提交），state 取候选 dump_state(now) 的解码对象；输出
        超过 16777216 字节抛 ReplayError 且不提交。仅全部通过后才把
        候选状态整体原子提交到本解析器。输出为紧凑 ASCII JSON、末尾
        单换行，顶层键序仅 v,result,ops,state：v 恒为 1，result 为
        "applied" 或 "conflict"；applied 的 ops 项沿用 replay 的
        in,out,stats 记录（in 为操作原文，stats 为该操作后的 stats()
        原文），conflict 时 ops 为空、state 为 null。
        """
        if not isinstance(text, str):
            raise TypeError("text must be str")
        if not isinstance(expected, int) or isinstance(expected, bool):
            raise TypeError("expected must be int")
        if expected < 0:
            raise ReplayError("expected revision must be non-negative")
        # 冲突不解析 text：任何解析都必须在修订号检查之后。
        if expected != self._revision:
            return _REPLAY_LOG_CONFLICT
        if len(text) > _MAX_REPLAY_LOG_TEXT_LEN:
            raise ReplayError("text exceeds 1048576 code points")
        if not text.isascii():
            raise ReplayError("text must be ASCII")
        try:
            log = json.loads(text, object_pairs_hook=_replay_log_pairs)
        except json.JSONDecodeError:
            raise ReplayError("invalid JSON") from None
        if not isinstance(log, dict):
            raise ReplayError("log must be an object")
        if list(log.keys()) != _REPLAY_LOG_KEYS:
            raise ReplayError("log keys must be v,now,ops")
        version = log["v"]
        if (not isinstance(version, int) or isinstance(version, bool)
                or version != 1):
            raise ReplayError("unsupported v")
        now = log["now"]
        if not isinstance(now, int) or isinstance(now, bool):
            raise ReplayError("now must be int")
        # 顶层 now<0 在预检 ops 与隔离执行之前拒绝。
        if now < 0:
            raise ReplayError("now must be non-negative")
        ops = log["ops"]
        if not isinstance(ops, list):
            raise ReplayError("ops must be list")
        if not 1 <= len(ops) <= _MAX_REPLAY_OPS:
            raise ReplayError("ops must contain 1..4096 items")
        # 预检：全部操作（含 recursive 的 levels）在隔离执行前完成校验。
        checked = _validate_ops(ops)
        # 隔离执行：全部操作在深拷贝上执行，任何异常放弃全部暂存状态，
        # 真实解析器（区域、版本、历史、缓存、时钟、统计）均不受影响。
        candidate = copy.deepcopy(self)
        items = []
        for kind, op, plans in checked:
            out = _execute_replay_op(candidate, kind, op, plans)
            items.append({"in": op, "out": out, "stats": candidate.stats()})
        # now 的时钟契约（非负、不早于上次成功结束时刻与各步 end）由
        # dump_state 一并校验，CacheError 原样传播且不提交；dump_state
        # 自身的超限 ConfigError 即输出超限，归为 ReplayError。
        try:
            state_obj = json.loads(candidate.dump_state(now))
        except ConfigError:
            raise ReplayError(
                "replay log result exceeds 16777216 bytes") from None
        result = json.dumps({"v": 1, "result": "applied", "ops": items,
                             "state": state_obj},
                            ensure_ascii=True, separators=(",", ":")) + "\n"
        # 紧凑 ASCII 文本字节数与码点数一致；整结果超 16MiB 拒绝提交。
        if len(result) > _MAX_REPLAY_RESULT_BYTES:
            raise ReplayError("replay log result exceeds 16777216 bytes")
        # 全部成功后原子提交：候选状态整体替换本解析器状态。
        self.__dict__.update(candidate.__dict__)
        return result

    def export_log(self, ops: list, now: int,
                   path: str | None = None) -> str | int:
        """把 ops 与 now 导出为 replay_log 日志文本，或原子落盘。

        ops 沿用 replay_log 的 ops 协议（限 1..4096 项，项非法抛
        ReplayError）；now 为非负非 bool 整数。ops 非 list 或 now 非
        int（含 bool）抛 TypeError；path 非 None 时沿用 save_state 的
        路径校验（非 str 抛 TypeError，空串或含 NUL 抛 ConfigError，
        先于日志内容校验）。日志顶层键序仅 v,now,ops：v 恒为 1，ops
        保留各项键序；紧凑 ASCII JSON、末尾单换行，文本超过 1048576
        字节抛 ReplayError。序列化后以当前修订号在解析器深拷贝上调用
        replay_log 完整验证（结构预检、隔离执行与时钟契约），其异常
        （ReplayError、CacheError 等）原样传播；验证在副本上进行，
        成功或失败都不改变本解析器状态。path 为 None 返回日志文本；
        否则沿用 save_state 的原子写入与 I/O 异常协议（同目录临时
        文件、循环写、flush、fsync、os.replace；I/O 失败抛 OSError、
        删除临时项、保留旧目标），返回写入字节数。同态同参逐字节
        一致。
        """
        if not isinstance(ops, list):
            raise TypeError("ops must be list")
        if not isinstance(now, int) or isinstance(now, bool):
            raise TypeError("now must be int")
        if path is not None:
            if not isinstance(path, str):
                raise TypeError("path must be str")
            if path == "" or "\x00" in path:
                raise ConfigError("path must be non-empty and without NUL")
        # 顶层键序仅 v,now,ops；ops 各项键序由保序序列化保留。项须为
        # JSON 可序列化形态，否则视为非法项（ReplayError）。
        try:
            text = json.dumps({"v": 1, "now": now, "ops": ops},
                              ensure_ascii=True,
                              separators=(",", ":")) + "\n"
        except (TypeError, ValueError):
            raise ReplayError("ops must be JSON-serializable") from None
        # 紧凑 ASCII 文本字节数与码点数一致；超 1MiB 拒绝导出。
        if len(text) > _MAX_REPLAY_LOG_TEXT_LEN:
            raise ReplayError("log text exceeds 1048576 bytes")
        # 以当前修订号在深拷贝上完整走 replay_log：任何异常原样传播，
        # 本解析器状态不变。
        copy.deepcopy(self).replay_log(text, self._revision)
        if path is None:
            return text
        data = text.encode("ascii")
        # 原子落盘与 save_state 共用同一路径。
        _atomic_write_file(path, data, ".dns-log-")
        return len(data)

    def replay_log_file(self, path: str, expected: int) -> str:
        """从日志文件重放（协议复用 replay_log），失败不产生副作用。

        path 非 str 或 expected 非 int（含 bool）抛 TypeError；
        expected<0 抛 ReplayError；path 为空串或含 NUL 抛 ConfigError
        （沿用 load_state_file 的路径校验）。验参后 expected 不等于
        当前修订号时不读文件，报告 conflict（ops 为空、state 为
        null），不改变任何状态。相符时最多读取 1048577 字节：文件
        缺失抛 FileNotFoundError，其余 I/O 错抛 OSError（均沿用
        load_state_file）；内容超过 1048576 字节或含非 ASCII 字节抛
        ReplayError。解码后完全复用 replay_log：整体预检、隔离执行、
        全部成功后一次提交，异常原样传播且解析器不变。同态同参逐
        字节一致。
        """
        if not isinstance(path, str):
            raise TypeError("path must be str")
        if not isinstance(expected, int) or isinstance(expected, bool):
            raise TypeError("expected must be int")
        if expected < 0:
            raise ReplayError("expected revision must be non-negative")
        if path == "" or "\x00" in path:
            raise ConfigError("path must be non-empty and without NUL")
        # 冲突不读文件：任何文件访问都必须在修订号检查之后。
        if expected != self._revision:
            return _REPLAY_LOG_CONFLICT
        # 缺失与 I/O 错原样传播（FileNotFoundError/OSError）；仅多读
        # 一字节即可判定超限，避免把超限文件整体读入内存。
        with open(path, "rb") as stream:
            data = stream.read(_MAX_REPLAY_LOG_TEXT_LEN + 1)
        if len(data) > _MAX_REPLAY_LOG_TEXT_LEN:
            raise ReplayError("log file exceeds 1048576 bytes")
        if not data.isascii():
            raise ReplayError("log file must be ASCII")
        # 解码后的全部协议与异常复用 replay_log。
        return self.replay_log(data.decode("ascii"), expected)

    @classmethod
    def replay_bundle(cls, text: str) -> "tuple[Resolver, str]":
        """从重放封包恢复计划、缓存、时钟、统计、ru、上游配置历史与审计
        并原子重放（接受 v1/v2 封包）。

        text 非 str 抛 TypeError；text 超过 16777216 码点、非 ASCII、
        JSON 解析（含重复键、超长整数、超深嵌套）、顶层键序、v、forward
        包装结构/关联、log 结构或执行所得文本与 result 不符抛
        ReplayError。封包为 ASCII JSON 对象，顶层键序仅
        v,state,forward,log,result：v=1 时 forward 为 migrate_forward
        的 v1 配置对象，恢复为唯一版本 0 历史、空审计（不产生 forward
        版本与审计，rollback_forward(0,0) 报告 unchanged 且不改配置）；
        v=2 时 forward 为键序 version,history,audit 的包装，经
        _check_bundle_v2_forward 完整校验关联，当前生效配置取末项
        config，版本号、32 项内历史与审计队列按包装原样恢复。两种形态
        的 state 均为 dump_state 的 v2 对象、log 为 export_log 的 v1
        对象、result 为 replay_log 的成功结果对象。

        恢复与重放完全隔离：四段分别重新紧凑序列化，state、forward、
        log 的结构与语义错误分别沿用 load_state（其先经 migrate_state
        完整校验）、migrate_forward 与 replay_log 抛出（state、forward
        配置语义抛 ConfigError/ZoneError/RecordError/CacheError 等；
        v2 forward 包装的结构与关联错误抛 ReplayError；log 结构抛
        ReplayError）；先以 state.rec.clock 与 forward 的 plan、timeout
        经 load_state 恢复候选实例（区域历史、修订号、缓存、时钟、统计
        与 ru），再按 forward 设置 attempts 并恢复版本号、历史与审计
        （v1 重建为唯一的版本 0 历史），然后在候选上以 state 的区域
        修订号为 expected 执行 log，操作异常与时钟 CacheError 原样传播。
        执行完成后所得文本与 result 紧凑序列化文本逐字节比较，result 的
        任何形态或内容不符（含 conflict）统一抛 ReplayError；仅全部通过
        才返回 (恢复并重放后的解析器, 该文本)。任何失败都不产生实例；
        同封包逐字节一致。
        """
        if not isinstance(text, str):
            raise TypeError("text must be str")
        if len(text) > _MAX_REPLAY_BUNDLE_LEN:
            raise ReplayError("bundle exceeds 16777216 code points")
        if not text.isascii():
            raise ReplayError("bundle must be ASCII")
        try:
            bundle = json.loads(text, object_pairs_hook=_replay_log_pairs)
        except ReplayError:
            # 重复键由 _replay_log_pairs 抛 ReplayError，原样传播。
            raise
        except (json.JSONDecodeError, RecursionError, ValueError):
            # json 对超长整数抛非 JSONDecodeError 的 ValueError、对超深
            # 嵌套抛 RecursionError，统一归为 ReplayError，不泄漏 json 异常。
            raise ReplayError("invalid JSON") from None
        if not isinstance(bundle, dict):
            raise ReplayError("bundle must be an object")
        if list(bundle.keys()) != _REPLAY_BUNDLE_KEYS:
            raise ReplayError("bundle keys must be v,state,forward,log,result")
        version = bundle["v"]
        if (not isinstance(version, int) or isinstance(version, bool)
                or version not in (1, 2)):
            raise ReplayError("unsupported v")
        state_obj, forward_obj = bundle["state"], bundle["forward"]
        log_obj, result_obj = bundle["log"], bundle["result"]
        # 各段重新紧凑序列化为文本：入参均为 JSON 已解析值，序列化不会
        # 失败。state、log 的结构与语义分别收口于 migrate_state/load_state
        # 与 replay_log，封包层不重复校验；result 的任何结构/内容错误都
        # 不可能与成功重放文本逐字节相同，由末尾比对统一收口为 ReplayError。
        state_text = json.dumps(state_obj, ensure_ascii=True,
                                separators=(",", ":"))
        log_text = json.dumps(log_obj, ensure_ascii=True,
                              separators=(",", ":")) + "\n"
        # 隔离恢复与重放完全复用 export_bundle 的同一恢复路径，保证同三段
        # 文本逐字节得到同一结果：state、forward 的语义错误沿用
        # load_state、migrate_forward 原样抛出（v2 forward 包装的结构与
        # 关联错误抛 ReplayError），log 结构错误抛 ReplayError，操作异常
        # 与时钟 CacheError 原样传播；失败时实例仅存在于本方法内，不产生
        # 对外实例。forward 段的校验在恢复路径内、state 之后进行，与 v1
        # 的 state→forward→log 异常优先级一致。
        resolver, out_text, _forward_restore = cls._recover_bundle_resolver(
            state_text, version, forward_obj, log_text)
        # result 按键序（v,result,ops,state）生成的紧凑文本须与执行 log
        # 所得文本逐字节相同；result 非对象、形态或内容不符均在此收口
        # 为 ReplayError。
        expected_text = json.dumps(result_obj, ensure_ascii=True,
                                   separators=(",", ":")) + "\n"
        if out_text != expected_text:
            raise ReplayError("replay result does not match bundle result")
        return resolver, out_text

    @classmethod
    def _recover_bundle_resolver(cls, state_text, bundle_version,
                                 forward_obj, log_text):
        """从封包 state/forward/log 隔离恢复解析器并重放 log。

        replay_bundle、export_bundle 与 migrate_bundle 共用的唯一恢复
        路径，保证同三段逐字节得到同一结果。bundle_version 为 1 时
        forward_obj 是 migrate_forward 的 v1 配置对象；为 2 时是经
        _check_bundle_v2_forward 完整校验的 version,history,audit 包装。

        state 先经 migrate_state 完整校验取 state.rec.clock 与区域当前
        修订号（ConfigError/ZoneError/RecordError 等原样传播）；随后
        校验 forward：v1 经 migrate_forward 规范化，v2 经
        _check_bundle_v2_forward 校验关联并以末项 config 作为当前生效
        配置（包装结构/关联错误抛 ReplayError，config 与 audit l.x 的
        配置语义错误由 migrate_forward 原样抛出 ConfigError 等），取
        plan、timeout、attempts；先以 state.rec.clock 经 load_state 恢复
        候选实例（区域历史、修订号、缓存、时钟、统计与 ru；权威缓存按
        load_state 语义为空），再按 forward 设置 attempts（plan、timeout
        已取 forward，不产生 forward 热加载）。v1 随后把当前生效配置
        重建为唯一的版本 0 历史——恢复实例未经历热加载、版本号仍为 0、
        审计队列仍空，版本 0 快照即当前生效配置，故
        rollback_forward(0, 0) 命中快照且快照与当前等价，报告
        unchanged 且不改配置；v2 按包装恢复版本号、32 项内历史快照与
        提交序审计队列。最后以 state 的区域修订号为 expected 在候选上
        执行 log；log 结构错误由 replay_log 抛 ReplayError，操作异常与
        时钟 CacheError 原样传播。返回 (恢复并重放后的解析器,
        replay_log 文本, forward 恢复信息)：v1 时第三项为 None，v2 时为
        (version, history 规范化对象列表, audit 对象)，供导出/迁移组装
        v2 封包。
        """
        # state 错误沿用 load_state（其内部先经 migrate_state 完整校验
        # 并规范化）：此处先迁移一次以取 state.rec.clock 与区域当前修订
        # 号；ConfigError/ZoneError/RecordError 等原样传播。
        state_norm = json.loads(migrate_state(state_text),
                                object_pairs_hook=_config_pairs)
        clock = state_norm["rec"]["clock"]
        expected = state_norm["zones"]["version"]
        # forward 段校验在 state 之后：v1 直接规范化配置对象；v2 完整
        # 校验 version,history,audit 包装的结构与关联（其 config 与
        # audit l.x 的配置语义错误由 migrate_forward 原样抛出），当前
        # 生效配置取末项 config。
        if bundle_version == 1:
            forward_text = json.dumps(forward_obj, ensure_ascii=True,
                                      separators=(",", ":")) + "\n"
            forward_text = migrate_forward(forward_text)
            forward_restore = None
        else:
            forward_version, forward_history, forward_audit_obj = (
                _check_bundle_v2_forward(forward_obj))
            forward_restore = (forward_version, forward_history,
                               forward_audit_obj)
            forward_text = json.dumps(forward_history[-1]["config"],
                                      ensure_ascii=True,
                                      separators=(",", ":")) + "\n"
        # forward 的规范化文本作为 plan/timeout/attempts 的恢复依据。
        forward_config = json.loads(forward_text)
        plan = [
            (item["name"],
             [(event["delay"],
               None if event["reply"] is None
               else bytes.fromhex(event["reply"]))
              for event in item["events"]])
            for item in forward_config["plan"]]
        # 以 state.rec.clock 调 load_state：计划、缓存、时钟、统计与 ru
        # 的恢复异常沿用 load_state（ConfigError/ZoneError/RecordError/
        # CacheError 及构造器 TypeError/ValueError），失败不产生实例。
        resolver = cls.load_state(state_text, plan, clock,
                                  forward_config["timeout"])
        # plan、timeout、attempts 取 forward：load_state 已用 plan 与
        # timeout 构造，attempts 直接按 forward 设置；不产生 forward
        # 热加载版本或审计。
        resolver._attempts = forward_config["attempts"]
        if forward_restore is None:
            # v1：按 forward 恢复后重建版本 0 历史：load_state 构造时按
            # 入参 plan 归档的版本 0 快照（attempts=2）可能与含恢复
            # attempts 的当前生效配置不等价，故丢弃构造历史、以当前生效
            # 配置重建唯一版本 0 快照；版本号保持 0、审计队列保持空。
            # 由此 rollback_forward(0, 0) 命中快照且与当前等价，报告
            # unchanged 且不改配置。
            resolver._forward_version = 0
            resolver._forward_history = {0: resolver._forward_snapshot()}
            resolver._forward_audit = deque()
            resolver._forward_audit_bytes = 0
        else:
            # v2：按包装恢复版本号与 32 项内历史快照（config 已由
            # migrate_forward 规范化为 v1 对象，转成与 _forward_snapshot
            # 同一形态的 (timeout, attempts, 截断 plan) 元组）及提交序
            # 审计队列（五键项重新紧凑渲染并重算字节预算；k="l" 的 x 已
            # 规范化为规范 v1 文本，渲染结果与 forward_audit 导出逐项
            # 一致）。
            forward_version, forward_history, forward_audit_obj = (
                forward_restore)
            resolver._forward_version = forward_version
            resolver._forward_history = {}
            for item in forward_history:
                config = item["config"]
                resolver._forward_history[item["version"]] = (
                    config["timeout"], config["attempts"],
                    [(plan_item["name"],
                      [(event["delay"],
                        None if event["reply"] is None
                        else bytes.fromhex(event["reply"]))
                       for event in plan_item["events"]])
                     for plan_item in config["plan"]])
            audit = deque()
            audit_bytes = 0
            for audit_item in forward_audit_obj["o"]:
                item_text = json.dumps(audit_item, ensure_ascii=True,
                                       separators=(",", ":"))
                audit.append(item_text)
                audit_bytes += len(item_text) + 1
            resolver._forward_audit = audit
            resolver._forward_audit_bytes = audit_bytes
        # 在恢复出的隔离实例上执行 log：log 的结构预检错误由 replay_log
        # 抛 ReplayError，操作异常与时钟 CacheError 原样传播；expected
        # 取 state 区域的当前修订号；不符时 replay_log 返回 conflict
        # 文本，由调用方末尾与 result 的比对收口为 ReplayError。
        # replay_log 在深拷贝上执行并整体提交，forward 版本/历史/审计不
        # 受任何 log 操作影响，随深拷贝原样保留。
        out_text = resolver.replay_log(log_text, expected)
        if forward_restore is None:
            # v1 迁为版本 0、单项历史（config 为规范化 v1 配置）与空审计。
            forward_wrapper = {
                "version": 0,
                "history": [{"version": 0,
                             "config": json.loads(forward_text)}],
                "audit": {"v": 1, "o": []}}
        else:
            forward_version, forward_history, forward_audit_obj = (
                forward_restore)
            forward_wrapper = {"version": forward_version,
                               "history": forward_history,
                               "audit": forward_audit_obj}
        return resolver, out_text, forward_wrapper

    def _bundle_v2_forward_obj(self):
        """构造封包 v2 的 forward 包装对象（键序 version,history,audit）。

        version 为当前 dump_forward 版本号；history 按 forward_versions
        严格升序列键序 version,config 的保留快照（config 为快照的规范
        migrate_forward v1 对象：快照在归档时已按 attempts 截断 plan，
        与 _forward_config 同一规范化，故末项配置即当前生效配置、末项
        版本即 version）；audit 为 forward_audit() 的解码对象（键序
        v,o，五键项 k,x,e,r,a）。只读：不改变任何状态。
        """
        history = []
        for version in sorted(self._forward_history):
            timeout, attempts, plan = self._forward_history[version]
            history.append({"version": version, "config": {
                "v": 1, "timeout": timeout, "attempts": attempts,
                "plan": [
                    {"name": name,
                     "events": [
                         {"delay": delay,
                          "reply": reply.hex() if reply is not None else None}
                         for delay, reply in events]}
                    for name, events in plan]}})
        return {"version": self._forward_version, "history": history,
                "audit": json.loads(self.forward_audit())}

    def export_bundle(self, ops: list, now: int) -> str:
        """导出可由 replay_bundle 隔离恢复并重放的重放封包文本（只读）。

        ops 沿用 export_log 的 ops 协议，限 1..4096 项，项非法抛
        ReplayError；起始时刻取最后成功结束时刻，未设为 0。ops 非 list
        或 now 非 int（bool 非法）抛 TypeError；now 为负或早于起始时刻
        抛 CacheError；ops 非法或完整封包结果超 16777216 字节抛
        ReplayError。先构造 log 文本（export_log 同形的 v,now,ops），
        再以起始时刻 dump_state 的 v2 对象、当前上游转发版本/32 项历史/
        提交序审计的 version,history,audit 包装与 log 的解码对象分别作为
        state、forward、log；result 不是本解析器深拷贝的重放结果
        （dump_state 不含权威缓存等），而是把三段重新紧凑序列化后经与
        replay_bundle 完全相同的隔离恢复路径（v2：连版本、历史与审计一并
        恢复）重放所得 replay_log 文本的解码对象。所有校验与重放都在隔离
        副本/恢复实例上进行，异常原样传播，成功或失败都不改变本解析器状态
        （区域、版本、历史、缓存、时钟、统计、上游配置与审计等）。输出
        顶层键序仅 "v","state","forward","log","result"：v 恒为 2；
        forward.version 为当前 dump_forward 版本号，history 按
        forward_versions 升序列键序 version,config 的保留快照（config 为
        migrate_forward 的规范 v1 对象，末项版本即 version、配置即当前
        生效配置），audit 为 forward_audit() 的解码对象；紧凑 ASCII
        JSON、末尾单换行，不超过 16777216 字节。封包交给 replay_bundle
        恢复重放后，其返回文本与本方法 result 段逐字节相同，且恢复解析器
        的 dump_forward、forward_versions、forward_audit 与本解析器导出
        时一致。同态同参逐字节一致。
        """
        if not isinstance(ops, list):
            raise TypeError("ops must be list")
        if not isinstance(now, int) or isinstance(now, bool):
            raise TypeError("now must be int")
        start = self._last_end if self._last_end is not None else 0
        if now < 0 or now < start:
            raise CacheError("now must be non-negative and monotonic")
        if not 1 <= len(ops) <= _MAX_REPLAY_OPS:
            raise ReplayError("ops must contain 1..4096 items")
        # 先以 export_log 同形构造 log 文本并经 export_log 在隔离副本上
        # 完整验证（结构预检、隔离执行与时钟契约）：ops 非法抛
        # ReplayError、操作异常与时钟 CacheError 原样传播，均不改变本
        # 解析器。log 对象直接取该文本的解码对象。
        log_text = self.export_log(ops, now)
        log_obj = json.loads(log_text)
        # state 为起始时刻 dump_state 的 v2 对象：now 已通过同样的时钟
        # 校验（start==最后成功结束时刻），dump_state 只读；其自身超
        # 16MiB 的 ConfigError 即封包结果超限，归为 ReplayError（同
        # replay_log 对 dump_state 超限的处理）。
        try:
            state_text = self.dump_state(start)
        except ConfigError:
            raise ReplayError(
                "replay bundle result exceeds 16777216 bytes") from None
        state_obj = json.loads(state_text)
        # forward 为键序 version,history,audit 的 v2 包装（与
        # _bundle_v2_forward_obj 同一构造）：version 取 dump_forward
        # 版本号；history 按 forward_versions 升序列保留的规范化快照；
        # audit 取 forward_audit() 的解码对象。
        forward_obj = self._bundle_v2_forward_obj()
        # result 必须是“从前三者隔离恢复并重放”的结果：把三段重新紧凑
        # 序列化后走与 replay_bundle 完全相同的 v2 恢复路径（load_state 使
        # 权威缓存为空、按包装恢复版本/历史/审计），而非本解析器深拷贝
        # 重放；恢复路径内的 _check_bundle_v2_forward 同时完整校验本解析器
        # 导出的 version/history/audit 自洽（淘汰项不核内容），恢复实例仅
        # 存在于本次调用，不触碰本解析器。
        _recovered, out_text, forward_wrapper = (
            self._recover_bundle_resolver(state_text, 2, forward_obj,
                                          log_text))
        result_obj = json.loads(out_text)
        bundle = json.dumps(
            {"v": 2, "state": state_obj, "forward": forward_wrapper,
             "log": log_obj, "result": result_obj},
            ensure_ascii=True, separators=(",", ":")) + "\n"
        # 紧凑 ASCII 文本字节数与码点数一致；整封包超 16MiB 拒绝导出。
        if len(bundle) > _MAX_REPLAY_BUNDLE_LEN:
            raise ReplayError("replay bundle exceeds 16777216 bytes")
        return bundle

    def export_bundle_file(self, ops: list, now: int, path: str) -> int:
        """把 export_bundle(ops, now) 字节逐字节原子落盘，返回写入字节数。

        path 非 str 抛 TypeError；path 为空串或含 NUL 抛 ConfigError
        （沿用 save_state 的路径校验，先于封包内容校验）。随后完全复用
        export_bundle：ops、now 的 TypeError/CacheError/ReplayError 等
        异常原样传播，且 export_bundle 只读，任何失败与成功都不改变本
        解析器状态。落盘内容与 export_bundle(ops, now) 逐字节相同：在
        目标同目录创建唯一临时文件，循环 write 至全部字节写完（write
        返回 None、非 int 或非正数抛 OSError），flush、fsync 后以
        os.replace 原子替换目标。任一步 I/O 失败抛 OSError，删除本次
        临时文件、保留旧目标文件。同态同参逐字节一致；经
        replay_bundle_file 读回所得状态与结果和直接经 export_bundle、
        replay_bundle 两入口完全相同。
        """
        if not isinstance(path, str):
            raise TypeError("path must be str")
        if path == "" or "\x00" in path:
            raise ConfigError("path must be non-empty and without NUL")
        # export_bundle 只读且先于任何文件操作完成：其 TypeError/
        # CacheError/ReplayError 原样传播，此时尚无临时文件。
        data = self.export_bundle(ops, now).encode("ascii")
        # 原子落盘与 save_state、export_log 共用同一路径：同目录临时
        # 文件、循环写、flush、fsync 后 os.replace；失败删除临时项、
        # 保留旧目标。
        _atomic_write_file(path, data, ".dns-bundle-")
        return len(data)

    @classmethod
    def replay_bundle_file(cls, path: str) -> "tuple[Resolver, str]":
        """从封包文件隔离恢复并重放（协议完全复用 replay_bundle）。

        path 非 str 抛 TypeError；path 为空串或含 NUL 抛 ConfigError
        （沿用 load_state_file 的路径校验）。最多读取 16777217 字节：
        文件缺失抛 FileNotFoundError，其余 I/O 错抛 OSError（均沿用
        load_state_file）；内容超过 16777216 字节或含非 ASCII 字节抛
        ReplayError。解码后完全复用 replay_bundle：封包格式校验、
        异常归类、隔离恢复与重放、result 逐字节比对均与其一致，任何
        失败都不产生实例。读取时间与空间均为 O(文件长度)，上限
        16777216 字节；仅多读一字节即可判定超限，避免把超限文件整体
        读入内存。相同封包经本方法与 replay_bundle 所得解析器状态
        相同、返回文本逐字节一致。
        """
        if not isinstance(path, str):
            raise TypeError("path must be str")
        if path == "" or "\x00" in path:
            raise ConfigError("path must be non-empty and without NUL")
        # 缺失与 I/O 错原样传播（FileNotFoundError/OSError）；仅多读
        # 一字节即可判定超限，避免把超限文件整体读入内存。
        with open(path, "rb") as stream:
            data = stream.read(_MAX_REPLAY_BUNDLE_LEN + 1)
        if len(data) > _MAX_REPLAY_BUNDLE_LEN:
            raise ReplayError("bundle file exceeds 16777216 bytes")
        if not data.isascii():
            raise ReplayError("bundle file must be ASCII")
        # 解码后的全部协议、异常、隔离恢复与比对均复用 replay_bundle。
        return cls.replay_bundle(data.decode("ascii"))

    def reload_bundle_file(self, path: str, expected: int) -> str:
        """带修订号检查地从封包文件原子接管整解析器状态，返回 version,result。

        path 非 str 或 expected 非 int（含 bool）抛 TypeError；path 为空
        串或含 NUL、expected 为负抛 ConfigError。验参后先比较 expected 与
        当前区域修订号：不相等时不得打开文件，报告 conflict（version 为
        当前修订号），不改变任何状态。相等时调用 replay_bundle_file(path)
        隔离恢复并重放，其 16MiB 读取上限、ASCII 与封包校验、异常归类
        （FileNotFoundError/OSError/ReplayError 及 state、forward 语义
        异常等）全部原样沿用；恢复与重放均在隔离实例上进行，本解析器不
        变。候选修订号小于当前修订号抛 ConfigError；候选最后成功结束
        时刻早于当前最后成功结束时刻（未设视为 0）抛 CacheError。全部
        通过后一次性以候选的区域历史及修订号、权威与递归缓存/FIFO、时钟、
        全部统计、上游配置历史及审计替换当前对应状态（整份 __dict__
        提交，含 plan、timeout、attempts、forward 版本、rated 与逐上游
        计数等），提交后后续公开调用须与直接使用候选实例一致；冲突外的
        任何异常均不改变原实例。报告键序仅 version,result（version 为
        操作后非负修订号，result 仅 "applied" 或 "conflict"），紧凑
        ASCII JSON、十进制整数、末尾单换行。同状态同文件逐字节一致；
        读取与候选恢复的时间及额外空间为 O(文件长度+操作数)。
        """
        if not isinstance(path, str):
            raise TypeError("path must be str")
        if not isinstance(expected, int) or isinstance(expected, bool):
            raise TypeError("expected must be int")
        if path == "" or "\x00" in path:
            raise ConfigError("path must be non-empty and without NUL")
        if expected < 0:
            raise ConfigError("expected revision must be non-negative")
        # 冲突不打开文件：任何文件访问都必须在修订号检查之后。
        if expected != self._revision:
            return self._tx_report(self._revision, "conflict")
        # 隔离恢复并重放：replay_bundle_file 的 16MiB 读取上限、校验与
        # 全部异常原样沿用；任何失败都只产生（或不产生）局部候选，原
        # 实例不受影响。
        candidate, _out_text = Resolver.replay_bundle_file(path)
        # 只允许接管到不回退的修订号；候选号更旧一律拒绝。
        if candidate._revision < self._revision:
            raise ConfigError("bundle revision must not be less than current")
        current_last = self._last_end if self._last_end is not None else 0
        candidate_last = (candidate._last_end
                          if candidate._last_end is not None else 0)
        # 时钟不得回退：候选最后成功结束时刻早于当前（未设视为 0）拒绝。
        if candidate_last < current_last:
            raise CacheError("bundle clock must not be earlier than current")
        # 全部校验通过后一次性原子接管：候选整份状态（区域历史与修订号、
        # 权威与递归缓存/FIFO、时钟、全部统计、上游配置历史及审计等）替换
        # 当前对应状态，使后续公开调用与直接使用候选一致。
        self.__dict__.update(candidate.__dict__)
        return self._tx_report(self._revision, "applied")

    def rated_stats(self, reset: bool = False) -> str:
        """返回 resolve_rated 的确定性统计（键序 o,e,l，末尾单换行）。

        输出为仅含键序 o,e,l 的紧凑 ASCII JSON，值为非负十进制整数
        数组。o 四项依次计 policy 拒绝、query-rate 拒绝、response-rate
        拒绝与响应放行；e 两项依次计查询放行后 resolve 异常、解析成功
        后 limiter.respond 异常；l 四项按实际上游耗时 0、1..timeout、
        timeout+1..2*timeout、>2*timeout 分桶（权威、缓存及未访问上游
        不计）。reset 非 bool 抛 TypeError 且状态不变；False 只读，
        重复调用逐字节相同；True 先返回旧快照再清零十项计数，其余
        状态与 stats() 不变。
        """
        if not isinstance(reset, bool):
            raise TypeError("reset must be bool")
        text = (
            '{"o":[' + ",".join(map(str, self._rated_o)) + "]"
            + ',"e":[' + ",".join(map(str, self._rated_e)) + "]"
            + ',"l":[' + ",".join(map(str, self._rated_l)) + "]}\n"
        )
        if reset:
            # 先返回重置前快照，再清零十项计数；其余状态与 stats 均保留。
            self._rated_o = [0, 0, 0, 0]
            self._rated_e = [0, 0]
            self._rated_l = [0, 0, 0, 0]
        return text


def _validate_replay_levels(levels):
    """校验 replay recursive 的 levels（JSON 形态）并转换为递归计划元组。

    1–16 层，每层 1–16 个键序 name,events 的对象；name 为非空 str，
    events 为事件数组；每个事件键序 delay,reply：delay 为非负非 bool
    整数，reply 为 null 或键序 kind,an,ns 的对象；kind 为 0..3 的非
    bool 整数，an/ns 为 RR 数组；RR 键序 name,type,class,ttl,rdata，
    rdata 为偶长小写十六进制，其余沿用现有 RR 契约。任何键序、字段
    类型/范围、十六进制形式或层级组合错误统一抛 ReplayError。返回
    resolve_recursive 入参契约的逐层元组计划（reply 为 None 或
    (kind, an, ns) 原始形态，rdata 为 bytes），其语义校验复用
    _validate_levels 仅用于提前把关、结果丢弃；执行时 resolve_recursive
    会在该元组形态上再校验一次（该校验非幂等，故不得回传规范化结果）。
    """
    def replay_rr(rr):
        if not isinstance(rr, dict) or list(rr.keys()) != _RR_KEYS:
            raise ReplayError("rr keys must be name,type,class,ttl,rdata")
        rdata = rr["rdata"]
        if not isinstance(rdata, str):
            raise ReplayError("rdata must be str")
        if (len(rdata) % 2
                or any(c not in _LOWER_HEXDIGITS for c in rdata)):
            raise ReplayError("rdata must be even-length lowercase hex")
        # 其余字段（name/type/class/ttl 及范围）由 _validate_levels 按
        # 现有 RR 契约校验，这里仅把十六进制 rdata 转换为 bytes。
        return {"name": rr["name"], "type": rr["type"],
                "class": rr["class"], "ttl": rr["ttl"],
                "rdata": bytes.fromhex(rdata)}

    def replay_reply(reply):
        if reply is None:
            return None
        if not isinstance(reply, dict) or list(reply.keys()) != _REPLAY_REPLY_KEYS:
            raise ReplayError("reply keys must be kind,an,ns")
        kind = reply["kind"]
        if not isinstance(kind, int) or isinstance(kind, bool):
            raise ReplayError("kind must be int")
        an = reply["an"]
        ns = reply["ns"]
        if not isinstance(an, list) or not isinstance(ns, list):
            raise ReplayError("an and ns must be list")
        # 保持 resolve_recursive 的原始 (kind, an, ns) 三元组契约。
        return (kind, [replay_rr(rr) for rr in an],
                [replay_rr(rr) for rr in ns])

    if not isinstance(levels, list):
        raise ReplayError("levels must be list")
    if not 1 <= len(levels) <= _MAX_RECURSION_LEVELS:
        raise ReplayError("levels must contain 1..16 plans")
    converted = []
    for level in levels:
        if not isinstance(level, list):
            raise ReplayError("plan must be list")
        if not 1 <= len(level) <= _MAX_PLAN_ITEMS:
            raise ReplayError("plan must contain 1..16 items")
        items = []
        for item in level:
            if (not isinstance(item, dict)
                    or list(item.keys()) != _REPLAY_LEVEL_KEYS):
                raise ReplayError("plan item keys must be name,events")
            name = item["name"]
            if not isinstance(name, str) or not name:
                raise ReplayError("name must be a non-empty str")
            events = item["events"]
            if not isinstance(events, list):
                raise ReplayError("events must be list")
            checked_events = []
            for event in events:
                if (not isinstance(event, dict)
                        or list(event.keys()) != _REPLAY_EVENT_KEYS):
                    raise ReplayError("event keys must be delay,reply")
                delay = event["delay"]
                if (not isinstance(delay, int) or isinstance(delay, bool)
                        or delay < 0):
                    raise ReplayError("delay must be a non-negative int")
                checked_events.append((delay, replay_reply(event["reply"])))
            items.append((name, checked_events))
        converted.append(items)
    try:
        # 完整语义校验（kind 范围、kind/an/ns 组合、RR 字段范围等）在此
        # 收口，确保层级组合错误在创建 Resolver 前即抛 ReplayError；
        # 规范化结果丢弃，回传原始元组形态供执行时再校验。
        _validate_levels(converted)
    except (TypeError, ValueError) as exc:
        raise ReplayError(str(exc)) from None
    return converted


def _validate_ops(ops):
    """校验回放操作序列，返回 [(kind, op, plans), ...]（不执行）。

    reload 键序 op,text 且 op 为 "reload"、text 为 str；reload_tx 键序
    op,text,expected 且 op 为 "reload_tx"、text 为 str、expected 为非负
    非 bool int；reload_serial 键序 op,text,expected,force 且 op 为
    "reload_serial"，text 为 1..1048576 码点的 str，expected 同
    reload_tx，force 为 bool；migrate 键序 op,text 且 op 为 "migrate"，text 为
    1..1048576 码点的 str；migrate_tx 键序 op,text,expected 且 op 为
    "migrate_tx"，text 长度同 migrate，expected 同 reload_tx；
    restore_zones 键序 op,text,expected 且 op 为 "restore_zones"，
    text 长度同 migrate，expected 同 reload_tx；resolve
    键序 op,query,now,limit 且 op 为 "resolve"、query 为偶长小写十六
    进制、now/limit 为非 bool int；transfer 键序
    op,from_serial,limit 且 op 为 "transfer"、from_serial 为 uint32
    非 bool int、limit 为 1..65535 非 bool int；recursive 键序
    op,query,levels,now,limit 且 op 为 "recursive"，query 为偶长小写
    十六进制，now/limit 为非 bool int，levels 经
    _validate_replay_levels 校验并转换（非 recursive 项 plans 为 None）；
    rollback_batch 键序 op,expected,steps 且 op 为 "rollback_batch"、
    expected 为非负非 bool int、steps 含 1..32 项，项键序 op,text 的
    "reload"（text 为 1..1048576 码点的 str）或键序 op,target 的
    "rollback"（target 为非负非 bool int）；rollback 键序
    op,target,expected 且 op 为 "rollback"，target/expected 为非负非
    bool int；update 键序 op,changes,serial,expected 且 op 为 "update"，
    changes 为 1..256 项（项键序 op,record，op 为 "add"/"delete"，record
    键序 name,type,class,ttl,rdata，rdata 为偶长小写十六进制并在校验时
    转为 bytes，记录语义同 zone.records 契约且不得为 SOA），serial 为
    uint32 非 bool int，expected 为非负非 bool int（非 update 项第三元
    为 None，update 项第三元为转换后的 changes）。cache_stats 键序
    op,now,reset 且 op 为 "cache_stats"、now 为非负非 bool int、reset
    为 bool。
    ops 非 list 抛 TypeError；ops 超 4096 项及项、键序、op 名或字段类型
    /内容错误均抛 ReplayError。
    """
    if not isinstance(ops, list):
        raise TypeError("ops must be list")
    if len(ops) > _MAX_REPLAY_OPS:
        raise ReplayError("ops must contain 0..4096 items")
    checked = []
    for op in ops:
        if not isinstance(op, dict):
            raise ReplayError("op must be dict")
        keys = list(op.keys())
        if keys == _REPLAY_RELOAD_KEYS:
            valid_names = ("reload", "migrate")
        elif keys == _REPLAY_RELOAD_TX_KEYS:
            valid_names = ("reload_tx", "migrate_tx", "restore_zones")
        elif keys == _REPLAY_RELOAD_SERIAL_KEYS:
            valid_names = ("reload_serial",)
        elif keys == _REPLAY_RESOLVE_KEYS:
            valid_names = ("resolve",)
        elif keys == _REPLAY_TRANSFER_KEYS:
            valid_names = ("transfer",)
        elif keys == _REPLAY_RECURSIVE_KEYS:
            valid_names = ("recursive",)
        elif keys == _REPLAY_ROLLBACK_BATCH_KEYS:
            valid_names = ("rollback_batch",)
        elif keys == _REPLAY_ROLLBACK_TX_KEYS:
            valid_names = ("rollback",)
        elif keys == _REPLAY_UPDATE_KEYS:
            valid_names = ("update",)
        elif keys == _REPLAY_RESOLVER_CACHE_STATS_KEYS:
            valid_names = ("cache_stats",)
        else:
            raise ReplayError(
                "op keys must be op,text, op,text,expected,"
                " op,text,expected,force, op,query,now,limit,"
                " op,from_serial,limit,"
                " op,query,levels,now,limit,"
                " op,expected,steps, op,target,expected,"
                " op,changes,serial,expected or op,now,reset")
        if not isinstance(op["op"], str):
            raise ReplayError("op must be str")
        if op["op"] not in valid_names:
            raise ReplayError("op name does not match op keys")
        kind = op["op"]
        plans = None
        if kind == "rollback":
            target = op["target"]
            if (not isinstance(target, int) or isinstance(target, bool)
                    or target < 0):
                raise ReplayError("target must be a non-negative int")
            expected = op["expected"]
            if (not isinstance(expected, int) or isinstance(expected, bool)
                    or expected < 0):
                raise ReplayError("expected must be a non-negative int")
        elif kind == "rollback_batch":
            steps = op["steps"]
            if not isinstance(steps, list):
                raise ReplayError("steps must be list")
            if not 1 <= len(steps) <= _MAX_ROLLBACK_BATCH_STEPS:
                raise ReplayError("steps must contain 1..32 items")
            for step in steps:
                if not isinstance(step, dict):
                    raise ReplayError("step must be dict")
                step_keys = list(step.keys())
                if step_keys == _REPLAY_RELOAD_KEYS:
                    if step["op"] != "reload":
                        raise ReplayError("step op must be reload")
                    text = step["text"]
                    if not isinstance(text, str):
                        raise ReplayError("text must be str")
                    # len() 按 Unicode 码点计数；配置文本不得为空。
                    if not 1 <= len(text) <= _MAX_MIGRATE_TEXT_LEN:
                        raise ReplayError(
                            "text must contain 1..1048576 code points")
                elif step_keys == _REPLAY_ROLLBACK_STEP_KEYS:
                    if step["op"] != "rollback":
                        raise ReplayError("step op must be rollback")
                    target = step["target"]
                    if (not isinstance(target, int)
                            or isinstance(target, bool) or target < 0):
                        raise ReplayError("target must be a non-negative int")
                else:
                    raise ReplayError(
                        "step keys must be op,text or op,target")
            expected = op["expected"]
            if (not isinstance(expected, int) or isinstance(expected, bool)
                    or expected < 0):
                raise ReplayError("expected must be a non-negative int")
        elif kind == "transfer":
            from_serial = op["from_serial"]
            if (not isinstance(from_serial, int)
                    or isinstance(from_serial, bool)):
                raise ReplayError("from_serial must be int")
            if not 0 <= from_serial <= _MAX_TTL:
                raise ReplayError("from_serial out of range")
            limit = op["limit"]
            if not isinstance(limit, int) or isinstance(limit, bool):
                raise ReplayError("limit must be int")
            if not _MIN_TRANSFER_LIMIT <= limit <= _MAX_TRANSFER_LIMIT:
                raise ReplayError("limit out of range")
        elif kind in ("resolve", "recursive"):
            query = op["query"]
            if not isinstance(query, str):
                raise ReplayError("query must be str")
            if (len(query) % 2
                    or any(c not in _LOWER_HEXDIGITS for c in query)):
                raise ReplayError(
                    "query must be even-length lowercase hex")
            if kind == "recursive":
                plans = _validate_replay_levels(op["levels"])
            if not isinstance(op["now"], int) or isinstance(op["now"], bool):
                raise ReplayError("now must be int")
            if not isinstance(op["limit"], int) or isinstance(op["limit"], bool):
                raise ReplayError("limit must be int")
        elif kind == "update":
            changes = op["changes"]
            if not isinstance(changes, list):
                raise ReplayError("changes must be list")
            if not 1 <= len(changes) <= _MAX_UPDATE_CHANGES:
                raise ReplayError("changes must contain 1..256 items")
            serial = op["serial"]
            if not isinstance(serial, int) or isinstance(serial, bool):
                raise ReplayError("serial must be int")
            if not 0 <= serial <= _MAX_TTL:
                raise ReplayError("serial out of range")
            expected = op["expected"]
            if (not isinstance(expected, int) or isinstance(expected, bool)
                    or expected < 0):
                raise ReplayError("expected must be a non-negative int")
            # 记录语义（zone.records 契约、SOA 禁令、CNAME rdata）与十六
            # 进制形式在此收口，非法即在创建 Resolver 前抛 ReplayError；
            # rdata 转为 bytes 后的 changes 经第三元回传，in 仍记录原文。
            converted = []
            for change in changes:
                if not isinstance(change, dict):
                    raise ReplayError("change must be dict")
                if list(change.keys()) != _UPDATE_CHANGE_KEYS:
                    raise ReplayError("change keys must be op,record")
                change_op = change["op"]
                if not isinstance(change_op, str):
                    raise ReplayError("op must be str")
                if change_op not in _UPDATE_OPS:
                    raise ReplayError("op must be add or delete")
                record = change["record"]
                if (not isinstance(record, dict)
                        or list(record.keys()) != _RR_KEYS):
                    raise ReplayError(
                        "record keys must be name,type,class,ttl,rdata")
                rdata = record["rdata"]
                if not isinstance(rdata, str):
                    raise ReplayError("rdata must be str")
                if (len(rdata) % 2
                        or any(c not in _LOWER_HEXDIGITS for c in rdata)):
                    raise ReplayError(
                        "rdata must be even-length lowercase hex")
                candidate = {"name": record["name"], "type": record["type"],
                             "class": record["class"], "ttl": record["ttl"],
                             "rdata": bytes.fromhex(rdata)}
                try:
                    _validate_rr(candidate, allow_wildcard=True)
                except (TypeError, ValueError) as exc:
                    raise ReplayError(str(exc)) from None
                if candidate["type"] == _TYPE_SOA:
                    raise ReplayError("change record must not be SOA")
                if candidate["type"] == _TYPE_CNAME:
                    try:
                        _decode_cname_target(candidate["rdata"])
                    except RecordError as exc:
                        raise ReplayError(str(exc)) from None
                converted.append({"op": change_op, "record": candidate})
            plans = converted
        elif kind == "cache_stats":
            now = op["now"]
            if not isinstance(now, int) or isinstance(now, bool) or now < 0:
                raise ReplayError("now must be a non-negative int")
            if not isinstance(op["reset"], bool):
                raise ReplayError("reset must be bool")
        else:
            if not isinstance(op["text"], str):
                raise ReplayError("text must be str")
            if kind in ("migrate", "migrate_tx", "restore_zones",
                        "reload_serial"):
                # len() 按 Unicode 码点计数；配置文本不得为空。
                if not 1 <= len(op["text"]) <= _MAX_MIGRATE_TEXT_LEN:
                    raise ReplayError(
                        "text must contain 1..1048576 code points")
            if kind in ("reload_tx", "migrate_tx", "restore_zones",
                        "reload_serial"):
                expected = op["expected"]
                if not isinstance(expected, int) or isinstance(expected, bool):
                    raise ReplayError("expected must be int")
                if expected < 0:
                    raise ReplayError("expected must be non-negative")
            if kind == "reload_serial":
                if not isinstance(op["force"], bool):
                    raise ReplayError("force must be bool")
        checked.append((kind, op, plans))
    return checked


def _execute_replay_op(resolver, kind, op, plans):
    """在 resolver 上执行单个已预检的回放操作，返回 out 记录。

    异常原样传播（调用方决定记录或放弃）；out 各形态的键序与
    replay/replay_log 的记录契约一致。
    """
    if kind == "reload":
        revision = resolver.reload_zone(op["text"])
        return {"ok": True, "revision": revision}
    if kind == "reload_tx":
        report = json.loads(
            resolver.reload_zone_tx(op["text"], op["expected"]))
        return {"ok": True, "version": report["version"],
                "result": report["result"]}
    if kind == "reload_serial":
        report = json.loads(
            resolver.reload_zone_serial_tx(
                op["text"], op["expected"], op["force"]))
        return {"ok": True, "version": report["version"],
                "result": report["result"], "serial": report["serial"]}
    if kind == "migrate":
        return {"ok": True, "text": migrate_zone(op["text"])}
    if kind == "migrate_tx":
        if op["expected"] != resolver._revision:
            # 冲突：不解析 text，version 为当前修订号，text 为 null。
            return {"ok": True, "version": resolver._revision,
                    "result": "conflict", "text": None}
        # 相等：先迁移校验，再按 reload_zone_tx 原子换区；
        # 迁移失败或换区失败都不产生状态副作用。
        migrated = migrate_zone(op["text"])
        report = json.loads(
            resolver.reload_zone_tx(migrated, op["expected"]))
        return {"ok": True, "version": report["version"],
                "result": report["result"], "text": migrated}
    if kind == "restore_zones":
        if op["expected"] != resolver._revision:
            # 冲突：不解析 text，version 为当前修订号。
            return {"ok": True, "version": resolver._revision,
                    "result": "conflict"}
        # 相等：按 load_zones（schema 0/1 历史）校验整份
        # 快照并构造候选；失败原样抛异常且无任何状态副作用。
        candidate = Resolver.load_zones(
            op["text"], resolver._plan, resolver._timeout)
        if candidate.dump_zones() == resolver.dump_zones():
            # 规范化结果与当前一致：不换区、不改版本。
            return {"ok": True, "version": resolver._revision,
                    "result": "unchanged"}
        if candidate._revision <= resolver._revision:
            raise ConfigError(
                "text version must be greater than current")
        # 原子提交：区域、历史与修订号一并替换，权威缓存
        # 随候选清空；递归缓存、时钟、plan 与统计保留。
        resolver._cache = candidate._cache
        resolver._revision = candidate._revision
        resolver._zone_history = candidate._zone_history
        return {"ok": True, "version": resolver._revision,
                "result": "applied"}
    if kind == "resolve":
        response, source, end, hit = resolver.resolve(
            bytes.fromhex(op["query"]), op["now"], op["limit"])
        return {"ok": True, "response": response.hex(),
                "source": source, "end": end, "hit": hit}
    if kind == "transfer":
        report = json.loads(
            resolver.transfer_zone(op["from_serial"], op["limit"]))
        return {"ok": True, "version": report["version"],
                "serial": report["serial"], "mode": report["mode"],
                "delete": report["delete"], "add": report["add"]}
    if kind == "rollback":
        report = json.loads(
            resolver.rollback_zone_tx(op["target"], op["expected"]))
        return {"ok": True, "version": report["version"],
                "result": report["result"], "target": report["target"]}
    if kind == "rollback_batch":
        steps = [("reload", step["text"])
                 if step["op"] == "reload"
                 else ("rollback", step["target"])
                 for step in op["steps"]]
        result_name, version, index = resolver._rollback_batch(
            op["expected"], steps)
        return {"ok": True, "version": version,
                "result": result_name, "index": index}
    if kind == "update":
        report = json.loads(
            resolver.update_zone_tx(plans, op["serial"],
                                    op["expected"]))
        return {"ok": True, "version": report["version"],
                "result": report["result"],
                "serial": report["serial"]}
    if kind == "cache_stats":
        snapshot = resolver.cache_stats(op["now"], op["reset"])
        return {"ok": True, "snapshot": snapshot}
    response, source, end, hit = resolver.resolve_recursive(
        bytes.fromhex(op["query"]), plans,
        op["now"], op["limit"])
    return {"ok": True, "response": response.hex(),
            "source": source, "end": end, "hit": hit}


def replay(zone: dict, plan: list, ops: list, expected=None,
           timeout: int = 5) -> str:
    """在 Resolver 上依次回放 reload/reload_tx/reload_serial/migrate/
    migrate_tx/
    restore_zones/resolve/transfer/recursive/rollback/rollback_batch/update/
    cache_stats 操作，返回记录的紧凑 JSON。

    ops 非 list 或 expected 非 None/str 抛 TypeError；ops 限 0..4096 项，
    超量或操作项、键序、op 名或字段类型/内容错误（含 recursive 的 levels
    层级结构、RR 与十六进制形式、migrate/migrate_tx/restore_zones/
    reload_serial 的 text 码点长度、
    rollback 的 target/expected、rollback_batch 的 expected/steps 及其
    reload/rollback 步、update 的 changes/serial/expected 及其项结构、
    记录语义与十六进制、transfer 的 from_serial/limit、cache_stats 的
    now/reset、reload_serial 的 force）均在创建 Resolver 前
    抛 ReplayError；zone、plan、timeout 的校验与异常同 Resolver 构造。
    每项记录键序 in,out,stats：in 为操作原文，stats 为该操作后的
    stats() 原文。成功 out 首键 ok 为 true：reload 键序 ok,revision；
    reload_tx 键序 ok,version,result，result 为
    "applied"/"unchanged"/"conflict"；reload_serial 键序
    ok,version,result,serial，事务语义（applied/unchanged/stale/
    ambiguous/conflict、修订号与归档、候选序列号、冲突时 serial 为
    null、缓存与统计保留、非 applied 或异常不改状态）沿用
    reload_zone_serial_tx，version、result、serial 取报告值；migrate 键序 ok,text，text 为
    规范 v2 文本且不改变任何状态；migrate_tx 键序
    ok,version,result,text，先比较修订号，冲突时不解析 text，result
    为 "conflict" 且 text 为 null，相等时先迁移校验再按 reload_zone_tx
    原子换区，result 为 "applied"/"unchanged"，text 为规范 v2 文本
    （版本、缓存语义沿用 reload_zone_tx）；restore_zones 键序
    ok,version,result，先比较修订号，冲突时不解析 text，result 为
    "conflict"；相等时按 migrate_zones 与 load_zones 契约校验
    schema=0/1 历史并构造候选，候选规范化导出与当前 dump_zones()
    相同为 "unchanged"（状态不变），不同则候选 version 须大于当前
    修订号（违反抛 ConfigError），applied 原子替换区域、历史与修订
    号并清权威缓存，保留递归缓存、时钟、plan 与统计，其余结果或
    异常无副作用（后续操作可见已提交项）；resolve 与 recursive 键序
    ok,response,source,end,hit，response 为小写十六进制；transfer
    键序 ok,version,serial,mode,delete,add：调用
    Resolver.transfer_zone(from_serial,limit)，五值逐值取其报告，传送
    只读，前序暂存的变更对其可见，ZoneError 或 TransferError 记为
    out 键序 ok,error 的 false 与类名并继续；rollback 键序
    ok,version,result,target，先比较修订号，版本不符为 conflict 且不查
    历史，target 为当前版为 unchanged、未保留为 missing、命中为
    applied，状态副作用沿用 rollback_zone_tx（后续操作观察其提交）；
    rollback_batch 键序 ok,version,result,index，result 为 "conflict"/
    "missing"/"unchanged"/"applied"：expected 不等于当前修订号即冲突且
    不解析任何 text（index 为 -1）；相符时在隔离状态依序执行各步，各步
    用暂存修订号，rollback 可指向批内新修订，步骤异常或目标 missing
    放弃整批（index 为 zero-based 步下标），完成后含 applied 步结果为
    "applied"、否则 "unchanged"（index 为 steps 长度）；version 为提交
    后修订号，未提交取原修订号。放弃整批保留区域、版本、历史、权威与
    递归缓存、时钟及统计。update 键序 ok,version,result,serial：changes
    的 rdata 在校验时已转为 bytes，事务语义（conflict/stale/unchanged/
    applied、修订号与归档、缓存与统计保留）沿用 update_zone_tx，version
    与 result 取报告值，serial 为入参原值。cache_stats 键序
    ok,snapshot：调用 Resolver.cache_stats(now,reset)，snapshot 为返回
    原文（含末尾换行），reset=True 清零对后续操作可见。操作抛出的异常
    记为 out 键序 ok,error（false 与异常类名）并继续后续操作，状态语义
    沿用各操作（失败不改变任何状态）。输出为紧凑 ASCII JSON，顶层键序
    version,ops，version 为 1，末尾单换行。结果上限 16777216 字节，
    超限抛 ReplayError 且不比较 expected；expected 为 None 时仅记录；
    为 str 时与输出整体逐字节比较，不一致抛 ReplayError。
    """
    if expected is not None and not isinstance(expected, str):
        raise TypeError("expected must be str or None")
    # 全部操作（含 recursive 的 levels）校验、转换在创建 Resolver 前完成。
    checked = _validate_ops(ops)
    resolver = Resolver(zone, plan, timeout)
    items = []
    for kind, op, plans in checked:
        try:
            out = _execute_replay_op(resolver, kind, op, plans)
        except Exception as exc:
            out = {"ok": False, "error": type(exc).__name__}
        items.append({"in": op, "out": out, "stats": resolver.stats()})
    result = json.dumps({"version": 1, "ops": items},
                        ensure_ascii=True, separators=(",", ":")) + "\n"
    if len(result) > _MAX_REPLAY_RESULT_BYTES:
        raise ReplayError("replay result exceeds 16777216 bytes")
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
                normalized = _labels_to_name(
                    _normalize_origin_name(name), wildcard=False)
            except RecordError as exc:
                raise PolicyError(str(exc)) from None
            if normalized != name:
                raise PolicyError(
                    "name must be a canonical escaped absolute name")
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
    decode_query，非单问题（QDCOUNT=0 且 ANCOUNT/NSCOUNT/ARCOUNT
    全为 0，或问题数非 1）或 QR 置位抛 EncodeError。
    规则全部校验通过后才解码 query 并匹配；不修改任何入参。
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
    if (_MIN_MESSAGE_LEN <= len(query) <= _MAX_MESSAGE_LEN
            and not int.from_bytes(query[4:6], "big")
            and not int.from_bytes(query[6:12], "big")):
        # QDCOUNT=0 且 ANCOUNT/NSCOUNT/ARCOUNT 全为 0 属"非单问题"而非
        # 解码错误：按契约抛 EncodeError；任一区段非零时留给
        # decode_query 抛 MessageError。
        raise EncodeError("query must contain exactly one question")
    msg = decode_query(query)
    if msg["flags"] & _FLAG_QR:
        raise EncodeError("query has QR set")
    if len(msg["questions"]) != 1:
        raise EncodeError("query must contain exactly one question")
    qname = msg["questions"][0]["name"]
    qtype = msg["questions"][0]["type"]
    qlabels = tuple(_normalize_name(qname))
    for net_kind, net, name, rule_type, is_allow in checked:
        if net_kind == "net" and addr not in net:
            continue
        # 名称按线格式逐字节比较（仅 ASCII 字母大小写不敏感，由双方
        # 规范化折叠）：规则名允许规范转义拼写，qname 可能为查询解码的
        # 规范文本（含首标签单字节 "*" 的通配形态）。
        if name != "*" and tuple(_normalize_origin_name(name)) != qlabels:
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
                normalized = _labels_to_name(
                    _normalize_origin_name(name), wildcard=False)
            except RecordError as exc:
                raise PolicyError(str(exc)) from None
            if normalized != name:
                raise PolicyError(
                    "name must be a canonical escaped absolute name")
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


def _rate_rule_model(rule):
    """把规范化限流规则元组还原为构造器契约的 dict（键序固定）。

    client 为 "*" 或规范 CIDR 文本，type 为 None 或整数；还原结果可经
    _validate_rate_rules 原样通过，保证 dump/load 往返一致。
    """
    net_kind, net, name, qtype, window, query_quota, response_quota = rule
    return {"client": "*" if net_kind == "*" else str(net),
            "name": name, "type": qtype, "window": window,
            "query": query_quota, "response": response_quota}


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

    respond(query, response, client, now, truncate=True) 按响应配额
    限流：query、client、now 的校验与异常沿用 allow，response 非
    bytes 或 truncate 非 bool 抛 TypeError，response 不符合 forward
    的合格应答判定抛 EncodeError；全部校验先于计数完成，随后仅调用
    一次 allow(query, client, now, "response")。放行返回
    (response, 余量)；拒绝且 truncate 为 False 返回 (None, 0)；
    拒绝且 truncate 为 True 返回 (tc, 0)，tc 的 ID 取 query、flags
    取 response 并置 TC、QDCOUNT=1、其余计数为 0、问题段逐字节取
    query[12:]。

    respond_edns(query, response, client, now, truncate=True) 是
    respond 的 EDNS 变体：query 须 QR=0、单问题且恰含一个合法 OPT
    （OPT 缺失、非法或尾随字节抛 EDNSError，QR 或问题数错抛
    EncodeError），response 须 QR=1、ID 与问题字节同 query 且恰有
    一个合法 OPT 为附加段末项（否则 EncodeError）；其余校验、计数
    （键忽略 OPT）与统计同 respond，仅计一次 response。放行返回
    (response, 余量)；拒绝且 truncate 为 False 返回 (None, 0)，
    否则返回 (tc, 0)：tc 的 ID 取 query、flags 取 response 并置
    TC、四段计数 1/0/0/1、问题段逐字节取 query 的问题字节，末项
    OPT 为未压缩根 owner、TYPE41、CLASS 与 TTL 取 response 的
    OPT、RDLENGTH=0。任何失败都不改变计数状态与入参。

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

    reload_rules(rules, expected) 带版本检查的原子规则热加载：版本
    初始为 0，expected 非 int 或 bool 抛 TypeError、负值抛
    PolicyError；先验 expected 再比版本，不等则不检查 rules 并报告
    "conflict"；相等时 rules 沿用构造器契约校验、规范化并深拷贝，
    与当前规范规则逐项相同报告 "unchanged"，否则替换、版本加 1 并
    报告 "applied"。applied 仅保留规则序号及规范化规则均未改变的
    计数键（计数与创建序保留），其余删除；时钟、全局创建序与 stats
    累计值不变。返回键序 version,result,kept,dropped 的紧凑 ASCII
    JSON（末尾单换行），kept/dropped 仅 applied 时为保留/删除数，
    否则均为 0。异常、conflict、unchanged 不改变任何状态。

    构造时的规范规则存为版本 0；每次 applied 热加载或回滚按新版本
    归档一份规范规则深拷贝，历史容量 32、超量淘汰最小版本，版本号
    单调递增、不复用。rollback_rules(target, expected) 带版本检查
    的原子规则回滚：target、expected 的校验与异常同 reload_rules
    的 expected；先比 expected，不等则不查询 target 并报告
    "conflict"；target 为当前版本或目标快照规范规则与当前逐项相同
    报告 "unchanged"，未保留（含已淘汰）报告 "missing"；否则恢复
    目标快照、版本加 1 并归档，报告 "applied"，计数键保留语义同
    reload_rules。返回键序 version,result,target,kept,dropped 的
    紧凑 ASCII JSON（末尾单换行），kept/dropped 仅 applied 时为
    保留/删除数，否则均为 0；非 applied 或异常不改变任何状态。

    dump() 把规则版本历史导出为 schema=1 的确定性配置文本（顶层键序
    schema,version,history，history 按版本升序，项键序
    version,rules；紧凑 ASCII JSON，末尾单换行），只读且同状态逐
    字节相同。load(text) 类方法从配置文本恢复实例：schema 为 0 或
    1（schema=0 的历史限 256 项，仅留最新 32 项；schema=1 限 32
    项），以末项为当前规则，版本取顶层 version 并继续递增，新实例
    计数为空、时钟未设、统计清零；text 非 str 抛 TypeError，解析、
    重复键、键序、schema、版本关系或空/超量历史抛 ConfigError，
    rules 的类型错抛 TypeError、数量/键序/值错抛 PolicyError，
    失败无副作用。
    """

    def __init__(self, rules: list):
        # 校验即构造全新的不可变元组列表，与外部对入参的后续改动隔离。
        self._rules = _validate_rate_rules(rules)
        self._version = 0  # 规则版本：初始为 0，每次 applied 热加载/回滚加 1
        # 规范规则历史：版本 -> 规范规则深拷贝。构造时存版本 0，之后仅在
        # applied 热加载或回滚时按新版本归档；容量 32，超量淘汰最小版本，
        # 版本号单调递增、不复用。
        self._history = {0: copy.deepcopy(self._rules)}
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
        qlabels = tuple(_normalize_name(qname))
        matched = None
        for index, (net_kind, net, name, rule_type, window,
                    query_quota, response_quota) in enumerate(self._rules):
            if net_kind == "net" and addr not in net:
                continue
            # 名称按线格式逐字节比较，转义拼写不同但等价者视为同一键。
            if name != "*" and tuple(_normalize_origin_name(name)) != qlabels:
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

    def respond(self, query: bytes, response: bytes, client: str, now: int,
                truncate: bool = True) -> tuple[bytes | None, int]:
        """按响应配额限流并给出应答报文。

        query、client、now 的校验与异常沿用 allow（kind 固定为
        "response"）；response 非 bytes 或 truncate 非 bool 抛
        TypeError；response 不符合 forward 的合格应答判定抛
        EncodeError。全部校验先于计数完成，任何失败都不改变计数、
        时钟与统计。校验通过后仅调用一次
        allow(query, client, now, "response")，首项匹配、固定窗、
        容量淘汰与统计提交均沿用 allow：放行返回 (response, 余量)；
        拒绝且 truncate 为 False 返回 (None, 0)；拒绝且 truncate 为
        True 返回 (tc, 0)，tc 的 ID 取 query，flags 取 response 并
        置 TC，QDCOUNT=1，ANCOUNT、NSCOUNT、ARCOUNT 均为 0，问题段
        逐字节取 query[12:]，不含 RR 或 OPT。同一状态和输入逐字节
        一致；一次 respond 仅提交一次 response 统计。
        """
        if not isinstance(query, bytes):
            raise TypeError("query must be bytes")
        if not isinstance(client, str):
            raise TypeError("client must be str")
        if not isinstance(now, int) or isinstance(now, bool):
            raise TypeError("now must be int")
        if not isinstance(response, bytes):
            raise TypeError("response must be bytes")
        if not isinstance(truncate, bool):
            raise TypeError("truncate must be bool")
        if now < 0 or (self._last_now is not None and now < self._last_now):
            raise CacheError("now must be non-negative and monotonic")
        # client 与 query 的校验顺序同 allow：先地址、后解码。
        try:
            ipaddress.ip_address(client)
        except (ValueError, TypeError):
            raise PolicyError("client must be an IP address") from None
        msg = decode_query(query)
        if msg["flags"] & _FLAG_QR:
            raise EncodeError("query has QR set")
        if len(msg["questions"]) != 1:
            raise EncodeError("query must contain exactly one question")
        if not _matching_reply(query, response):
            raise EncodeError("response is not a valid reply to query")
        # 全部校验已通过：仅调用一次 allow，统计随其成功返回提交一次。
        allowed, remaining = self.allow(query, client, now, "response")
        if allowed:
            return response, remaining
        if not truncate:
            return None, 0
        flags = int.from_bytes(response[2:4], "big") | _FLAG_TC
        tc = (query[0:2] + flags.to_bytes(2, "big")
              + (1).to_bytes(2, "big") + b"\x00\x00\x00\x00\x00\x00"
              + query[12:])
        return tc, 0

    def respond_edns(self, query: bytes, response: bytes, client: str,
                     now: int, truncate: bool = True,
                     ) -> tuple[bytes | None, int]:
        """按响应配额限流含 OPT 的查询与应答，返回应答报文与余量。

        query、client、now、response、truncate 的类型与值域校验及异常
        沿用 respond；query 须 QR=0、单问题且恰含一个合法 OPT：OPT
        缺失、非法或尾随字节抛 EDNSError（同 resolve_edns 的查询契
        约），QR 置位或问题数非 1 抛 EncodeError。response 须 QR=1、
        ID 与问题字节同 query，且全报文恰有一个合法 OPT 并为附加段
        末项（OPT 字段契约同查询），否则抛 EncodeError。全部校验先
        于计数完成，任何失败都不改变计数、时钟与统计。校验通过后仅
        计一次 response（同 allow(query, client, now, "response")
        的匹配、固定窗、容量淘汰与统计提交，计数键忽略 OPT）：放行
        返回 (response, 余量)；拒绝且 truncate 为 False 返回
        (None, 0)；拒绝且 truncate 为 True 返回 (tc, 0)，tc 的 ID
        取 query，flags 取 response 并置 TC，QDCOUNT=1、ANCOUNT=
        NSCOUNT=0、ARCOUNT=1，问题段逐字节取 query 的问题字节，末项
        OPT 为未压缩根 owner、TYPE41、CLASS 与 TTL 逐字节取
        response 的 OPT、RDLENGTH=0。同一状态和输入逐字节一致。
        """
        if not isinstance(query, bytes):
            raise TypeError("query must be bytes")
        if not isinstance(client, str):
            raise TypeError("client must be str")
        if not isinstance(now, int) or isinstance(now, bool):
            raise TypeError("now must be int")
        if not isinstance(response, bytes):
            raise TypeError("response must be bytes")
        if not isinstance(truncate, bool):
            raise TypeError("truncate must be bool")
        if now < 0 or (self._last_now is not None and now < self._last_now):
            raise CacheError("now must be non-negative and monotonic")
        # client 与 query 的校验顺序同 respond：先地址、后解码。
        try:
            ipaddress.ip_address(client)
        except (ValueError, TypeError):
            raise PolicyError("client must be an IP address") from None
        if not _MIN_MESSAGE_LEN <= len(query) <= _MAX_MESSAGE_LEN:
            raise EDNSError("bad message length")
        if int.from_bytes(query[2:4], "big") & _FLAG_QR:
            raise EncodeError("query has QR set")
        if int.from_bytes(query[4:6], "big") != 1:
            raise EncodeError("query must contain exactly one question")
        # EDNS 查询须恰含一个合法 OPT：OPT 缺失、非法或尾随字节均为
        # EDNSError（_decode_edns_query 的 OPT 契约）。
        _msg, opt = _decode_edns_query(query)
        if opt is None:
            raise EDNSError("query must contain exactly one OPT")
        opt_class, opt_ttl = _decode_edns_response(query, response)
        # 计数键只取问题段的 qname/qtype，与 OPT 无关：剥去 OPT 后沿用
        # allow 的匹配、固定窗、容量淘汰与统计，一次调用仅计一次
        # response。
        query_end = _reply_question_end(query, 1)
        plain = (query[0:10] + b"\x00\x00"
                 + query[_MIN_MESSAGE_LEN:query_end])
        allowed, remaining = self.allow(plain, client, now, "response")
        if allowed:
            return response, remaining
        if not truncate:
            return None, 0
        flags = int.from_bytes(response[2:4], "big") | _FLAG_TC
        tc = (query[0:2] + flags.to_bytes(2, "big")
              + (1).to_bytes(2, "big") + (0).to_bytes(2, "big")
              + (0).to_bytes(2, "big") + (1).to_bytes(2, "big")
              + query[_MIN_MESSAGE_LEN:query_end]
              + b"\x00" + _TYPE_OPT.to_bytes(2, "big")
              + opt_class.to_bytes(2, "big") + opt_ttl.to_bytes(4, "big")
              + (0).to_bytes(2, "big"))
        return tc, 0

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

    def reload_rules(self, rules: list, expected: int) -> str:
        """带版本检查的原子规则热加载，返回紧凑 ASCII JSON 报告。

        expected 非 int 或为 bool 抛 TypeError，负值抛 PolicyError；
        先校验 expected，再与当前版本比较：不等则不检查 rules，直接
        报告 "conflict"。相等时 rules 沿用构造器全部契约校验、规范化
        并深拷贝，异常与构造器一致；与当前规范规则逐项相同报告
        "unchanged"，否则原子替换规则、版本加 1、按新版本归档规范
        规则快照（历史容量 32，超量淘汰最小版本，版本不复用）并报告
        "applied"。
        applied 仅保留规则序号存在且该序号规范化规则逐项未改变的计数
        键（计数与创建序原样保留），其余删除；时钟、全局创建序与 stats
        累计值不变，keys 反映保留后的键数，容量仍为 4096。异常、
        conflict、unchanged 均不改变规则、历史、版本、计数、时钟与统计；
        调用后修改 rules 不影响实例。返回键序 version,result,kept,
        dropped 的紧凑 ASCII JSON（末尾单换行）：version 为操作后的
        整数版本，result 为 "applied"、"unchanged" 或 "conflict"，
        kept/dropped 仅 applied 时为保留/删除的计数键数，否则均为 0。
        相同状态与输入逐字节一致。
        """
        if not isinstance(expected, int) or isinstance(expected, bool):
            raise TypeError("expected must be int")
        if expected < 0:
            raise PolicyError("expected must be non-negative")
        kept = 0
        dropped = 0
        if expected != self._version:
            # 版本不符：不校验 rules，不改变任何状态。
            result = "conflict"
        else:
            # 校验、规范化与深拷贝同构造器契约，异常原样传播。
            new_rules = copy.deepcopy(_validate_rate_rules(rules))
            if new_rules == self._rules:
                result = "unchanged"
            else:
                # 规则序号在新旧规则中均存在且规范化规则逐项相同的计数键
                # 保留（计数与创建序不变），其余删除。
                old_rules = self._rules
                common = min(len(old_rules), len(new_rules))
                same = {index for index in range(common)
                        if old_rules[index] == new_rules[index]}
                counts = {}
                for key, value in self._counts.items():
                    if key[0] in same:
                        counts[key] = value
                        kept += 1
                    else:
                        dropped += 1
                self._counts = counts
                self._rules = new_rules
                self._version += 1
                self._archive_rules(self._version)
                result = "applied"
        return ('{"version":' + str(self._version)
                + ',"result":' + json.dumps(result)
                + ',"kept":' + str(kept)
                + ',"dropped":' + str(dropped) + "}\n")

    def _archive_rules(self, version):
        """按版本保存当前规范规则深拷贝；超容量 32 淘汰最小版本。

        归档仅在 applied 热加载或回滚提交时进行，版本号单调递增、不复用。
        """
        self._history[version] = copy.deepcopy(self._rules)
        if len(self._history) > _RATE_RULE_HISTORY_CAPACITY:
            oldest = min(self._history)
            del self._history[oldest]

    def rollback_rules(self, target: int, expected: int) -> str:
        """带版本检查的原子规则回滚，返回紧凑 ASCII JSON 报告。

        target、expected 非 int 或为 bool 抛 TypeError，负值抛
        PolicyError。两参数校验完成后先比较 expected：不等于当前版本
        时不查询 target，报告 "conflict"。相等且 target 为当前版本，
        或目标快照的规范规则与当前逐项相同，报告 "unchanged"；target
        未保留（含已淘汰）报告 "missing"。否则原子恢复目标快照、版本
        加 1 并按新版本归档，报告 "applied"。applied 仅保留规则序号
        存在且该序号规范化规则逐项未改变的计数键（计数与创建序原样
        保留），其余删除；时钟、全局创建序与 stats 累计值不变。非
        applied 结果或任何异常均不改变规则、历史、版本、计数、时钟
        与统计。返回键序 version,result,target,kept,dropped 的紧凑
        ASCII JSON（末尾单换行）：version 为操作后的整数版本，
        kept/dropped 仅 applied 时为保留/删除的计数键数，否则均为 0。
        相同状态与输入逐字节一致。
        """
        if not isinstance(target, int) or isinstance(target, bool):
            raise TypeError("target must be int")
        if not isinstance(expected, int) or isinstance(expected, bool):
            raise TypeError("expected must be int")
        if target < 0:
            raise PolicyError("target must be non-negative")
        if expected < 0:
            raise PolicyError("expected must be non-negative")
        kept = 0
        dropped = 0
        # 两参数校验完成后才比较 expected；冲突时不得查询 target。
        if expected != self._version:
            result = "conflict"
        elif target == self._version:
            result = "unchanged"
        else:
            snapshot = self._history.get(target)
            if snapshot is None:
                result = "missing"
            elif snapshot == self._rules:
                result = "unchanged"
            else:
                # 保留语义同 reload_rules：序号在新旧规则中均存在且规范
                # 化规则逐项相同的计数键保留（计数与创建序不变），其余删除。
                old_rules = self._rules
                common = min(len(old_rules), len(snapshot))
                same = {index for index in range(common)
                        if old_rules[index] == snapshot[index]}
                counts = {}
                for key, value in self._counts.items():
                    if key[0] in same:
                        counts[key] = value
                        kept += 1
                    else:
                        dropped += 1
                self._counts = counts
                self._rules = copy.deepcopy(snapshot)
                self._version += 1
                self._archive_rules(self._version)
                result = "applied"
        return ('{"version":' + str(self._version)
                + ',"result":' + json.dumps(result)
                + ',"target":' + str(target)
                + ',"kept":' + str(kept)
                + ',"dropped":' + str(dropped) + "}\n")

    def dump(self) -> str:
        """把规则版本历史导出为确定性配置文本（schema=1），只读。

        顶层键序仅 schema,version,history：schema 恒为 1，version 为
        当前规则版本；history 按版本严格升序，项键序仅 version,rules，
        rules 为构造器契约的规则数组（项键序
        client,name,type,window,query,response，type 为 null 或整数）。
        输出为紧凑 ASCII JSON、十进制整数、末尾单换行；不改变任何状态，
        同状态逐字节相同，load(dump()) 得到规则、版本与历史等价的实例。
        """
        history = []
        for version in sorted(self._history):
            history.append({
                "version": version,
                "rules": [_rate_rule_model(rule)
                          for rule in self._history[version]],
            })
        config = {"schema": 1, "version": self._version,
                  "history": history}
        return json.dumps(config, ensure_ascii=True,
                          separators=(",", ":")) + "\n"

    @classmethod
    def load(cls, text: str) -> "RateLimiter":
        """从 dump 配置文本恢复限流器实例。

        新实例以末项规则为当前规则，版本取顶层 version（之后继续递增），
        计数为空、时钟未设、统计清零。text 非 str 抛 TypeError；JSON
        解析、重复键、键序、schema、版本关系或空/超量历史抛
        ConfigError；rules 沿用构造器契约，字段类型错抛 TypeError，
        数量、键序或值错抛 PolicyError；失败无副作用。

        配置为 JSON 对象，顶层键序仅 schema,version,history：schema 为
        非 bool 整数 0 或 1，version 为非负非 bool 整数；history 项
        键序仅 version,rules，version 为严格递增的非负非 bool 整数且
        末项等于顶层 version。schema=0 的 history 限 1..256 项，仅留
        最新 32 项；schema=1 限 1..32 项。
        """
        if not isinstance(text, str):
            raise TypeError("text must be str")
        try:
            config = json.loads(text, object_pairs_hook=_config_pairs)
        except json.JSONDecodeError:
            raise ConfigError("invalid JSON") from None
        if not isinstance(config, dict):
            raise ConfigError("config must be an object")
        if list(config.keys()) != _RATE_CONFIG_KEYS:
            raise ConfigError("config keys must be schema,version,history")
        schema = config["schema"]
        if not isinstance(schema, int) or isinstance(schema, bool):
            raise ConfigError("schema must be int")
        if schema not in (0, 1):
            raise ConfigError("unsupported schema")
        version = config["version"]
        if not isinstance(version, int) or isinstance(version, bool):
            raise ConfigError("version must be int")
        if version < 0:
            raise ConfigError("version must be non-negative")
        history = config["history"]
        if not isinstance(history, list):
            raise ConfigError("history must be list")
        capacity = (_RATE_LOAD_HISTORY_LIMIT_V0 if schema == 0
                    else _RATE_RULE_HISTORY_CAPACITY)
        if not 1 <= len(history) <= capacity:
            raise ConfigError(
                "history must contain 1.." + str(capacity) + " items")
        # 结构层校验（键序、版本类型与严格递增、末项等于顶层值）全部
        # 先于 rules 契约校验完成，ConfigError 优先于 TypeError/PolicyError。
        versions = []
        for item in history:
            if not isinstance(item, dict):
                raise ConfigError("history item must be an object")
            if list(item.keys()) != _RATE_HISTORY_ITEM_KEYS:
                raise ConfigError("history item keys must be version,rules")
            item_version = item["version"]
            if (not isinstance(item_version, int)
                    or isinstance(item_version, bool)):
                raise ConfigError("history version must be int")
            if item_version < 0:
                raise ConfigError("history version must be non-negative")
            if versions and item_version <= versions[-1]:
                raise ConfigError(
                    "history versions must be strictly increasing")
            versions.append(item_version)
        if versions[-1] != version:
            raise ConfigError("last history version must equal version")
        # rules 沿用构造器契约：类型错抛 TypeError，数量、键序或值错抛
        # PolicyError；schema=0 仅留最新 32 项归档。
        parsed = [(item["version"], _validate_rate_rules(item["rules"]))
                  for item in history]
        kept = parsed[-_RATE_RULE_HISTORY_CAPACITY:]
        instance = cls.__new__(cls)
        instance._rules = copy.deepcopy(parsed[-1][1])
        instance._version = version
        instance._history = {
            item_version: copy.deepcopy(rules)
            for item_version, rules in kept}
        instance._counts = {}
        instance._serial = 0
        instance._last_now = None
        instance._stat = {
            "query": {"allow": 0, "deny": 0, "unmatched": 0},
            "response": {"allow": 0, "deny": 0, "unmatched": 0},
            "expired": 0,
            "evicted": 0,
        }
        return instance


class ResponseRateLimiter:
    """确定性固定窗响应速率限流器（含 slip 截断应答）。

    window、limit、slip 均为非 bool 整数：window 取 1..3600，limit 取
    1..65535，slip 取 0..65535；类型错抛 TypeError，越界抛 PolicyError。

    apply(query, response, client, now) 的入参校验与异常沿用
    RateLimiter.respond（query、client、now、response 的类型与 now 单调
    校验一致，client 须为字面 IP 地址，query 须 QR=0 的单问题报文，
    response 须为 query 的合格应答）；now 为负数或相对上次成功调用回退
    抛 CacheError。全部校验先于计数完成，任何失败都不改变计数状态、
    创建序与最后时钟。

    计数键为 (客户端网段, 规范 qname, qtype, rcode, 窗号)：client 归入
    IPv4 的 /24 或 IPv6 的 /56 网段（取规范网段文本），qname 为查询的
    小写绝对名，qtype 为问题类型，rcode 取 response flags 的低 4 位，
    窗号为 now // window。每次调用先删除窗截止时刻 <= now 的过期项，
    随后仅在成功调用时把该窗计数加一：计数未超过 limit 返回
    (response, "pass", limit - 计数)；已超限令超额序号
    n = 计数 - limit（首个超额为 1），slip > 0 且 n % slip == 0 时返回
    既有 respond 格式的截断应答 (tc, "slip", 0)，否则返回
    (None, "drop", 0)。计数表至多 4096 项：插入第 4097 个键前淘汰
    (窗截止时刻, 创建序) 最小项，单次调用开销为 O(4096)。相同初态与
    相同调用序列逐字节相同。

    stats(reset=False) 返回固定键序 pass,drop,slip,expired,evicted,
    keys,capacity 的紧凑 ASCII JSON（末尾一个换行）：值均为非负十进制
    整数，capacity 恒为 4096；pass/drop/slip 按成功 apply 的返回动作
    仅递增其一，expired/evicted 分别累加实际清除的过期键数与为插入新
    键实际淘汰的键数，keys 为提交后的活动键数。统计仅在 apply 成功
    返回后原子提交，构造时清零；任何校验失败或异常都不改变计数表、
    创建序、最后时钟与统计。reset 非 bool 抛 TypeError 且无变化；
    False 只读，重复读取逐字节相同；True 先返回重置前快照，再清零
    五个累计计数，保留活动键及其计数、创建序和最后时钟，后续 keys
    不清零。
    """

    def __init__(self, window: int, limit: int, slip: int = 2):
        _check_int(window, "window")
        _check_int(limit, "limit")
        _check_int(slip, "slip")
        if not _MIN_RATE_WINDOW <= window <= _MAX_RATE_WINDOW:
            raise PolicyError("window out of range")
        if not 1 <= limit <= _MAX_RATE_QUOTA:
            raise PolicyError("limit out of range")
        if not 0 <= slip <= _MAX_RATE_QUOTA:
            raise PolicyError("slip out of range")
        self._window = window
        self._limit = limit
        self._slip = slip
        # 计数键 -> [窗起始, 窗截止, 计数, 创建序]
        self._counts = {}
        self._serial = 0  # 创建序：随新窗计数项从 0 递增
        self._last_now = None  # 上次成功 apply 的时钟值
        # 统计：三种成功动作 pass/drop/slip 各计一次，expired/evicted 累加
        # 本次重置周期内实际删除的过期键数与容量淘汰键数。仅在 apply 成功
        # 返回后原子提交，构造时清零。
        self._stat = {"pass": 0, "drop": 0, "slip": 0,
                      "expired": 0, "evicted": 0}

    def apply(self, query: bytes, response: bytes, client: str, now: int
              ) -> tuple[bytes | None, str, int]:
        """按 (网段, qname, qtype, RCODE, 窗号) 固定窗限流单个应答。

        校验与异常顺序同 RateLimiter.respond；校验全部通过后先清过期窗，
        再令当前窗计数加一。未超 limit 返回 (response, "pass", 剩余)；
        超额按 slip 周期返回截断应答 (tc, "slip", 0) 或静默丢弃
        (None, "drop", 0)。任何校验失败都不改变计数与时钟。
        """
        if not isinstance(query, bytes):
            raise TypeError("query must be bytes")
        if not isinstance(client, str):
            raise TypeError("client must be str")
        if not isinstance(now, int) or isinstance(now, bool):
            raise TypeError("now must be int")
        if not isinstance(response, bytes):
            raise TypeError("response must be bytes")
        if now < 0 or (self._last_now is not None and now < self._last_now):
            raise CacheError("now must be non-negative and monotonic")
        # client 与 query 的校验顺序同 respond：先地址、后解码。
        try:
            addr = ipaddress.ip_address(client)
        except (ValueError, TypeError):
            raise PolicyError("client must be an IP address") from None
        msg = decode_query(query)
        if msg["flags"] & _FLAG_QR:
            raise EncodeError("query has QR set")
        if len(msg["questions"]) != 1:
            raise EncodeError("query must contain exactly one question")
        if not _matching_reply(query, response):
            raise EncodeError("response is not a valid reply to query")
        # 客户端归入 IPv4 /24 或 IPv6 /56 网段，取规范网段文本作为键。
        prefix = 24 if addr.version == 4 else 56
        subnet = str(ipaddress.ip_network(client).supernet(
            new_prefix=prefix))
        qname = msg["questions"][0]["name"]
        qtype = msg["questions"][0]["type"]
        rcode = int.from_bytes(response[2:4], "big") & 0x000F
        # 先删除当前已过期窗（截止时刻 <= now），再处理当前键。
        # 删除数先记为本次局部计数，待成功返回时与动作计数一并提交。
        expired = 0
        for dead in [key for key, value in self._counts.items()
                     if value[1] <= now]:
            del self._counts[dead]
            expired += 1
        bucket = now // self._window
        key = (subnet, qname, qtype, rcode, bucket)
        entry = self._counts.get(key)
        evicted = 0
        if entry is None:
            # 插入第 4097 个键前淘汰 (截止, 创建序) 最小项。
            if len(self._counts) >= _RATE_TABLE_CAPACITY:
                oldest = min(self._counts,
                             key=lambda k: (self._counts[k][1],
                                            self._counts[k][3]))
                del self._counts[oldest]
                evicted += 1
            self._counts[key] = [bucket * self._window,
                                 (bucket + 1) * self._window,
                                 0, self._serial]
            self._serial += 1
            entry = self._counts[key]
        # 成功调用：计数加一，统计原子提交，时钟随之推进。
        entry[2] += 1
        count = entry[2]
        self._stat["expired"] += expired
        self._stat["evicted"] += evicted
        if count <= self._limit:
            self._stat["pass"] += 1
            self._last_now = now
            return response, "pass", self._limit - count
        excess = count - self._limit
        if self._slip > 0 and excess % self._slip == 0:
            self._stat["slip"] += 1
            self._last_now = now
            # 截断应答格式同 RateLimiter.respond 的 TC 应答。
            flags = int.from_bytes(response[2:4], "big") | _FLAG_TC
            tc = (query[0:2] + flags.to_bytes(2, "big")
                  + (1).to_bytes(2, "big") + b"\x00\x00\x00\x00\x00\x00"
                  + query[12:])
            return tc, "slip", 0
        self._stat["drop"] += 1
        self._last_now = now
        return None, "drop", 0

    def stats(self, reset: bool = False) -> str:
        """返回统计的固定键序紧凑 ASCII JSON（末尾一个换行）。

        键序仅 pass,drop,slip,expired,evicted,keys,capacity，值均为非负
        十进制整数，capacity 恒为 4096；pass/drop/slip 分别累计三种成功
        动作次数，expired、evicted 为上次重置后实际删除的过期键数、容量
        淘汰键数，keys 为当前活动计数键数。统计仅在 apply 成功返回后原子
        提交，apply 抛异常不改变统计。reset 非 bool 抛 TypeError 且无变
        化；False 只读且重复读取逐字节相同；True 先返回重置前快照，再清
        零五个累计计数，保留活动键及其计数、创建序和最后时钟，因此 keys
        不清零。相同状态与输入逐字节一致；读取时间与额外空间为 O(1)。
        """
        if not isinstance(reset, bool):
            raise TypeError("reset must be bool")
        stat = self._stat
        text = (
            '{"pass":' + str(stat["pass"])
            + ',"drop":' + str(stat["drop"])
            + ',"slip":' + str(stat["slip"])
            + ',"expired":' + str(stat["expired"])
            + ',"evicted":' + str(stat["evicted"])
            + ',"keys":' + str(len(self._counts))
            + ',"capacity":' + str(_RATE_TABLE_CAPACITY) + "}\n"
        )
        if reset:
            # 先返回重置前快照，再清零五个累计计数；活动键及其计数、创建
            # 序、时钟均保留。
            stat["pass"] = 0
            stat["drop"] = 0
            stat["slip"] = 0
            stat["expired"] = 0
            stat["evicted"] = 0
        return text


def _validate_rate_ops(ops):
    """校验 replay_rate 的操作序列（不执行）。

    ops 限 0..4096 项；allow 项键序仅 op,query,client,now,kind，
    authorize 项键序仅 op,query,client，reload 项键序仅
    op,rules,expected，rollback 项键序仅 op,target,expected：op 与
    键序形状一致；allow/authorize 项 query 为偶长小写十六进制，
    client 为 str；allow 项 now 为非 bool 整数、kind 为 str；reload
    项 rules 沿用 RateLimiter 构造契约（结构、键序、类型、值域非法
    均抛 ReplayError），expected 为非负非 bool 整数；rollback 项
    target、expected 均为非负非 bool 整数。ops 非 list 抛 TypeError；
    超量及项、键序、op 名、值类型或格式非法抛 ReplayError。kind 取值、
    client 是否为 IP 地址与 query 报文可解码性不在此校验，留待执行时
    判定。
    """
    if not isinstance(ops, list):
        raise TypeError("ops must be list")
    if len(ops) > _MAX_REPLAY_RATE_OPS:
        raise ReplayError("ops must contain 0..4096 items")
    for op in ops:
        if not isinstance(op, dict):
            raise ReplayError("op must be dict")
        keys = list(op.keys())
        if keys == _REPLAY_RATE_OP_KEYS:
            kind = "allow"
        elif keys == _REPLAY_AUTHORIZE_OP_KEYS:
            kind = "authorize"
        elif keys == _REPLAY_RELOAD_OP_KEYS:
            kind = "reload"
        elif keys == _REPLAY_RATE_ROLLBACK_KEYS:
            kind = "rollback"
        else:
            raise ReplayError(
                "op keys must be op,query,client,now,kind"
                " or op,query,client or op,rules,expected"
                " or op,target,expected")
        if not isinstance(op["op"], str):
            raise ReplayError("op must be str")
        if op["op"] != kind:
            raise ReplayError("op name does not match op keys")
        if kind == "rollback":
            for field in ("target", "expected"):
                value = op[field]
                if not isinstance(value, int) or isinstance(value, bool):
                    raise ReplayError(field + " must be int")
                if value < 0:
                    raise ReplayError(field + " must be non-negative")
            continue
        if kind == "reload":
            # rules 沿用 RateLimiter 构造契约；契约违规（含类型错）在此
            # 统一收口为 ReplayError，构造限流器前抛出。
            try:
                _validate_rate_rules(op["rules"])
            except (TypeError, PolicyError) as exc:
                raise ReplayError(str(exc)) from None
            expected = op["expected"]
            if (not isinstance(expected, int)
                    or isinstance(expected, bool)):
                raise ReplayError("expected must be int")
            if expected < 0:
                raise ReplayError("expected must be non-negative")
            continue
        query = op["query"]
        if not isinstance(query, str):
            raise ReplayError("query must be str")
        if (len(query) % 2
                or any(c not in _LOWER_HEXDIGITS for c in query)):
            raise ReplayError("query must be even-length lowercase hex")
        if not isinstance(op["client"], str):
            raise ReplayError("client must be str")
        if kind == "allow":
            if (not isinstance(op["now"], int)
                    or isinstance(op["now"], bool)):
                raise ReplayError("now must be int")
            if not isinstance(op["kind"], str):
                raise ReplayError("kind must be str")


def replay_rate(rules: list, ops: list, expected=None, policy=None,
                default: str = "deny") -> str:
    """在 RateLimiter 上依次回放 allow/authorize/reload/rollback 操作，返回记录的 JSON。

    ops 非 list 或 expected 非 None/str 抛 TypeError；ops 超 4096 项
    及项、键序、op 名、值类型或格式非法（allow 项键序
    op,query,client,now,kind，authorize 项键序 op,query,client，
    reload 项键序 op,rules,expected，rollback 项键序
    op,target,expected；query 非偶长小写十六进制、client/kind 非
    str、now 为 bool 或非整数、reload 项 rules 不满足 RateLimiter
    构造契约或 expected 为 bool/非整数/负值、rollback 项 target 或
    expected 为 bool/非整数/负值）均在构造 RateLimiter 前抛
    ReplayError。ops 校验通过后校验
    policy/default：policy 为 None 视为空列表（不校验 default），
    否则 default 与 policy 的校验及异常同 authorize；随后 rules 的
    校验与异常同 RateLimiter 构造。每项记录键序 in,out,stats：in 为
    操作原文，stats 为该操作后的 stats(False) 原文。allow 项成功
    out 键序 ok,allow,remaining（ok 为 true，后两项为 allow 的返回
    值）；authorize 项按同名函数执行，成功 out 键序 ok,allow；reload
    项调用 reload_rules(rules, expected)，成功 out 键序
    ok,version,result,kept,dropped（ok 为 true，后四项为该方法报告的
    四值）；rollback 项调用 rollback_rules(target, expected)，成功
    out 键序 ok,version,result,target,kept,dropped（ok 为 true，后
    五项为该方法报告的五值）。四者抛出的异常均记为 out 键序
    ok,error（false 与异常类名）并继续后续操作；allow 的失败原子性
    不变（计数、时钟与统计均不改），authorize 不改限流状态，reload
    的冲突、未变与异常无副作用，rollback 的冲突、未变、缺失与异常
    亦无副作用，applied 沿用版本、历史归档及计数键保留删除语义且
    后续 allow 使用新规则。输出为紧凑 ASCII JSON，顶层键序
    version,ops，version 为 1，末尾单换行；同输入逐字节一致。结果
    超 16777216 字节抛 ReplayError 且不比较 expected。expected 为
    None 时仅记录；为 str 时与输出整体比较，不一致抛 ReplayError。
    """
    if expected is not None and not isinstance(expected, str):
        raise TypeError("expected must be str or None")
    # 全部操作校验在构造 RateLimiter 前完成。
    _validate_rate_ops(ops)
    # policy/default 的校验在 ops 之后、构造 RateLimiter 之前。
    if policy is None:
        policy = []
    else:
        if not isinstance(default, str):
            raise TypeError("default must be str")
        if default not in _POLICY_ACTIONS:
            raise PolicyError("default must be allow or deny")
        _validate_policy_rules(policy)
    limiter = RateLimiter(rules)
    items = []
    for op in ops:
        if op["op"] == "allow":
            try:
                allowed, remaining = limiter.allow(
                    bytes.fromhex(op["query"]), op["client"], op["now"],
                    op["kind"])
                out = {"ok": True, "allow": allowed,
                       "remaining": remaining}
            except Exception as exc:
                out = {"ok": False, "error": type(exc).__name__}
        elif op["op"] == "reload":
            try:
                report = json.loads(limiter.reload_rules(
                    op["rules"], op["expected"]))
                out = {"ok": True, "version": report["version"],
                       "result": report["result"], "kept": report["kept"],
                       "dropped": report["dropped"]}
            except Exception as exc:
                out = {"ok": False, "error": type(exc).__name__}
        elif op["op"] == "rollback":
            try:
                report = json.loads(limiter.rollback_rules(
                    op["target"], op["expected"]))
                out = {"ok": True, "version": report["version"],
                       "result": report["result"],
                       "target": report["target"],
                       "kept": report["kept"],
                       "dropped": report["dropped"]}
            except Exception as exc:
                out = {"ok": False, "error": type(exc).__name__}
        else:
            try:
                allowed = authorize(
                    bytes.fromhex(op["query"]), op["client"], policy,
                    default)
                out = {"ok": True, "allow": allowed}
            except Exception as exc:
                out = {"ok": False, "error": type(exc).__name__}
        items.append({"in": op, "out": out, "stats": limiter.stats(False)})
    result = json.dumps({"version": 1, "ops": items},
                        ensure_ascii=True, separators=(",", ":")) + "\n"
    if len(result) > _MAX_REPLAY_RESULT_BYTES:
        raise ReplayError("replay result exceeds 16777216 bytes")
    if expected is not None and result != expected:
        raise ReplayError("output does not match expected")
    return result


def _validate_cache_ops(ops):
    """校验 replay_cache 的操作序列，返回 [(kind, op), ...]（不执行）。

    ops 限 0..4096 项，项键序仅 op,query,now,limit（kind 为 resolve）
    或 op,reset（kind 为 stats）：op 分别为 "resolve"、"stats"；resolve
    的 query 为偶长小写十六进制、now/limit 为非 bool 整数；stats 的
    reset 为 bool。ops 非 list 抛 TypeError；超量及项、键序、op 名或
    字段类型/格式非法均抛 ReplayError。query 报文可解码性不在此校验，
    留待执行时由 resolve 判定。
    """
    if not isinstance(ops, list):
        raise TypeError("ops must be list")
    if len(ops) > _MAX_REPLAY_CACHE_OPS:
        raise ReplayError("ops must contain 0..4096 items")
    checked = []
    for op in ops:
        if not isinstance(op, dict):
            raise ReplayError("op must be dict")
        keys = list(op.keys())
        if keys == _REPLAY_RESOLVE_KEYS:
            kind = "resolve"
        elif keys == _REPLAY_CACHE_STATS_KEYS:
            kind = "stats"
        else:
            raise ReplayError("op keys must be op,query,now,limit or op,reset")
        if not isinstance(op["op"], str):
            raise ReplayError("op must be str")
        if op["op"] != kind:
            raise ReplayError("op name does not match op keys")
        if kind == "resolve":
            query = op["query"]
            if not isinstance(query, str):
                raise ReplayError("query must be str")
            if (len(query) % 2
                    or any(c not in _LOWER_HEXDIGITS for c in query)):
                raise ReplayError("query must be even-length lowercase hex")
            if not isinstance(op["now"], int) or isinstance(op["now"], bool):
                raise ReplayError("now must be int")
            if not isinstance(op["limit"], int) or isinstance(op["limit"], bool):
                raise ReplayError("limit must be int")
        else:
            if not isinstance(op["reset"], bool):
                raise ReplayError("reset must be bool")
        checked.append((kind, op))
    return checked


def replay_cache(zone: dict, ops: list, expected=None) -> str:
    """在 PositiveCache 上依次回放 resolve/stats 操作，返回记录的紧凑 JSON。

    ops 非 list 或 expected 非 None/str 抛 TypeError；ops 超 4096 项
    及项、键序、op 名或字段类型/格式非法（resolve 的 query 非偶长小写
    十六进制、now/limit 为 bool 或非整数，stats 的 reset 非 bool）均
    在构造 PositiveCache 前抛 ReplayError；zone 的校验与异常同
    PositiveCache 构造，且在 ops 完整校验通过后才进行。每项记录键序
    in,out,stats：in 为操作原文，stats 为该操作后的 stats(False) 原文。
    成功 out 首键 ok 为 true：resolve 键序 ok,response,hit，response
    为小写十六进制；stats 键序 ok,snapshot，snapshot 为 stats(reset)
    返回原文（含末尾换行，reset 为 true 时是重置前的旧快照，而记录的
    stats 为重置后的值）。操作抛出的异常记为 out 键序 ok,error（false
    与异常类名）并继续后续操作，失败原子性沿用 PositiveCache（条目、
    时钟与统计均不改）。输出为紧凑 ASCII JSON，顶层键序 version,ops，
    version 为 1，末尾单换行；同输入逐字节一致。expected 为 None 时
    仅记录；为 str 时与输出整体比较，不一致抛 ReplayError。
    """
    if expected is not None and not isinstance(expected, str):
        raise TypeError("expected must be str or None")
    # 全部操作校验在构造 PositiveCache 前完成。
    checked = _validate_cache_ops(ops)
    cache = PositiveCache(zone)
    items = []
    for kind, op in checked:
        if kind == "resolve":
            try:
                response, hit = cache.resolve(
                    bytes.fromhex(op["query"]), op["now"], op["limit"])
                out = {"ok": True, "response": response.hex(), "hit": hit}
            except Exception as exc:
                out = {"ok": False, "error": type(exc).__name__}
        else:
            try:
                snapshot = cache.stats(op["reset"])
                out = {"ok": True, "snapshot": snapshot}
            except Exception as exc:
                out = {"ok": False, "error": type(exc).__name__}
        items.append({"in": op, "out": out, "stats": cache.stats(False)})
    result = json.dumps({"version": 1, "ops": items},
                        ensure_ascii=True, separators=(",", ":")) + "\n"
    if expected is not None and result != expected:
        raise ReplayError("output does not match expected")
    return result


def _run_answer_cli(zone_path, hextext, limit_text):
    """answer 子命令实现：参数通过后才打开区域文件。

    返回 (退出码, stdout bytes, stderr 异常名或 None)；失败时 stdout 为
    b""，由调用方向 stderr 写一个异常类型名加换行，不输出 traceback。
    区域文件上限 1048576 字节、查询报文上限 512 字节、应答不超 LIMIT
    （12..65535）。
    """
    # 参数校验：路径非空且不含 NUL，查询为非空偶长十六进制，LIMIT 缺省
    # 512 或 12..65535 的 ASCII 十进制整数；失败不打开区域文件。
    if zone_path == "" or "\x00" in zone_path:
        return 2, b"", "ArgumentError"
    if (not hextext or len(hextext) % 2
            or any(c not in _HEXDIGITS for c in hextext)):
        return 2, b"", "ArgumentError"
    if limit_text is None:
        limit = 512
    elif (not limit_text or not limit_text.isascii()
            or not limit_text.isdigit()):
        return 2, b"", "ArgumentError"
    else:
        limit = int(limit_text)
        if not _MIN_LIMIT <= limit <= _MAX_LIMIT:
            return 2, b"", "ArgumentError"
    query = bytes.fromhex(hextext)
    # 读取并导入区域：文件/配置结构错误归 ConfigError，区域/记录语义
    # 错误沿用 ZoneError、RecordError，均退出 4。
    try:
        with open(zone_path, "rb") as stream:
            data = stream.read(_MAX_ANSWER_ZONE_BYTES + 1)
    except OSError:
        return 4, b"", "ConfigError"
    if len(data) > _MAX_ANSWER_ZONE_BYTES:
        return 4, b"", "ConfigError"
    if not data.isascii():
        return 4, b"", "ConfigError"
    text = data.decode("ascii")
    try:
        try:
            config = json.loads(text, object_pairs_hook=_config_pairs)
        except (json.JSONDecodeError, RecursionError, ValueError):
            # json 对超长整数抛非 JSONDecodeError 的 ValueError、对超深
            # 嵌套抛 RecursionError，统一归为 ConfigError，不泄漏 json 异常。
            raise ConfigError("invalid JSON") from None
        zone, _version = _check_zone_config(config)
        origin, rrs, _zone_class = _validate_zone(zone)
        zone = {"origin": _labels_to_name(origin, wildcard=False),
                "records": [_rr_to_model(rr) for rr in rrs]}
    except ConfigError:
        return 4, b"", "ConfigError"
    except ZoneError:
        return 4, b"", "ZoneError"
    except RecordError:
        return 4, b"", "RecordError"
    # 区域导入后处理查询：报文格式错误 3；不可应答、超 LIMIT 等编码错误
    # 与 CNAME 链错误 5。
    try:
        reply = answer(query, zone, limit)
    except MessageError:
        return 3, b"", "MessageError"
    except CNAMEError:
        return 5, b"", "CNAMEError"
    except EncodeError:
        return 5, b"", "EncodeError"
    return 0, reply, None


def main(argv):
    if len(argv) >= 2 and argv[1] == "answer":
        if len(argv) not in (4, 5):
            sys.stderr.write("ArgumentError\n")
            return 2
        code, reply, error = _run_answer_cli(argv[2], argv[3],
                                             argv[4] if len(argv) == 5
                                             else None)
        if error is not None:
            sys.stderr.write(error + "\n")
            return code
        # 成功：仅应答原始字节，无追加换行，stderr 为空。
        sys.stdout.buffer.write(reply)
        return 0
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
