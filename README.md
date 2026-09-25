# dns

从零实现的 DNS 解析与权威应答框架，仅用 Python 标准库、不联网。

- 入口：`python dns.py <子命令>`
- 所有 TTL 与超时必须由显式时钟驱动；相同查询必须产生逐字节相同的应答报文。
- 结构化结果写成 JSON，浮点数按固定小数位格式化；应答报文按字节写出。

## 测试

    python -m unittest discover
