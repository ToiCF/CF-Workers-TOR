# CF-Workers-TOR

一个基于 Cloudflare Workers 的实验性 Tor exit 代理。项目使用 `TLSClientMini.js` 在 Worker 内连接 Tor relay，并在 TLS 之上实现基础 Tor circuit / relay cell 转发。

> 这是研究性、学习性代码，用来验证 Workers 内手写 Tor relay TLS 和 exit circuit 的可行性。实际代理体验不保证稳定，速度、延迟和可用性取决于 Cloudflare egress、Workers `connect()`、Tor relay 状态和出口质量。

## 功能特性

- 支持 VLESS over WebSocket over TLS 入口。
- 支持手动指定 Tor relay path：`/tor://[relay1:port→relay2:port→exit:port]`。
- 支持 `/getServ?hops=N` 从 Tor consensus 生成 relay path。
- 支持 `CREATE2` / `EXTEND2` 建立 Tor circuit。
- 支持 `BEGIN` / `DATA` 转发普通 clearnet TCP 目标。
- 使用 `TLSClientMini.js` 连接真实 Tor relay，而不是依赖浏览器/系统 Tor 客户端。

## 不支持

- 不支持纯 `.onion` / hidden service / onion service。
- 不支持完整 Tor Browser / 完整 Tor client 行为。
- 不支持完整 Tor directory 验证。
- 不支持完整 stream multiplexing；当前 WebSocket 连接主要对应单个 stream。

## 文件结构

| 文件 | 说明 |
| --- | --- |
| [TLSClientMini.js](./TLSClientMini.js) | 最小 TLS 客户端，用于连接 Tor relay。 |
| [TOR.js](./TOR.js) | Worker 源文件，不内联 TLS。 |
| [TOR-merged.js](./TOR-merged.js) | 部署用单文件，内联 `TOR.js` + `TLSClientMini.js`。 |
| [TorHS-Circuit.py](./TorHS-Circuit.py) | Python onion service 实验参考，不属于 Worker 主线。 |

## 部署方式

### Cloudflare Workers

1. 创建一个 Cloudflare Worker。
2. 使用 Module Worker 格式部署 `TOR-merged.js`。
3. 确保部署环境支持 `cloudflare:sockets` TCP 出站连接。
4. 访问 Worker 域名，普通 HTTP 请求返回 `ok`。

`TOR-merged.js` 是部署产物；改逻辑时优先改 `TOR.js` / `TLSClientMini.js`，再重新生成部署文件。

## 配置项

当前主要配置在源码顶部：

| 配置 | 说明 |
| --- | --- |
| `uuid` | VLESS 用户 UUID。 |
| `maxED` | `sec-websocket-protocol` early data 最大长度，当前为 `8192`。 |
| `/getServ?hops=N` | 自动生成 relay path 的跳数，限制在 `1..8`。 |

## 入口协议

客户端入口使用 VLESS over WebSocket over TLS 的节点格式。`TOR.js` 只解析当前代理入口需要的 VLESS 首包和响应头，不绑定具体客户端实现，也不是完整代理内核。

外层入口和内层 Tor circuit 是两层协议：

```text
客户端 --VLESS/WS/TLS--> Worker --Tor relay TLS + Tor cells--> Tor relay path
```

## 节点格式

Worker WebSocket path 使用 Tor relay path：

```text
/tor://[relay1_ip:port→relay2_ip:port→exit_ip:port]&ed=2560
```

说明：

- `[]` 内是 Tor relay 路径。
- relay 之间用 `→` 分隔。
- 最后一跳是 exit relay。
- `ed=2560` 是 VLESS early data 参数。
- 这是普通 Tor relay path，不是 `.onion` 地址。

VLESS 分享链接模板：

```text
vless://<uuid>@<front-host>:<front-port>/?type=ws&encryption=none&flow=&host=<worker-host>&path=%2Ftor%3A%2F%2F%5B<relay1_ip>%3A<port>%E2%86%92<relay2_ip>%3A<port>%E2%86%92<exit_ip>%3A<port>%5D%26ed%3D2560&security=tls&sni=<worker-host>&fp=chrome&packetEncoding=xudp#TOR
```

字段说明：

| 字段 | 说明 |
| --- | --- |
| `<uuid>` | 与 `TOR.js` 中的 `uuid` 一致。 |
| `<front-host>:<front-port>` | 客户端连接入口。 |
| `host` / `sni` | Worker 域名。 |
| `path` | URL 编码后的 `/tor://[...]&ed=2560`。 |
| `security=tls` | 客户端到入口使用 TLS。 |
| `packetEncoding=xudp` | 客户端侧参数；Worker 这里按 WebSocket/VLESS TCP 流处理。 |

## API

### `GET /`

健康检查。

```text
ok
```

### `GET /getServ?hops=3`

从 consensus 中选择 relay，返回可直接放入节点 path 的 Tor relay path。

响应示例：

```text
/tor://[guard_ip:port→middle_ip:port→exit_ip:port]
```

规则：

- `hops=1`：只选一个 exit relay。
- `hops>=2`：选择 guard / middle / exit 结构。
- 返回的是 clearnet exit path，不是 onion service path。

### WebSocket 入口

客户端使用 VLESS over WebSocket 连接 Worker。Worker 解析 VLESS 首包后，将目标 `host:port` 转成 Tor `BEGIN` stream。

## 实现路径

普通 clearnet 请求流程：

```text
VLESS/WS 客户端
  → Worker
  → 解析 /tor://[...] relay path
  → TLSClientMini 连接第一跳 Tor relay
  → CREATE2 建第一跳
  → EXTEND2 扩展后续 relay
  → BEGIN 连接目标 host:port
  → DATA 双向转发
```

当前实现的 Tor 能力：

- Tor relay TLS；
- ntor key 派生；
- AES-CTR relay cell 加解密；
- SHA1 relay digest；
- consensus 获取；
- relay `ntor-onion-key` 查询和缓存。

## `.onion` 支持说明

当前不能访问 `.onion`。原因不是缺少 DNS，而是 `.onion` 访问需要完整 onion service 流程：

```text
.onion identity
  → HSDir 选择
  → descriptor 获取、验签、解密
  → introduction points
  → introduction circuit
  → rendezvous circuit
  → INTRODUCE1 / RENDEZVOUS2
  → onion service stream
```

`TOR.js` 只实现普通 exit circuit；`TorHS-Circuit.py` 只是 Python 实验参考，用于研究 HSDir、descriptor、intro、rendezvous 这条更重的路径。

## 注意事项

- 这是协议实验项目，不是稳定代理产品。
- relay path 质量会明显影响成功率和速度。
- 大文件、长连接、复杂网页加载都可能受 Workers 和 Tor relay 状态影响。
- 公开部署前请自行处理访问控制和 UUID 管理。

## 相关链接

- 开源协议：[GPL-3.0](./LICENSE)
- 交流群组：[Telegram](https://t.me/Enkelte_notif)
- Arti 源码：<https://gitlab.torproject.org/tpo/core/arti>
- Tor 官方源码：<https://gitlab.torproject.org/tpo/core/tor>

## Stargazers over time

[![Stargazers over time](https://starchart.cc/ToiCF/CF-Workers-TOR.svg?variant=adaptive)](https://starchart.cc/ToiCF/CF-Workers-TOR)
