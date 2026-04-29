# CF-Workers-TOR
CF-Workers-TOR 是一个实验性项目，在 Cloudflare Workers 中内嵌轻量 TLS 客户端，直连 Tor relay，在 TLS 层之上实现 Tor circuit 构建、relay cell 加解密及 BEGIN/DATA 流转发，使 VLESS over WebSocket 流量可经 Tor exit 访问 clearnet 目标。
