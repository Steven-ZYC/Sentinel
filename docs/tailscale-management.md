# 仅通过 Tailscale Serve 访问 SafeLine 管理平台

本方案适合所有管理员设备均在同一 Tailnet 的场景。它不创建公网管理域名、不使用
Cloudflare Tunnel，也不使用 Tailscale Funnel。

## 目标拓扑

```text
管理员设备（Tailnet）
  -> https://<server>.<tailnet>.ts.net  (Tailscale HTTPS Serve :443)
  -> https+insecure://127.0.0.1:9443
  -> SafeLine 管理平台
```

SafeLine 本身绑定 `127.0.0.1:9443`。Tailscale Serve 在 Tailnet 内提供 HTTPS 入口，
再由本机 Tailscale 守护进程转发到回环管理端。公网和普通 LAN 设备无法访问管理端口。

## 启用 Tailscale Serve

服务器上执行：

```bash
sudo tailscale serve --bg https+insecure://localhost:9443
tailscale serve status
```

输出应包含类似内容：

```text
https://<server>.<tailnet>.ts.net (tailnet only)
|-- / proxy https+insecure://localhost:9443
```

其中 `https+insecure` 只表示 Tailscale 到本机 SafeLine 的源站证书不做验证；管理员
浏览器到 Tailscale `*.ts.net` 地址仍使用 Tailscale 的 HTTPS 证书。不要使用
`tailscale funnel`，因为 Funnel 会将服务暴露到公网。

如果 Tailnet 尚未启用 HTTPS 或 MagicDNS，Serve CLI 会提示打开相应设置。管理员设备
必须已加入同一 Tailnet，并且 ACL/Grants 允许访问服务器。

## 绑定 SafeLine 到回环

确认 Serve 的页面和 `/api/open/health` 在另一台 Tailnet 设备上都正常后，执行：

```bash
cd /path/to/Sentinel
sudo ./scripts/bind-safeline-management-tailscale.sh
```

脚本会：

1. 确认 Tailscale HTTPS Serve 已指向 `localhost:9443`；
2. 备份 SafeLine `.env`；
3. 将 `MGT_PORT` 改成 `127.0.0.1:9443`；
4. 重建仅 management 容器并等待健康检查；
5. 验证公网监听已消失；
6. 提供三分钟自动回滚，等待远程 Tailnet 设备确认。

脚本提示后，在远程设备验证页面、`/api/open/health`、登录、事件列表和保存操作，
再在脚本原终端输入 `CONFIRM`。未确认或检查失败会恢复原先的 SafeLine 绑定。

## 访问与排错

管理访问使用 Serve 输出的 `https://<server>.<tailnet>.ts.net`，不要使用
`https://<tailscale-ip>:9443`。后者是 SafeLine 原生端口，绑定到 localhost 后按设计
不可达。

远程设备验证：

```powershell
tailscale ping <server-tailscale-ip>
curl.exe --noproxy "*" -k -v https://<server>.<tailnet>.ts.net/api/open/health
```

如果页面能打开但 API 失败，先检查浏览器开发者工具、Serve route 和 SafeLine Host/SNI；
不要为了绕过 421 而把 SafeLine 管理端重新绑定到 `0.0.0.0`。

如果 Tailscale 延迟高：

```bash
tailscale ping <peer-tailscale-ip>
tailscale netcheck
```

显示 `via DERP(...)` 表示使用中继；检查 UDP/NAT 连通性，但不要为降低延迟而公开
管理端口。

## ACL/Grants

Tailscale Serve 遵循 Tailnet 的 ACL/Grants。应仅允许管理用户、管理设备或受控 tag，
不要对所有 Tailnet 成员开放服务器管理入口。若策略是 deny-by-default，需显式允许
到服务器的 HTTPS Serve 访问；如果已有允许规则，则无需额外开放公网端口。

关键词：`Tailscale ACL`、`Grants`、`tailnet policy`、`tailscale serve status`、
`MagicDNS`、`HTTPS certificates`。

## 回滚

优先使用脚本自动回滚。若必须手工恢复，先保证 SSH/云控制台可用，再恢复备份的
`/data/safeline/.env` 并重建 management 容器。不要用 `tailscale serve reset` 清空其他
Serve 配置；先保存 `tailscale serve get-config --all`，仅恢复对应 route。

## 官方参考

- [Tailscale Serve CLI](https://tailscale.com/docs/reference/tailscale-cli/serve)
- [Tailscale Serve 概览](https://tailscale.com/docs/features/tailscale-serve)
- [Tailscale HTTPS 设置](https://tailscale.com/docs/how-to/set-up-https-certificates)
- [Tailscale Grants](https://tailscale.com/docs/features/access-control/grants)
