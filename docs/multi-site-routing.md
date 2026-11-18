# Sentinel 多站点路由

Sentinel 只有一个公网入口：同一 NGINX 进程监听 `PUBLIC_LISTEN_ADDR:80/443`。每个业务站点是一个 NGINX virtual host，并由 `sites.json` 声明；新增站点不会创建新容器，也不会新增公网端口。

```text
app.example.com     ─┐
portal.example.com  ─┼─> Sentinel :443 ─> 127.0.0.1:10443 (SafeLine) ─> 应用 A
shop.example.org    ─┘                   -> 127.0.0.1:10444 (SafeLine) ─> 应用 B
```

## 清单规则

- `sites.json` 中每个 `proxy` 都必须有精确 hostname、单独的 SafeLine listener 端口和显式证书路径。
- Sentinel 只接受 `127.0.0.1` 作为业务上游。应用的私网地址应配置在 SafeLine 控制台，而不是 Sentinel。
- SafeLine listener 端口不可复用；渲染器会拒绝冲突。
- `redirect` 类型也监听同一组 `80/443`，但只返回 HTTPS `308` 跳转，不会接触 SafeLine。
- 渲染器生成一个默认虚拟主机，拒绝未知 `Host`（`421`）；不能通过删除此边界来“支持更多域名”。

完整字段定义和示例见项目 [README](../README.md#2-编写-sitesjson)。

## 添加业务站点

1. 在所选 DNS 服务商创建 A/AAAA 记录，按 direct/cloudflare/trusted-proxy 选择入口模式；确认该 hostname 的适用证书和私钥已安全部署。
2. 在 SafeLine 控制台创建站点：HTTP listener 使用未占用端口，例如 `10446`，应用上游填写回环或私网地址。
3. 发布后收口 SafeLine listener：

   ```bash
   UPSTREAM_PORT=10446 ./scripts/safeline-listener.sh check
   sudo UPSTREAM_PORT=10446 ./scripts/safeline-listener.sh apply
   ss -ltn 'sport = :10446'
   ```

   输出必须只包含 `127.0.0.1:10446`。

4. 将站点对象加入 `sites.json`：

   ```json
   {
     "name": "new-app",
     "type": "proxy",
     "domain": "new.example.com",
     "certificate": "/etc/sentinel/tls/new.example.com/fullchain.pem",
     "private_key": "/etc/sentinel/tls/new.example.com/privkey.pem",
     "upstream": {"address": "127.0.0.1", "port": 10446, "scheme": "http"},
     "security": {
       "content_security_policy": "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'",
       "permissions_policy": "camera=(), microphone=()"
     }
   }
   ```

5. 生成、验证并更新：

   ```bash
   sudo ./scripts/preflight.sh
   sudo ./scripts/deploy-proxy.sh
   ./scripts/verify.sh https://new.example.com
   ```

## 更新、删除与回滚

修改清单后通过发布脚本验证完整候选、原子切换版本、显式重载并核对运行摘要；预检不会改变线上版本。删除站点时，先在对应 DNS/代理服务与 SafeLine 中下线该域名，再从清单删除并发布。

SafeLine listener 脚本每次 `apply` 都会在 `/data/safeline/backups/sentinel/listeners/` 保存原文件。Sentinel 发布失败会自动恢复前一版本与镜像；手动回滚恢复审核过的清单与环境，再执行 `sudo ./scripts/deploy-proxy.sh`。若要回到旧架构，停止 Sentinel 后在 SafeLine 控制台恢复监听。
