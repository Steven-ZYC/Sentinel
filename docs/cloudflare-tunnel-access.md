# 用 Cloudflare Tunnel + Access 保护 SafeLine 管理平台

本文说明如何把 SafeLine 管理平台从公网端口迁移到受身份认证保护的 HTTPS 域名。
所有示例均已去敏感化：

- 管理域名使用 `waf.example.com`；
- 管理员邮箱使用 `admin@example.com`；
- Tunnel 凭据统一写作 `<TUNNEL_TOKEN>`；
- 不在仓库、Issue、日志或聊天记录中粘贴真实 token、账户 ID、证书私钥或 Cookie。

实际部署时将占位符替换为自己的值。Tunnel token 等同于连接凭据，泄露后应立即在
Cloudflare 控制台执行 **Rotate token**。

## 架构与边界

```text
管理员浏览器
  -> Cloudflare HTTPS
  -> Cloudflare Access（身份 + MFA + Allow policy）
  -> Cloudflare Tunnel（cloudflared 主动建立的出站连接）
  -> https://127.0.0.1:9443
  -> SafeLine 管理平台
```

这个管理链路不经过 Sentinel，也不在 SafeLine 中创建一个指向 SafeLine 管理平台的
站点。这样可避免“用 WAF 数据面代理自身控制面”的循环依赖。业务站点仍使用
Cloudflare -> Sentinel -> SafeLine -> 应用的链路。

Tunnel 建立后不代表已经安全；如果没有 Access 应用，Published application 默认可被
公网访问。正确顺序是：先创建 Access 应用和最小 Allow 策略，再发布 Tunnel hostname，
最后才关闭公网 9443。

## 0. 前提检查

1. 域名 Zone 已托管在同一 Cloudflare 账户。
2. 仍有一条与 9443 无关的管理通道，例如云厂商控制台或 Tailscale SSH。
3. 在服务器本机确认 SafeLine 管理 API 正常：

   ```bash
   curl --fail --silent --show-error --insecure \
     https://127.0.0.1:9443/api/open/health
   ```

4. 不提前关闭公网 9443；等 Tunnel 与 Access 验收通过后再收口。
5. Cloudflare 页面名称可能随版本变化。可搜索关键词：
   `Cloudflare Tunnel`、`Published application`、`Self-hosted application`、
   `Access policy`、`No TLS Verify`。

## 1. 先创建 Access 应用

在 Cloudflare Zero Trust 控制台进入 **Access controls -> Applications**，选择
**Create application**，再选择 **Self-hosted / Self-hosted and private**。

建议填写：

| 字段 | 去敏感化示例 | 建议 |
| --- | --- | --- |
| Application name | `SafeLine Admin` | 名称不含服务器 IP |
| Public hostname | `waf.example.com` | 独立管理子域 |
| Path | 留空 | 保护整个站点 |
| Session duration | `1 hour` | 管理控制面使用短会话 |

创建一条 Allow policy：

- Action：`Allow`；
- Include：优先选 Cloudflare Account Member、指定 IdP 用户或精确邮箱
  `admin@example.com`；
- 不要使用 `Everyone`，也不要仅凭来源国家放行；
- Authentication/MFA：启用应用级或策略级 MFA；
- 不创建 `Bypass` policy；
- 多条策略同时存在时，复核策略优先级和最短 session duration。

如果账户使用 Cloudflare 身份提供商，可限制为账户成员，并继续要求账户本身开启
MFA。使用 Entra ID、Okta 或 OIDC 时，可进一步要求 IdP 报告的 MFA 或设备状态。

保存后，在 Tunnel 尚未发布时域名可能仍不可访问，这是预期状态。

## 2. 创建 remotely-managed Tunnel

Cloudflare 对大多数场景推荐 remotely-managed Tunnel。进入 **Networking -> Tunnels**；
部分界面显示为 **Zero Trust -> Networks -> Connectors -> Cloudflare Tunnels**。

1. 选择 **Create tunnel**；
2. 选择 `cloudflared` connector；
3. 使用不含域名、IP 或人员姓名的名称，例如 `admin-origin-01`；
4. 选择 Linux 安装方式；
5. 按控制台给出的官方安装步骤安装 `cloudflared`；
6. 复制控制台生成的服务安装命令，在服务器终端执行：

   ```bash
   sudo cloudflared service install <TUNNEL_TOKEN>
   ```

不要把真实命令提交到 shell 脚本，因为命令中包含 token。若需要运维记录，只记录
Tunnel 名称、UUID、创建时间和 token 轮换时间，不记录 token 值。

检查 connector：

```bash
systemctl is-enabled cloudflared
systemctl is-active cloudflared
sudo systemctl status cloudflared --no-pager
```

控制台中的 connector 状态应为 `Healthy`。排错关键词：`cloudflared service`、
`QUIC 7844`、`Tunnel connector health`、`journalctl -u cloudflared`。

## 3. 发布管理域名

进入刚创建的 Tunnel，选择 **Published application routes -> Add route**：

| 字段 | 值 |
| --- | --- |
| Hostname | `waf.example.com` |
| Service type | `HTTPS` |
| Service URL | `https://127.0.0.1:9443` |

在 **Additional application settings -> TLS** 中：

- `No TLS Verify`：开启。这里只允许该例外，因为 cloudflared 与 SafeLine 在同一台
  主机上通过回环地址通信，而 SafeLine 本地证书通常不包含 `127.0.0.1`；
- `Origin Server Name`：留空，除非已为 SafeLine 配置可验证且名称匹配的证书；
- `HTTP2 connection`：保持默认关闭即可，管理流量无需为本机一跳启用 HTTP/2；
- `HTTP Host Header`：默认留空，只有 SafeLine 明确要求固定 Host 时再设置。

`No TLS Verify` 只影响 Tunnel 到回环源站的一跳，不等于关闭浏览器到 Cloudflare 的
TLS。若以后给本地管理端部署受信证书，应关闭该选项并设置正确的 Origin Server Name。

保存 route 后，Cloudflare 通常会自动创建指向 `<UUID>.cfargotunnel.com` 的代理
CNAME。不要再创建一个指向服务器公网 IP 的同名 A/AAAA 记录。

## 4. 验收 Access 与 Tunnel

在关闭公网 9443 前完成以下测试：

1. 未登录的隐私窗口访问 `https://waf.example.com`，应先进入 Cloudflare Access，
   不能直接看到 SafeLine 登录页；
2. 不在 Allow policy 中的身份应被拒绝；
3. 允许的管理员必须完成 MFA；
4. 登录后检查 SafeLine 首页、站点列表、事件页、保存操作和退出登录；
5. 浏览器开发者工具中不应有 API、WebSocket、Cookie 或跨域错误；
6. Cloudflare Access audit log 中应出现对应的 allow/deny 记录；
7. 暂停 cloudflared 后域名应不可到达源站，恢复服务后重新正常；
8. SafeLine 原生账号和强密码仍需保留，Access 是额外一层而非替代品。

若访问直接进入 SafeLine 而没有 Access 登录，立即删除 Published application route 或
DNS 记录，修正 Access 应用匹配范围后再发布。

## 5. 收回公网 9443

Tunnel 与 Access 验收完成后，才将 SafeLine 的 Docker 发布地址绑定为：

```dotenv
MGT_PORT=127.0.0.1:9443
```

然后重建 management service，并验证公网 IP 的 9443 已不可连接。本仓库的网络边界
脚本会备份 SafeLine 和 UFW 配置、设置自动回滚，再执行这一收口。将已经受 Access
保护的 hostname 作为验收目标：

```bash
cd /path/to/Sentinel
sudo MANAGEMENT_URL=https://waf.example.com \
  ./scripts/apply-network-boundary.sh
```

脚本只检查该 URL 能否到达 Cloudflare；最终仍需在第二个浏览器会话中完成 Access
认证并验证 SafeLine 页面，然后才输入 `CONFIRM`。不要把 Access token 或 Cookie
作为命令行参数。

即使 Docker 已绑定回环，也应在云防火墙和主机防火墙中保持 9443 无公网 Allow 规则，
形成纵深防御。

## 6. 回滚与应急

如果 Tunnel 或 Access 故障：

1. 保持 SSH/云控制台会话；
2. 临时恢复 9443 时只绑定可信管理 IP，不恢复 `0.0.0.0/0`；
3. 检查 `cloudflared` service、connector health、Access policy 和 DNS CNAME；
4. 需要废弃 Tunnel 时，先建立替代管理通道，再删除 route、Access application 和
   connector；
5. token 疑似泄露时执行 **Rotate token**，随后重新安装 connector service。

## 官方文档

- [Cloudflare Tunnel 总览](https://developers.cloudflare.com/tunnel/)
- [创建并发布 Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [Published applications](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/routing-to-tunnel/)
- [Tunnel origin parameters](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
- [创建 Access 应用](https://developers.cloudflare.com/learning-paths/clientless-access/access-application/create-access-app/)
- [Access 自托管 Web 应用](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/)
- [Access MFA](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/mfa-requirements/)
- [Access session management](https://developers.cloudflare.com/cloudflare-one/access-controls/access-settings/session-management/)
- [Tunnel token 轮换](https://developers.cloudflare.com/tunnel/advanced/tunnel-tokens/)
