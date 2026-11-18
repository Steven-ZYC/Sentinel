# 访问来源 IP 的识别与传递

本文记录示例业务域名 `app.example.com` 在 Cloudflare、Sentinel、SafeLine 和业务源站
之间的客户端 IP 信任链。域名、IP、用户和管理地址均为去敏感化示例。

## 修复前审计基线

最初的单站点基线**没有把真实访客 IP 传递给 SafeLine**：

```text
访客
  -> Cloudflare
  -> Sentinel :443
       TCP 对端 = Cloudflare 边缘 IP
       X-Real-IP = Cloudflare 边缘 IP
       X-Forwarded-For = Cloudflare 边缘 IP
  -> SafeLine 127.0.0.1:10443
       TCP 对端 / $remote_addr = 127.0.0.1
  -> 业务上游
```

Sentinel 仍会把请求完整交给 SafeLine 做内容检测，所以 SQL 注入、XSS 等基于请求内容的检测不会因此绕过。但是，依赖来源 IP 的日志归属、访问控制、频率限制和封禁可能把大量访客归到 Cloudflare 节点或本机回环地址，不能视为真实访客维度。

基线审计还发现源站公网地址（示例写作 `192.0.2.10:443`）可绕过 Cloudflare 直连。
因此在完成源站入站限制前，绝对不能无条件信任请求携带的 `CF-Connecting-IP`、
`X-Real-IP` 或 `X-Forwarded-For`。

## 各层如何辨识来源

### Cloudflare

Cloudflare 与访客直接建立连接，因此它知道访客的网络来源。对于普通的橙云代理请求，Cloudflare 发给源站的连接来自 Cloudflare 边缘网段，并通过 `CF-Connecting-IP` 向源站提供单一的访客 IP。

不应把收到的 `X-Forwarded-For` 直接作为唯一可信值。它可能包含多跳代理链，处理规则也比单值头复杂。Cloudflare 官方建议源站优先使用 `CF-Connecting-IP` 或 Enterprise 可选的 `True-Client-IP`。

需要注意两个 Cloudflare 设置：

- 如果 Pseudo IPv4 使用 `Overwrite Headers`，IPv6 访客的真实 IPv6 位于 `CF-Connecting-IPv6`，相关 IPv4 头可能是合成值。
- Worker 子请求可能改变 `CF-Connecting-IP` 的语义。启用 Worker 后必须重新验证来源链，不能沿用普通代理请求的假设。

### 旧版 Sentinel 行为（历史基线）

旧版 Sentinel 的 Nginx 模板曾设置为：

```nginx
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $remote_addr;
```

该历史配置中没有 `real_ip_header` 或 `set_real_ip_from`。所以：

- 经过 Cloudflare 的公网请求：`$remote_addr` 是 Cloudflare 边缘 IP。
- 绕过 Cloudflare 的直连请求：`$remote_addr` 是直连者 IP。
- 客户端自带的 `X-Real-IP` 和 `X-Forwarded-For` 会被覆盖，无法直接伪造这两个下游值；但真实访客 IP 也同时丢失。
- Cloudflare 的 `CF-Connecting-IP` 当前会继续随请求进入下游，但 Sentinel 没有验证连接是否确实来自 Cloudflare，因此 SafeLine 不应信任它。

### SafeLine 修复前行为

SafeLine 只监听 `127.0.0.1:10443`。因此 SafeLine Nginx 收到 Sentinel 请求时，其连接来源和 `$remote_addr` 都是 `127.0.0.1`。

本机生成的 SafeLine 配置中未发现 `real_ip_header` 或 `set_real_ip_from`。站点访问日志格式使用 `$remote_addr`，向业务上游转发时则使用：

```nginx
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
```

因此，按当前 Sentinel 输入推导，普通公网请求继续转发时的 XFF 链会近似为：

```text
<Cloudflare 边缘 IP>, 127.0.0.1
```

当前站点的业务上游是 SafeLine 自己的静态文件目录，所以应用层暂时没有消费该值。SafeLine 内部检测模块是否对特定功能额外解析代理头，不应仅靠猜测；但无论它选择当前的 `$remote_addr`、`X-Real-IP` 还是 `X-Forwarded-For`，得到的都不是已经验证的真实访客 IP。因此当前不能把 SafeLine 控制台中的 IP 相关策略当作访客级策略。

## 当前实现的目标信任链

当前通过 `EDGE_MODE` 生成 `current/00-edge.conf`：direct 不信任来源头，cloudflare 使用官方 CIDR，trusted-proxy 使用显式代理 CIDR。所有模式都会重建 `X-Real-IP` / `X-Forwarded-For` 并删除其他来源头。下面以 Cloudflare 模式说明；NGINX 自身以原始 TCP 对端限制可信代理，主机/云防火墙提供额外防护，SafeLine 还必须配置回环信任。普通 DNS 直连及其他代理见[通用服务器部署](general-server-deployment.md)。

```text
访客 IP
  -> Cloudflare（受信代理）
  -> Sentinel
       验证 TCP 对端属于 Cloudflare 官方网段
       从 CF-Connecting-IP 恢复 $remote_addr = 访客 IP
       保留 $realip_remote_addr = Cloudflare 边缘 IP 供审计
       删除外部传入的代理链，生成单值 X-Real-IP/X-Forwarded-For
  -> SafeLine（只信任来自 127.0.0.1 的 Sentinel）
       从 Sentinel 生成的头恢复访客 IP
  -> 业务上游
```

必须按以下顺序实施。

### 1. 先封闭源站

主机防火墙和云服务商防火墙都应将公网 80/443 的来源限制为 Cloudflare 官方 IPv4 和 IPv6 网段。保留回环地址用于本机健康检查；SSH、SafeLine 管理端等端口使用各自独立的最小允许规则。

Cloudflare 会提前公布网段变更。网段应从官方列表或 API 定期同步，并在语法检查成功后原子更新；不要在文档中复制一份长期不更新的静态列表。

### 2. Sentinel 只信任 Cloudflare 网段

确认 Nginx 构建包含 `ngx_http_realip_module` 后，在 `http` 或对应 `server` 层加载由官方 Cloudflare 网段生成的配置：

```nginx
# 每个 Cloudflare 官方 CIDR 一行：
set_real_ip_from <cloudflare-cidr>;
real_ip_header CF-Connecting-IP;
real_ip_recursive off;
```

严禁使用以下配置：

```nginx
set_real_ip_from 0.0.0.0/0;
set_real_ip_from ::/0;
```

只有原始 TCP 对端命中 `set_real_ip_from` 时，Nginx 才会使用 `CF-Connecting-IP` 替换 `$remote_addr`。此后向 SafeLine 发送规范化的单值头：

```nginx
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header CF-Connecting-IP "";
```

最后一行删除供应商专用头，避免下游同时存在多个互相冲突的“真实 IP”来源。Sentinel 日志应同时记录 `$remote_addr`（恢复后的访客 IP）、`$realip_remote_addr`（实际连接的 Cloudflare 节点）和 `$http_cf_ray`（Cloudflare 请求标识）。

### 3. SafeLine 只信任 Sentinel 回环连接

要让 SafeLine 的 Nginx 日志和依赖 `$remote_addr` 的模块统一看到访客 IP，应在 SafeLine 的 `http` 层使用等价配置：

```nginx
set_real_ip_from 127.0.0.1;
real_ip_header X-Real-IP;
real_ip_recursive off;
```

SafeLine 的站点文件由管理端生成，直接修改 `resources/nginx/sites-enabled/IF_backend_1` 可能在站点编辑或升级时被覆盖。实施前必须确认当前 SafeLine 版本支持的持久化自定义入口；若只能使用独立的 `conf.d` include，也要把升级后的配置保留检查加入验收流程。

若业务上游需要 XFF，SafeLine 应重新生成单值或明确的可信链，而不是继续追加造成重复值。当前静态站点不读取 XFF，但未来接入应用时必须单独验证。

## SafeLine 控制台中的“来源 IP 获取方式”

在 Sentinel 已启用 Cloudflare real-IP、且源站只允许 Cloudflare 到达 80/443 后，SafeLine
站点的来源 IP 获取方式选择：

```text
从 HTTP Header 中获取
Header 名称：X-Real-IP
```

原因是链路已经被 Sentinel 规范化为：

```text
访客 IP -> Cloudflare -> Sentinel $remote_addr -> X-Real-IP -> SafeLine
```

选项对照：

| 雷池选项 | 本链路是否选择 | 原因 |
| --- | --- | --- |
| 从网络连接中获取 | 否 | SafeLine 的 TCP 对端是 `127.0.0.1`（Sentinel） |
| XFF 上一级/上上一级/上上上一级 | 否 | 本链路不应依赖固定多跳索引，部署变化会导致取错地址 |
| 从 X-Forwarded-For 中获取 | 仅作兼容备选 | 当前 Sentinel 已生成单值 XFF，但 X-Real-IP 更明确 |
| 从 HTTP Header 中获取 | **是** | 指定 `X-Real-IP`，单值且由 Sentinel 重建 |
| 从 PROXY Protocol 中获取 | 否 | Sentinel 和 SafeLine listener 没有启用 PROXY Protocol |

不要把 `CF-Connecting-IP` 直接填给 SafeLine。该头只应在 Sentinel 已验证 TCP 对端属于
Cloudflare 官方网段后使用；本架构由 Sentinel 把结果转换成 `X-Real-IP`。也不要在源站
仍可绕过 Cloudflare 时信任任何代理头，因为直连者可以自行伪造它们。

修改后用两个不同公网出口触发无害的 SafeLine 事件，确认事件来源分别显示测试出口 IP，
而不是 `127.0.0.1` 或 Cloudflare 节点。SafeLine 升级、站点重新发布或 Sentinel 配置
变化后必须重新检查 Header 名称和事件来源。

## 本仓库的边界实现

仓库中的实现文件如下：

- `nginx/cloudflare-realip.conf`：仅包含 Cloudflare 官方 IPv4/IPv6 网段，并以
  `CF-Connecting-IP` 恢复 Sentinel 的 `$remote_addr`。
- `safeline/sentinel-realip.conf`：SafeLine 只信任回环地址上的 Sentinel，并从
  Sentinel 生成的 `X-Real-IP` 恢复来源。
- `scripts/harden-deployment.sh`：收紧 TLS 与业务监听，安装 real-IP、移动公开备份并安全发布；Tailscale 管理保护是可选项。
- `scripts/apply-network-boundary.sh`：按入口模式和实际公网网卡规划/插入 UFW 规则，不清空现有规则或改变管理方式。

部署后的端口边界为：

| 端口 | 允许来源 | 用途 |
| --- | --- | --- |
| 80/443 | direct 直连；代理模式为已声明可信网段 | 公网站点 |
| SSH 端口 | 现有经过审核的管理规则 | SSH 管理，非必须 Tailscale |
| 9443 | `127.0.0.1` | SafeLine 管理平台 |
| 10443、10444… | `127.0.0.1` | Sentinel 到每个 SafeLine 业务 listener |
| 127.0.0.1:18090（可配） | 仅本机 | 独立健康检查 |

在 `.env` 指定真实 `PUBLIC_INTERFACE`，先审阅计划。apply 仅在 UFW 已启用时执行，保留 SSH/其他规则，不假设网卡为 eth0，也不自动改变默认策略。无 UFW 的服务器应使用自己的 nftables/云安全组；管理修改之前始终保留独立 SSH/控制台和第二条会话。

执行：

```bash
cd /path/to/Sentinel
./scripts/apply-network-boundary.sh plan
sudo ./scripts/apply-network-boundary.sh apply
```

管理访问可以使用 SSH 隧道、VPN，或可选的 [Cloudflare Tunnel + Access](cloudflare-tunnel-access.md)：

```bash
ssh -N -L 9443:127.0.0.1:9443 <admin-user>@<management-ip>
```

然后访问 `https://127.0.0.1:9443`。来源网段与管理规则修改后从第二个终端重新验证；防火墙辅助脚本不提供原来的全量规则替换/定时回滚模式，也不要求 Cloudflare/Tailscale。

每次 Cloudflare 公布网段变更后，必须先更新 `nginx/cloudflare-realip.conf`，逐项与
官方列表核对，再重新运行配置检查。遗漏新网段会导致对应 Cloudflare 节点无法访问
源站；保留已撤销网段则会扩大可信代理边界。

## 验收清单

来源恢复上线前后都要保留证据，不能只检查页面是否可访问。

1. 从两个不同公网出口访问，Sentinel 日志中的访客 IP 应分别等于各自公网 IP；Cloudflare 节点 IP 应记录在独立字段。
2. 在 SafeLine 触发一条无害的测试事件，控制台事件来源应等于测试出口 IP，而不是 `127.0.0.1` 或 Cloudflare 网段。
3. 业务上游若存在，确认其 IP 字段只使用规范化后的可信头。
4. 直连源站地址（示例 `192.0.2.10:443`）应被防火墙丢弃或拒绝，不能返回站点内容。
5. 直连时伪造 `CF-Connecting-IP: 1.2.3.4` 不得改变任何日志或访问控制结果。
6. IPv4、IPv6、WebSocket、Cloudflare Worker（若有）分别测试。
7. 更新 Cloudflare 网段或 SafeLine 后，执行 Nginx 配置检查和本清单回归。

## 官方参考

- [Cloudflare：HTTP 请求头](https://developers.cloudflare.com/fundamentals/reference/http-headers/)
- [Cloudflare：恢复访客 IP](https://developers.cloudflare.com/support/troubleshooting/restoring-visitor-ips/restoring-original-visitor-ips/)
- [Cloudflare：保护源站](https://developers.cloudflare.com/fundamentals/security/protect-your-origin-server/)
- [Cloudflare：官方 IP 网段与更新说明](https://developers.cloudflare.com/fundamentals/concepts/cloudflare-ip-addresses/)
- [Cloudflare：IP API](https://developers.cloudflare.com/api/resources/ips/)
- [Nginx：ngx_http_realip_module](https://nginx.org/en/docs/http/ngx_http_realip_module.html)
- [SafeLine：反向代理工作方式](https://docs.waf.chaitin.com/en/GetStarted/AddApplication)
