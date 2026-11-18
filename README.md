<p align="center">
  <img src="assets/sentinel-logo.svg" width="560" alt="Sentinel — Safe Edge Gateway">
</p>

# Sentinel

[![License: AGPL-3.0-or-later](https://img.shields.io/badge/License-AGPL--3.0--or--later-0b7a75.svg)](LICENSE)

Sentinel 是部署在 [SafeLine CE（雷池社区版）](https://waf-ce.chaitin.cn/) 前面的独立 NGINX 边缘网关。它把所有业务域名收敛到服务器的一组公网入口 `80/443`，提供 TLS、SNI/Host 路由、可信客户端 IP 传递和统一安全响应头；SafeLine 继续负责 WAF 检测、站点规则和到业务应用的转发。

它不是 SafeLine 的分支、插件或替代品，也不会修改 SafeLine 镜像、二进制或控制台生成逻辑。

重启/网络更新后的监听隔离、端口归属检查和可选自动恢复见[运行恢复机制](docs/runtime-recovery.md)。

## 工作链路

```text
                    公网业务数据面
访客
  │ HTTPS
  ▼
普通 DNS 直连，或 Cloudflare / 其他可信 HTTP 代理
  │ direct 接受直接连接；代理模式只接受明确的代理网段
  ▼
Sentinel（宿主机公网 IP :80/:443）
  │ 按 EDGE_MODE 识别来源 IP，TLS、Host 路由、安全头
  ├───────────────┬───────────────────────┐
  ▼               ▼                       ▼
SafeLine       SafeLine                SafeLine
127.0.0.1:10443 127.0.0.1:10444 ...    127.0.0.1:10446
  │               │                       │
  ▼               ▼                       ▼
应用 A           应用 B                  应用 C
（回环或私网）    （回环或私网）           （回环或私网）
```

SafeLine 管理面与业务数据面分离：

```text
管理员 → SSH 本地端口转发、VPN、Access + Tunnel 或 Tailscale Serve
       → SafeLine 127.0.0.1:9443
```

管理端 `9443` 不经过 Sentinel，也不应在 SafeLine 中创建一个“反代 SafeLine 自己”的业务站点。

## 端口模型

每个业务域名不需要独占公网端口。浏览器通过 TLS SNI 和 HTTP `Host` 区分站点，因此所有域名共享 Sentinel 的 `80/443`。

| 端口/地址 | 所属层 | 可达范围 | 用途 |
| --- | --- | --- | --- |
| `<本机入口 IP>:80` | Sentinel | direct 公网；代理模式仅可信网段 | HTTP，重定向至 HTTPS |
| `<本机入口 IP>:443` | Sentinel | direct 公网；代理模式仅可信网段 | 所有业务域名的 TLS 入口 |
| `127.0.0.1:18090`（可配） | Sentinel | 仅本机 | 无 DNS / TLS 依赖的健康检查 |
| `127.0.0.1:10443`、`10444`… | SafeLine | 仅本机 | Sentinel 到各业务站点的 WAF listener |
| 应用端口 | 应用 | 回环或私网 | 仅由 SafeLine 访问 |
| `127.0.0.1:9443` | SafeLine 管理面 | Tunnel/Tailscale/本机 | 管理控制台，不是业务上游 |

**新增站点时新增的是 SafeLine 的内部回环端口，而不是新的公网端口。** Sentinel 的站点清单拒绝把业务上游设为非 `127.0.0.1` 地址，也拒绝两个业务站点复用同一个 SafeLine listener 端口。

## 快速开始

### 新服务器一行安装

适用于已有 SafeLine CE 的 Linux 服务器。准备好 Git、Bash、Python 3.10+、OpenSSL、iproute2、rootful Docker 和 Compose v2。在雷池中建好业务域名及 HTTP 回环 listener，配置来源头 `X-Real-IP` 和下文的 real-IP include。将域名证书和私钥放在 root 管理的专用目录，保留独立 SSH 管理通道。入口 IP 的 80/443 须可供 Sentinel 使用。

从包含本安装器的 GitHub 发布提交复制完整的 40 位 SHA，在 Bash 运行下面一行并按提示粘贴。命令下载仓库，检出指定版本，从 root 管理的全新目录运行安装向导。先确认该提交来自你审核过的版本。

```bash
read -rp '发布提交 SHA（40 位）: ' rev && [[ $rev =~ ^[0-9a-f]{40}$ ]] && sudo mkdir -m 0755 /opt/sentinel && sudo git clone --no-checkout https://github.com/Steven-ZYC/Sentinel.git /opt/sentinel && sudo git -C /opt/sentinel checkout --detach "$rev" && sudo /opt/sentinel/sentinel install
```

向导收集入口地址、域名、证书路径和雷池端口，写入权限为 `0600` 的配置。它会先核对管理面、上游 socket 归属、证书及候选 NGINX 配置，再提示输入 `deploy` 发布。复用已有完整配置或修正预检错误后，运行 `sudo /opt/sentinel/sentinel install`。已启用 Tailscale 管理转发时给安装命令加 `--tailscale`。雷池业务容器名称不同于 `safeline-tengine` 时，在 `.env` 设置 `SAFELINE_CONTAINER` 后重试。

生产用的代码、Compose 文件、配置和父目录须由受信管理员控制。旧部署若位于普通用户可写的工作区，请在维护窗口迁移到受保护的目录，并核对旧容器归属和回退路径。从新目录运行 CLI 会拒绝接管另一目录的同名容器。

| 业务请求从哪里到达 | 向导中填写 | 站点配置 |
| --- | --- | --- |
| Cloudflare 橙云 | `cloudflare` | 使用 Full (strict)，源站按 Cloudflare CIDR 放行 |
| 企业自有 DNS、内网分域解析、Cloudflare 灰云 | `direct` | A/AAAA 指向对应入口，客户端信任站点证书 |
| 企业负载均衡或其他 CDN | `trusted-proxy` | 输入受控代理的 CIDR 和它维护的来源头 |

安装使用服务器已有的 DNS 解析设置。向导按流量路径选择信任策略，所有模式均无需 DNS API 凭据。旧版配置缺少 `EDGE_MODE` 时，发布会停止，须先按上表明确选择。启用 AAAA 前须配置本机入口 IPv6。使用企业 CA 时，给访问端配置信任链，验收可传 `--ca-file`。

同一实例可接入由不同 DNS 服务商解析的域名，所有站点共用一个入口信任模式。例如，两家 DNS 服务商都把业务域名解析到服务器时可共用 `direct`；同时承载仅限橙云的站点和允许公网直连的站点，需要独立入口策略，当前向导仅配置单一模式。

```bash
cd /opt/sentinel
sudo ./sentinel check                     # 校验候选配置
sudo ./sentinel deploy                    # 发布修改并核对运行摘要
sudo ./sentinel status                    # 核对运行版本、TLS、端口与归属，退出码表示结果
./sentinel verify https://app.example.com # 验收访客实际经过的 HTTPS 链路
```

默认使用 2 个 NGINX worker，容器内存上限 512 MiB，请求与响应临时缓冲共用 128 MiB 的 cache tmpfs，容器日志轮转保留 3 个 10 MiB 文件。大文件、慢客户端或高并发可能耗尽缓冲并产生请求错误。按实际流量在 `.env` 调整 `SENTINEL_MEMORY_LIMIT` 和 `SENTINEL_CACHE_SIZE`，为同机雷池保留余量后重新发布。可选的防火墙和恢复 timer 见[通用服务器部署](docs/general-server-deployment.md)。

### 前提

- Docker Engine 与 Docker Compose v2；运行账户需要访问 Docker。
- Python 3.10+（只使用标准库，无 `pip` 依赖）。
- 已部署 SafeLine CE，且每个业务站点能在控制台配置独立 HTTP listener。
- 任意 DNS 服务商均可：普通 A/AAAA 直连使用 `EDGE_MODE=direct`，证书必须由客户端信任的 CA 签发并覆盖每个域名。Cloudflare、Tailscale 均非必需。
- 仅在使用 Cloudflare 橙云时选择 `EDGE_MODE=cloudflare`，并配置 `Full (strict)`；其他 CDN/负载均衡使用 `trusted-proxy` 和明确的代理 CIDR。参见[通用服务器部署](docs/general-server-deployment.md)。
- 服务器仍有 SSH 或云控制台等独立管理通道。

### 1. 创建全局环境和站点清单

```bash
cd /path/to/Sentinel
cp .env.example .env
cp sites.example.json sites.json
chmod 600 .env sites.json
```

编辑 `.env`：

```dotenv
# Sentinel 只绑定这一个公网 IPv4；不要填写 0.0.0.0。
PUBLIC_LISTEN_ADDR=203.0.113.10
EDGE_MODE=direct
HEALTHCHECK_PORT=18090

# 此宿主机目录会只读挂载为容器内 /etc/sentinel/tls。
# sites.json 中的每个 certificate/private_key 必须位于该目录下。
TLS_MOUNT_ROOT=/etc/sentinel/tls

# 仅用于 TLS 默认虚拟主机拒绝未知 Host。
DEFAULT_TLS_CERT_PATH=/etc/sentinel/tls/app.example.com/fullchain.pem
DEFAULT_TLS_KEY_PATH=/etc/sentinel/tls/app.example.com/privkey.pem
```

`.env` 保留全局监听地址、证书根目录和默认 TLS 证书。Compose 将 `TLS_MOUNT_ROOT` 只读挂载到容器内固定的 `/etc/sentinel/tls`；渲染器会拒绝任何不位于该根目录下的站点证书路径。业务域名、业务证书、SafeLine listener 与安全策略都写入 `sites.json`；它默认被 Git 忽略，避免把真实域名和主机路径误提交。

### 2. 编写 `sites.json`

一个最小代理站点如下：

```json
{
  "version": 1,
  "sites": [
    {
      "name": "app",
      "type": "proxy",
      "domain": "app.example.com",
      "certificate": "/etc/sentinel/tls/app.example.com/fullchain.pem",
      "private_key": "/etc/sentinel/tls/app.example.com/privkey.pem",
      "upstream": {
        "address": "127.0.0.1",
        "port": 10443,
        "scheme": "http"
      },
      "security": {
        "content_security_policy": "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; img-src 'self' data: https:; font-src 'self' data: https:; style-src 'self' https:; script-src 'self' https:; connect-src 'self' https: wss:; upgrade-insecure-requests",
        "permissions_policy": "accelerometer=(), autoplay=(), camera=(), display-capture=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"
      }
    }
  ]
}
```

完整的多站点和重定向示例见 [sites.example.json](sites.example.json)。清单中的字段含义如下。

| 字段 | 适用类型 | 说明 |
| --- | --- | --- |
| `name` | 全部 | 小写名称，仅用于稳定生成 NGINX 文件名与 upstream 名称。 |
| `type` | 全部 | `proxy`（业务站点）或 `redirect`（永久跳转）。默认是 `proxy`。 |
| `domain` | 全部 | 单个、精确的业务 hostname；不接受通配符。 |
| `certificate` / `private_key` | 全部 | 该 hostname 的证书和私钥绝对路径。证书文件不进入仓库。 |
| `upstream` | `proxy` | 必须是 `127.0.0.1`、唯一端口和 `http`；即对应 SafeLine listener。 |
| `security` | `proxy` | 该站点的 CSP 和 Permissions-Policy，必须基于真实浏览器报错调整。 |
| `client_max_body_size` | `proxy`，可选 | 如 `30m`；仅在上传需求与默认 20m 不同时填写。 |
| `redirect_to` | `redirect` | 目标 HTTPS origin，例如 `https://app.example.com`；请求路径和查询串会保留。 |

每个站点都使用自己的证书路径。即使多个域名正好由同一张通配符证书覆盖，也要在每个站点条目中显式声明，便于日后分区、轮换和审计。

### 3. 生成与预检

```bash
sudo python3 scripts/harden_deployment.py tls
sudo ./scripts/preflight.sh
```

预检在 `nginx/generated/.revisions/` 暂存完整候选配置，不切换正在运行的版本。它会确认：

- 清单字段、域名、端口、回环上游与生成文件有效；
- 私钥 root:root `0600`、证书目录 `0750`；证书覆盖站点、匹配私钥且至少还有七天有效期；
- 每个 SafeLine listener 都实际存在且**只监听** `127.0.0.1:<port>`；
- Docker Compose 和生成后的 NGINX 配置均可通过语法检查。

若 Docker 仅允许 root 访问，请使用 `sudo ./scripts/preflight.sh`。不要跳过预检后直接重载生产入口。

### 4. 启动或更新 Sentinel

```bash
sudo ./scripts/deploy-proxy.sh
sudo docker compose ps
sudo docker compose logs --tail=100 proxy
./scripts/verify.sh https://app.example.com
```

修改 `sites.json`、证书路径或 `.env` 后，始终重新运行：

```bash
sudo ./scripts/preflight.sh
sudo ./scripts/deploy-proxy.sh
```

发布脚本先验证完整候选，再原子切换 `current`，显式重建/重载并核对运行配置摘要；失败恢复上一版本及镜像。重建可能短暂中断流量，请安排维护窗口。`docker compose up -d` 单独执行不保证站点配置生效。离线调用渲染器不会重载线上 NGINX。

渲染器生成一个 TLS 默认虚拟主机，未知 `Host` 返回 `421`（代理模式下不可信对端先返回 `403`），不会被错误发送到第一个业务上游。

## 给新业务站点分配端口

以 `new.example.com` 为例，假设当前已使用 `10443` 和 `10444`：

1. 选择尚未使用的内部端口，例如 `10446`。不要使用 `80`、`443` 或 SafeLine 管理端 `9443`。
2. 在 SafeLine 控制台创建业务站点：`Domain = new.example.com`、监听协议为 **HTTP**、端口为 `10446`、上游为应用的回环或私网地址。
3. 保存并发布后，将 SafeLine listener 收口到回环：

   ```bash
   cd /path/to/Sentinel
   UPSTREAM_PORT=10446 ./scripts/safeline-listener.sh check
   sudo UPSTREAM_PORT=10446 ./scripts/safeline-listener.sh apply
   ss -ltn 'sport = :10446'
   ```

   正确结果必须是 `127.0.0.1:10446`，而不是 `0.0.0.0:10446`。SafeLine 控制台重新发布站点或升级后可能重建其 NGINX 文件；每次都重新执行 `check`。

4. 将新对象加入 `sites.json`，并填写该域名自己的证书路径和 `127.0.0.1:10446` 上游。
5. 在所选 DNS 服务商创建 A/AAAA 记录，确认实际代理模式和证书。直连不要使用 Cloudflare Origin CA 证书。
6. 渲染、预检并更新 Sentinel：

   ```bash
   sudo ./scripts/preflight.sh
   sudo ./scripts/deploy-proxy.sh
   ./scripts/verify.sh https://new.example.com
   ```

不为 `10446` 添加公网防火墙放行规则。它是 Sentinel 与 SafeLine 的本机链路，而不是客户端入口。

## 安全边界

### 客户端 IP

`direct` 使用连接来源 IP，忽略客户端伪造的代理头；`cloudflare` 信任官方 CIDR 的 `CF-Connecting-IP`；`trusted-proxy` 仅信任显式 CIDR 与指定头。代理模式还基于原始 TCP 对端执行 NGINX 来源 ACL。三种模式都重建单值 `X-Real-IP` / `X-Forwarded-For`，删除其他来源头。

SafeLine 侧必须加载 [safeline/sentinel-realip.conf](safeline/sentinel-realip.conf)，并在控制台选择“从 HTTP Header 获取”、Header 为 `X-Real-IP`。不要信任任意来源的 `CF-Connecting-IP`，不要选择 PROXY Protocol，也不要使用 `set_real_ip_from 0.0.0.0/0` 或 `::/0`。

完整说明见 [访问来源 IP 的识别与传递](docs/client-ip-provenance.md)。

### 网络与管理面

- 主机与云防火墙按模式放行公网 `80/443`；`scripts/apply-network-boundary.sh plan` 先审阅方案，配置实际 `PUBLIC_INTERFACE` 后才 `apply`。不清空现有规则，不依赖固定网卡名。
- 所有 SafeLine 业务 listener 必须为 `127.0.0.1:<port>`；应用端口同样应在回环或私网。
- 管理端 `9443` 仅回环，通过 SSH 隧道或 VPN 访问；Cloudflare Tunnel + Access 或 Tailscale Serve 为可选方案。参见 [通用部署](docs/general-server-deployment.md)、[Tunnel 指南](docs/cloudflare-tunnel-access.md) 和 [Tailscale 指南](docs/tailscale-management.md)。
- 当前服务器若发现 `10445` 或 `9443` 仍绑定 `0.0.0.0` / `[::]`，这不是 Sentinel 可接受的最终边界；请在独立变更窗口使用对应文档收口。本项目不会在 `docker compose up` 时自动修改它们。

## 从旧版单站点配置迁移

旧版以 `DOMAIN`、`UPSTREAM_PORT`、`GBA_DOMAIN` 等 `.env` 变量和 NGINX 模板定义站点。迁移脚本可从旧 `.env` 生成新的清单，默认只打印结果：

```bash
./scripts/migrate-legacy-env.py > /tmp/sites.json
# 若旧 Compose 有独立的跳转域名，也一并声明：
./scripts/migrate-legacy-env.py --redirect legacy.example.com=https://app.example.com > /tmp/sites.json
# 审阅 /tmp/sites.json 后：
./scripts/migrate-legacy-env.py --write \
  --redirect legacy.example.com=https://app.example.com
sudo ./scripts/preflight.sh
sudo ./scripts/deploy-proxy.sh
```

迁移期内，渲染器会临时接受旧的 `TLS_CERT_PATH` / `TLS_KEY_PATH` 作为默认 TLS 证书来源；仍需在 `.env` 设置包含这些文件的 `TLS_MOUNT_ROOT`。完成验证后应改为 `DEFAULT_TLS_CERT_PATH` / `DEFAULT_TLS_KEY_PATH`。旧业务变量不再被 Compose 使用，应在确认新入口正常后从 `.env` 删除。

部署前后都应保留 SSH/云控制台。回滚时停止 Sentinel 释放 `80/443`，再在 SafeLine 控制台恢复原监听端口并发布；详细步骤见 [SafeLine 迁移与回滚](docs/safeline-migration.md)。

## 验收清单

每个业务域名至少检查：

1. `http://<domain>` 以 `308` 跳转到相同 host 的 HTTPS；
2. TLS 1.0/1.1 被拒绝，TLS 1.2/1.3 正常；
3. 未知 Host 返回 `421`，不会命中任一应用；
4. SafeLine 控制台和应用日志看到正确、不可伪造的客户端 IP；
5. 对应域名命中自己的 SafeLine 规则和应用上游；
6. 登录、上传、API、WebSocket、错误页与 CSP 均经回归验证；
7. 对公网无法连接任何 SafeLine 内部 listener；代理模式不能绕过所选可信代理，所有模式都不能绕过 Sentinel/WAF。

`scripts/verify.sh https://<domain>` 提供 TLS、安全头和 TRACE 的基础检查；完整安全扫描验收见 [Acunetix 验收标准](docs/acunetix-acceptance.md)。

## 常见问题

**`generated NGINX configuration is out of date`**

运行 `sudo ./scripts/deploy-proxy.sh`。生成文件不是手写配置；修改清单后必须验证、发布并核对运行版本。

**预检提示 SafeLine listener 不是 loopback-only**

先在 SafeLine 控制台发布端口变更，再运行：

```bash
UPSTREAM_PORT=<port> ./scripts/safeline-listener.sh check
sudo UPSTREAM_PORT=<port> ./scripts/safeline-listener.sh apply
```

**为什么不能在清单中填写应用的 `10.x.x.x:port`？**

Sentinel 的唯一上游应是本机 SafeLine。应用地址应由 SafeLine 控制台的站点配置管理；这样业务请求不会绕过 WAF。

**为什么未知域名的 TLS 证书可能不匹配？**

TLS 握手发生在 HTTP Host 路由之前。默认虚拟主机必须使用一张有效证书才能完成握手，然后返回 `421`；它不应被理解为给未知域名提供服务。

## 开源许可证

Copyright (c) 2026 Steven Zhang.

本项目以 [GNU Affero General Public License v3.0 or later](LICENSE)（`AGPL-3.0-or-later`）发布。若你修改并通过网络向用户提供本项目或其衍生版本，AGPL 要求向这些用户提供相应源代码。
