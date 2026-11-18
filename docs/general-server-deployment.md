# 通用服务器部署与安全修复

DNS 解析服务商与 HTTP 代理是两回事。阿里云、腾讯云、Route 53、普通权威 DNS，以及 Cloudflare 的 DNS-only 记录，都可以用于 Sentinel。Docker Engine、Compose v2、Python 3.10+、OpenSSL 和本机 SafeLine 是运行前提；Tailscale、Cloudflare、systemd/UFW 仅相应可选功能需要。

当前采用 rootful Docker 的宿主机网络模型；rootless Docker、userns-remap 和跨主机/Kubernetes 不是直接支持的部署形态，需要另行设计网络与证书读取权限。此处的“通用”不代表跳过这些运行前提。

## 选择入口模式

| 场景 | `.env` | 客户端 IP 与入口限制 |
| --- | --- | --- |
| 普通 A/AAAA 直连、Cloudflare 灰云 | `EDGE_MODE=direct` | 使用连接来源；忽略声称真实 IP 的客户端头 |
| Cloudflare 橙云 | `EDGE_MODE=cloudflare` | 只接受官方代理 CIDR，读取 `CF-Connecting-IP` |
| 其他 CDN / 负载均衡 | `EDGE_MODE=trusted-proxy` | 显式配置代理 CIDR 与头，拒绝其他连接对端 |

其他代理示例（替换为实际代理地址，勿照抄）：

```dotenv
EDGE_MODE=trusted-proxy
TRUSTED_PROXY_CIDRS=10.20.0.0/24,2001:db8:abcd::/48
REAL_IP_HEADER=X-Forwarded-For
```

`X-Forwarded-For` 使用从右到左的可信代理链解析；单值头可选择 `X-Real-IP`。上游代理必须正确覆盖/追加来源头。禁止 `0.0.0.0/0`、`::/0`，勿把不受控客户端网段加入信任列表。经过代理但选择 direct 不会信任伪造头，不过将记录代理节点而非访客 IP。

`PUBLIC_LISTEN_ADDR` 填服务器实际拥有的明确 IPv4；NAT 部署填本机入口地址，不是并未分配到网卡的公网地址。可选 `PUBLIC_LISTEN_IPV6` 填明确 IPv6；仅启用后才发布对应 AAAA。不要使用 `0.0.0.0`、`::`，避免与 VPN 管理入口冲突。确保路由/NAT/云安全组将 80/443 送到指定地址。

### 其他公网 IPv4 服务器与 Tailscale 共存

这不是当前主机专用修复。同一套部署/启动/运行检查使用各服务器自己的地址和接口：

```dotenv
# 文档示例地址，替换为这台服务器实际分配的入口 IPv4。
PUBLIC_LISTEN_ADDR=192.0.2.81
# 可留空；填写时校验该接口或其别名，不假定 eth0/ens3。
PUBLIC_INTERFACE=enp5s0
# 默认为 tailscale0；自定义 TUN 时填实际名称，例如 ts-vpn0。
TAILSCALE_INTERFACE=tailscale0
EDGE_MODE=direct
```

Sentinel 只能监听此入口 IP 的 TCP 80/443；Tailscale 的 HTTPS 443 留在此服务器的
Tailnet IP 上，因此不依赖谁先启动，也不要求 Cloudflare。Tailscale 未启动时不阻止
公网入口；入口地址尚未分配时有限等待，绝不退回 0.0.0.0 或选择 Tailnet IP。
公网地址改变后须更新配置并完整发布，不会根据 VPN 默认路由自动替换入口地址。

TAILSCALE_INTERFACE 必须与 daemon 的实际 TUN 名称一致；这个配置只用于隔离检查，
不会重命名网卡或修改 Tailscale。自定义名称对应官方的
[`tailscaled --tun=NAME`](https://tailscale.com/docs/reference/tailscaled)。部署时生成
经校验的接口元数据，使宿主机守护和容器重启后的检查一致。

有 systemd 时以 tailscaled.service 的 MainPID 核对监听归属；非 systemd 主机只认可
唯一一个 root 运行、已加载可执行文件为 root 所有且不可由组/其他用户写入的
tailscaled。无法读取、多个 daemon 或无法确认身份时拒绝放行，不能仅凭进程名
信任占用者。非 systemd 的周期恢复需接入现有调度器，项目不会擅自安装新服务管理器。

保证范围是受支持的 Linux/rootful Docker host-network 与正确配置下不产生重叠监听。
若其他 root 进程、旧反代或异常 Tailscale 配置已监听通配/公网 80/443，安装/发布会
拒绝并报告实际 PID，而不是杀进程、抢绑定或宣称网站仍可用。该项目不提供对第三方
root 操作的内核强制限制。Tailscale userspace-networking/独立网络命名空间不能套用
这里的宿主机 TUN/PID 检查，需单独设计；不要为通过检查而把入口设成 Tailnet 地址。

## 证书与管理面

直连必须使用浏览器信任的证书，例如公共 CA 签发的证书。Cloudflare Origin CA 只适合 Cloudflare 代理到源站，不适合普通 DNS 直连。ACME HTTP-01/DNS-01 的选择和 DNS 插件取决于服务商，Sentinel 不要求某一家 DNS API。所有证书应位于专用 `TLS_MOUNT_ROOT`；若使用 ACME 符号链接，该根目录必须同时覆盖链接解析后的实际文件，例如 `/etc/letsencrypt`。

私钥由容器 root 主进程读取：root:root `0600`，证书 `0644`，相关目录 `0750`。证书根目录的上级路径也需 root 所有且不可由其他用户写入，建议 `/etc` 或 `/data` 下专用目录；加固通过 no-follow 文件描述符操作，拒绝不安全的路径。容器删除了 `CAP_DAC_OVERRIDE`，仅改成普通用户所有的 `0600` 可能导致读取失败。续期后重新执行 TLS 加固与发布；不要输出或提交私钥。

SafeLine 管理端映射应为 `127.0.0.1:9443`，所有业务 listener 为 `127.0.0.1:<独立端口>`（可附加 `::1`，禁止任何非回环地址）。普通服务器可以使用 SSH：

```bash
ssh -N -L 9443:127.0.0.1:9443 admin@server
```

浏览器访问本地 `https://127.0.0.1:9443`；管理端自签证书仅限这一受控本地链路，不能因此关闭公网 HTTPS 校验。修改管理绑定前保留 SSH/云控制台并验证第二条会话。Tailscale 用户可使用专门的绑定/升级守护脚本；守护检查禁止 Funnel、额外路由和任何未经批准的监听地址。

## 应用已有部署的修复

检查 `.env` 的模式，尤其旧版 Cloudflare 部署要显式写 `EDGE_MODE=cloudflare`，不能沿用示例默认 direct。在维护窗口执行：

```bash
cd /path/to/Sentinel
sudo ./scripts/harden-deployment.sh
# 已使用 Tailscale Serve 的主机改为：
# sudo ./scripts/harden-deployment.sh --tailscale
```

这会校验管理边界，收紧已声明证书权限，备份并限制全部业务 listener，安装 SafeLine 回环 real-IP 配置，将已知公开旧网页备份移到非 webroot 的 `backups/sentinel/site/`，然后验证、发布 Sentinel。不会更改 DNS、重置 UFW、自动开启 Tailscale、执行在线升级或轮换 CA 证书。非默认 SafeLine 路径通过 `SAFELINE_DIR` 配置；网页目录可单独用 `harden_deployment.py backups --webroot ... --backup-root ...` 处理。

SafeLine 检测模块仍需在控制台选择来源 Header `X-Real-IP`，并用实际请求验证控制台事件与应用日志。NGINX 层 real-IP 生效不等于证明每个 SafeLine 版本的检测模块选项都已配置。

## 日常发布与验收

```bash
sudo ./scripts/preflight.sh
sudo ./scripts/deploy-proxy.sh
./scripts/verify.sh https://app.example.com
```

预检不会切换 current；发布使用完整 `.revisions/`、原子符号链接、发布锁、候选 `nginx -t`、显式重建/重载和回环健康端点配置摘要核验。失败恢复上一配置与镜像。挂载的是稳定 `nginx/generated/` 根目录，不是某个会被替换的目录 inode。历史版本保留用于恢复；生产更新不要单独使用渲染器或 `docker compose up -d`。重建有短暂中断，非无停机发布。

发布会安装 root-owned 的启动检查快照，验证最终监听地址、入口网卡与 socket 进程归属。
systemd 主机的 harden 流程还安装独立公网恢复 timer，不要求 Tailscale/Cloudflare；
非 systemd 主机仍有容器启动检查和 Docker restart policy，可由现有调度系统以 root
调用受保护的 `runtime_guard.py reconcile-public`。权限不明、手动停止或配置异常不会
强制恢复。详见[监听隔离与恢复](runtime-recovery.md)。

安全验收要求最终 HTTPS 成功，每个 HTTPS 跳转都必须 HSTS `max-age>=31536000`，关键安全头值正确、Cookie 标志完整；先验证 TLS 1.2，再确认 TLS 1.0/1.1 收到明确拒绝，网络失败不能算通过。私有 CA 可通过 `--ca-file` 指定，不允许跳过证书校验。

Cloudflare 用户还必须在边缘设置有效 HSTS 和 TLS 最低版本 1.2，排查 Transform Rules / Workers 覆盖源站头的问题。这是外部账户设置，源站修复无法代替。普通 DNS 直连不需要此步骤。

## 防火墙与剩余风险

设置实际 `PUBLIC_INTERFACE`，先运行 `./scripts/apply-network-boundary.sh plan`，审阅后才以 root `apply`。该脚本只在已启用 UFW 时插入限定网卡/业务端口的规则，保留 SSH 和其他规则。切换模式时重新应用，云防火墙也应保持一致。不使用 UFW 的服务器按同样边界配置 nftables/安全组；不要盲目启用 UFW 导致管理锁定。Docker 发布端口可能绕过主机普通 INPUT 规则，因此所有实际业务监听必须回环。

HTTP real-IP 仅信任回环意味着同主机不可信用户/容器仍可能连接 SafeLine 并伪造来源头；不应把这台网关当作多租户共享服务器。业务应用不得另外暴露公网入口。

曾经世界可读/目录可写的私钥必须按可能泄露处理：通过对应 CA 重签新密钥与证书，切换后撤销旧证书。仅 chmod 无法消除已发生的泄露或篡改。
