# 公网 / Tailscale 监听隔离与恢复

端口的归属由协议、本地地址和端口共同决定。Linux 上 `公网 IP:443` 与 `Tailnet IP:443`
可以共存；`0.0.0.0:443` / `[::]:443` 通配监听可能与具体地址重叠。先检查地址和 PID，
不要通过杀掉 Tailscale 或调整启动顺序掩盖重叠。

## 只读诊断

```bash
cd /path/to/Sentinel
sudo python3 scripts/runtime_guard.py inspect
sudo ss -ltnup
tailscale serve status --json
```

没有 root 时可以运行 inspect，但其他用户的 socket owner 会标为 unknown，不能据此
确认某个进程占用公网 IP。诊断包含 TCP/UDP，UDP VPN 传输端口与 TCP HTTPS 不冲突。

检查每个入口地址上的 TCP 80/443、每个 Tailnet 地址上的管理监听，以及对应的进程归属。

## 公网入口：所有 DNS 提供商适用

- 渲染和发布检查全部 include/listen 指令，包括跨行、引号、IPv6、额外 conf 文件。
  公网只能为显式入口地址的 80/443，健康端点只能为回环专用端口。
- 预检核对入口地址确实分配到本机；可核对 PUBLIC_INTERFACE 及其别名。NAT 主机填
  本机入口地址，不填云路由器上未分配给本机的公网 IP。禁止与 TAILSCALE_INTERFACE
  指定的 Tailnet 接口（默认 tailscale0）重叠。
- 发布前检查全部有关 socket 的 PID；公网/健康端口必须属于本项目容器，Tailnet
  443 必须属于经验证的 tailscaled PID。unknown owner、陌生占用和通配监听均拒绝发布。
- 实际运行核验 Docker Compose 项目身份、只读挂载、host 网络、启动脚本、PID/cgroup、
  nginx -T 最终加载文件、健康摘要和公网 TLS。TLS 直接连接入口 IP，校验证书/域名/有效期，
  并匹配所声明叶证书；不依赖 DNS/CDN ACL。这个本机证书核验不代替公网信任链验收。

容器使用 `/usr/local/libexec/sentinel/container-startup-check.sh` 的 root-owned 副本。
启动前校验 bootstrap、所有版本文件的 SHA-256 及未列入清单的额外 conf；等待显式
入口地址最多 60 秒，不退回通配监听。至少等待 10 秒再执行官方 entrypoint，避免首次
快速 bind 失败发生在 Docker restart policy 的启动监控窗口之前。候选 `nginx -t`
由发布程序显式绕过启动 entrypoint，仍执行完整静态/语法验证。

地址与接口信息由本机 .env 生成，不含当前服务器的固定 IP/网卡；.tailscale-interface
将 TAILSCALE_INTERFACE 传给容器启动检查，自定义 TUN 与默认 tailscale0 一样隔离。
不同公网 IPv4、ens18/enp5s0/bond0.7、不同 Tailnet IPv4/IPv6 和自定义 TUN 都有回归；
这些是模拟服务器参数与隔离 socket 测试，不表示已在其他真实服务器完成上线验收。
安装新代码后须完整发布新版本，并更新 root-owned 守护快照；不要单独重启旧容器。

systemd 主机优先使用 tailscaled.service MainPID；非 systemd 主机扫描 /proc，要求
唯一的 root daemon、加载中的 tailscaled 可执行文件为 root 所有且无组/其他用户写权限。
进程名伪装、未知归属、多个 daemon 或扫描不完整均不放行。加载文件因包更新标记
为 deleted 时仍核对已加载 inode，不把同路径的新文件当作旧进程身份凭据。

Docker 的 `unless-stopped` 独立负责开机、daemon 更新和进程退出后的启动；守护不会
`docker start`、创建容器或调用 compose up，因此手动停止的容器保持停止。
支持 rootful Docker host 网络；新发布需要 sudo 安装受保护的启动脚本。

## 可选的 systemd 恢复

在完成安全发布后安装（harden-deployment.sh 在 systemd 主机自动调用）：

```bash
sudo ./scripts/install-runtime-guard.sh
# 已有批准的 Tailscale Serve 部署才加装：
sudo ./scripts/install-tailscale-sentinel-guard.sh
```

公网 timer 开机 30 秒后运行，每次结束约 60–70 秒后再次检查；没有 Tailscale 或
network-online.target 硬依赖。重试窗口 60 秒，systemd 单次总时限 120 秒。地址暂时
消失、Docker 正在恢复时只等待；网络恢复后再验证。属于正常运行、明确标记
`io.sentinel.recovery=running-only` 的同一容器才能修复：确认全部安全前置条件后最多
重启一次，用完整容器 ID 而不是可被替换的名字；跨调用 300 秒冷却。停止/暂停、正在
Docker 重启、启动中、外部占用、配置漂移或上游边界异常均不会强行重启。

守护与部署共享非阻塞发布锁；部署进行中跳过恢复，不干扰版本切换。root 定时任务
执行 `/usr/local/libexec/sentinel/scripts/` 下的代码快照及受保护的 NGINX 模板，
不直接执行可写 checkout 的 Python。改变代码/全局 bootstrap 后需要显式 root
部署/重新安装快照；工作区文件仍属于可信管理员的配置输入，不用于多租户共享。

Tailscale timer 与启动恢复独立于 Docker/公网健康。只恢复空的 Serve 或已批准的
路由缺少当前节点主机名的情况；拒绝 Funnel、Foreground、Services、额外 listener/
路径/target。保留批准的 `9443 -> 127.0.0.1:9443` forward。恢复后必须看到全部已分配
Tailnet 地址的实际监听、正确 tailscaled PID，以及验证通过的 `.ts.net` 管理 HTTPS。
启动事件与 timer 共享私有锁，避免同时写 Serve。

已批准 Serve 但暂时缺少 kernel listener 时有限等待 tailscaled 自身的退避重试，
不会 reset Serve 或重启 tailscaled；持续故障记录到 journal，供人工检查。不会自动
修改 SafeLine 管理绑定、防火墙、DNS、Tailscale 登录/路由或未知配置。故意停用 Serve
前应先禁用对应 guard，否则空的批准路由会被重建。

```bash
sudo python3 scripts/runtime_guard.py check-public
sudo python3 scripts/runtime_guard.py check-tailnet
sudo journalctl -u sentinel-runtime-guard.service -u sentinel-tailscale-guard.service -n 80 --no-pager
sudo systemctl list-timers 'sentinel-*'
```

## 验证范围与维护窗口

回归包含两种启动顺序下的真实同端口/不同回环地址绑定、通配冲突、PID 误归属、缺失
Tailnet 监听、地址延迟/超时、配置漂移、重复恢复冷却、停止/暂停、Docker 重启、部署
锁和容器替换竞态。启动脚本在临时文件和模拟网络事件中执行；NGINX/TLS 使用实际
隔离实例和非生产端口。systemd 语法验证只替换尚未安装的 ExecStart 为 true。
首次恢复机制回归 79 项全部通过；通用服务器补充后共 90 项通过，包含 6 项真实
NGINX/TLS。重载测试等待原 worker 退出，再核对新健康摘要和公网策略，避免一次
新响应后又命中旧 worker 的测试竞态；修正后重载专项另连续 3 次通过。

维护时先停止/禁用恢复 timer，再对容器直接执行 stop/recreate；Docker 没有提供给此
守护“检查状态并重启”的原子条件操作。发布锁和重启前二次核验缩小竞态，但不能把
其他管理员绕过锁的并发 Docker 操作原子串行化。SHA 清单用于发现未经发布的文件
漂移，不是对能同时改配置与清单的可信管理员的密码学授权。

这些不是实际冷启动或 apt 更新后的生产验收。本次无 sudo 密码/Docker 管理权限，
没有安装单元、重建生产容器或修改 Serve。上线需保留独立 SSH/云控制台，在维护窗口
执行 `sudo ./scripts/harden-deployment.sh [--tailscale]`，验证公网业务与另一台 Tailnet
设备的管理访问；之后再做真实冷启动、分别重启 Docker/tailscaled、网络中断恢复测试。
不要在仅有 Tailscale 的远程会话中直接做这些维护操作。

设计依据：[Docker restart policy](https://docs.docker.com/engine/containers/start-containers-automatically/)、
[Tailscale Serve](https://tailscale.com/docs/reference/tailscale-cli/serve)、
[systemd 网络可用性](https://systemd.io/NETWORK_ONLINE/)。
