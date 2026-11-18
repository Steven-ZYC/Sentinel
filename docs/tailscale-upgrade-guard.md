# Tailscale 升级保护

Sentinel 只绑定明确入口 IPv4/可选 IPv6 的 `80/443`，Tailscale Serve 只绑定 Tailscale IPv4/IPv6 的
`443`。两者可共用端口号，但不得使用通配符绑定或把 SafeLine 管理端公开到 `9443`。

`tailscale serve --bg` 会在重启或 `tailscaled` 重启后恢复原有配置；本项目额外提供的
guard 用于重申期望的管理路由，并发现其他组件或升级后的配置漂移。
公网和 Tailnet 恢复互不依赖，完整机制与权限边界见[运行恢复](runtime-recovery.md)。

## 前置条件

先确认 Tailscale Serve 指向 `https+insecure://localhost:9443`，并从另一台 Tailnet
设备确认管理页可用。随后收口 SafeLine 管理端：

```bash
cd /path/to/Sentinel
sudo ./scripts/bind-safeline-management-tailscale.sh
```

该步骤会在三分钟后自动回滚；只有从另一台 Tailnet 设备完成验证后才输入 `CONFIRM`。
不要在 `9443` 仍监听 `0.0.0.0` 或 `[::]` 时安装 guard。

## 安装

```bash
cd /path/to/Sentinel
sudo ./scripts/install-tailscale-sentinel-guard.sh
```

安装程序会：

- 先验证 Serve、SafeLine 管理边界、全部实际 Tailnet listener 的地址/PID 和管理 HTTPS；
- 安装 root-owned 的代码快照，不让定时任务执行可写 checkout 的 Python；
- 将当前 `tailscale serve status --json` 状态快照备份到 `/etc/sentinel/tailscale/`；
- 在每次 `tailscaled` 启动后有限等待批准的管理路由：
  `HTTPS :443 -> https+insecure://localhost:9443`；只在空配置/批准路由缺失当前主机名时恢复；
- 每次检查结束约 60–70 秒后重新验证/安全恢复，单次重试窗口 60 秒、systemd 总时限 120 秒；
- 不要求 Docker/公网入口健康，不等待可能无限的 tailscale-online.target；失败记录 journal。

安装路径通过 root 所有的 `/etc/sentinel/guard.env` 传入，无固定用户名/仓库位置。检查递归拒绝非空 `AllowFunnel`、Foreground、额外 TCP listener 与 Web 路由；所有业务 socket 必须回环，管理 socket 只能是回环或已批准 Serve 对应的本机 Tailnet 地址，不只排除通配符。已有的 Tailnet `9443 -> 127.0.0.1:9443` 可以保留，其他 forward 被拒绝。该功能完全可选，普通 DNS/SSH 管理服务器无需安装。

守护程序不会自动把 SafeLine 管理端改回回环，避免错误自动化导致管理锁定。若检查发现
`9443` 漂移到公网绑定，请重新执行 `bind-safeline-management-tailscale.sh` 并从另一台
Tailnet 设备验证。

## 验证与排错

```bash
tailscale serve status
sudo systemctl status sentinel-tailscale-serve.service
sudo systemctl list-timers sentinel-tailscale-guard.timer
sudo systemctl start sentinel-tailscale-guard.service
sudo journalctl -u sentinel-tailscale-guard.service -n 50 --no-pager
```

故意停用 Serve 前先禁用 guard，否则空的批准配置会被重建。不要使用 `tailscale serve reset`，它会清空所有 Serve 配置。备份是审计状态快照，
不是 `set-config` 的输入；要重申本机的管理路由，请运行
`sudo systemctl restart sentinel-tailscale-serve.service`。

## 卸载

停止／禁用 guard 不会改变当前 Serve 路由：

```bash
sudo systemctl disable --now sentinel-tailscale-guard.timer
sudo systemctl disable --now sentinel-tailscale-serve.service
sudo rm -f /etc/systemd/system/sentinel-tailscale-serve.service \
  /etc/systemd/system/sentinel-tailscale-guard.service \
  /etc/systemd/system/sentinel-tailscale-guard.timer
sudo rm -f /usr/local/libexec/sentinel/tailscale-sentinel-guard
sudo systemctl daemon-reload
```
