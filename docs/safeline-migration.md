# SafeLine 迁移与回滚

本文只修改 SafeLine 的运行配置，不修改 SafeLine 镜像、二进制或源代码。当前私有
安装包未从 GitHub 获取，所有已观察版本和路径均记录在本文，确保另一台同版本机器
可以重复操作。

## 0. 变更窗口与前提

准备一个短维护窗口。端口切换期间可能有数十秒不可用。确保仍有 SSH 控制台，不要
只依赖待切换的网站进入机器。

记录版本和配置摘要（不要把 `.env` 的数据库密码提交到 Git）：

```bash
grep -E '^(SAFELINE_DIR|IMAGE_TAG|MGT_PORT|SUBNET_PREFIX)=' /data/safeline/.env
sudo docker ps --format '{{.Image}} {{.Names}} {{.Ports}}'
sudo cp -a /data/safeline/docker-compose.yaml /data/safeline/docker-compose.yaml.pre-sentinel
sudo cp -a /data/safeline/resources/nginx /data/safeline/backups/nginx-pre-sentinel
```

先记录实际 `IMAGE_TAG`；容器名通常为 `safeline-tengine`。不同版本必须重新核对
生成文件格式，不能盲目执行替换或照搬本文中的路径。

## 1. 先在 SafeLine 控制台改业务端口

登录 `https://<管理地址>:9443`，找到示例站点 `app.example.com`，把监听协议改为 HTTP，并将端口
从 `443` 改为 `10443`，保存并发布。

这一步通过 SafeLine 自己的控制面更新数据库，避免仅修改生成文件后下次发布又变回
443。确认生成配置：

```bash
grep -nE 'listen .*:(443|10443).*default_server' \
  /data/safeline/resources/nginx/sites-enabled/IF_*
sudo docker exec safeline-tengine nginx -t
curl -I -H 'Host: app.example.com' http://127.0.0.1:10443/
```

此时 10443 通常仍绑定 `0.0.0.0`。在 Sentinel 启动前必须把它限制到回环，避免攻击
者绕过最外层头策略直接访问 SafeLine。

## 2. 将 SafeLine 内部监听限制到回环

先检查脚本只识别到一个站点，再应用：

```bash
UPSTREAM_PORT=10443 ./scripts/safeline-listener.sh check
sudo UPSTREAM_PORT=10443 ./scripts/safeline-listener.sh apply
ss -ltn 'sport = :10443'
```

脚本执行顺序固定：创建带 UTC 时间戳的备份、仅把
`listen 0.0.0.0:10443 default_server` 改成 `listen 127.0.0.1:10443 default_server`、运行
`nginx -t`，最后 reload。它遇到零个或多个候选站点会中止，不会猜测。

SafeLine 后续在控制台重新发布该站点时可能重建 `IF_*` 文件。每次 SafeLine 更新或
站点变更后都要执行：

```bash
UPSTREAM_PORT=10443 ./scripts/safeline-listener.sh check
```

若输出恢复为 `0.0.0.0`，重新执行 `apply`。此外用主机 UFW 和云防火墙双重拒绝公网
10443；防火墙规则要按实际 SSH/Cloudflare/管理网段设计，本文不擅自修改现网规则。

## 3. 启动 Sentinel

```bash
cp .env.example .env
cp sites.example.json sites.json
editor .env
editor sites.json
./scripts/render-sites.py
./scripts/preflight.sh
sudo docker compose pull
sudo docker compose up -d
sudo docker compose ps
sudo docker compose logs --tail=100 proxy
```

`sites.json` 为每个业务域名声明独立的 `127.0.0.1:<SafeLine listener>` 上游、证书和
安全策略；多个业务域名仍共用 Sentinel 的公网 80/443。确认 `ss -ltn` 显示 Sentinel
占用 80/443，且每一个 SafeLine 业务 listener 均只占用回环地址（例如
`127.0.0.1:10443`）。Cloudflare SSL/TLS 模式应为 Full (strict)，DNS 记录应保持代理
状态；不要把 Cloudflare Origin CA 证书暴露给公网直连客户端。
在 Cloudflare Dashboard 的 SSL/TLS -> Edge Certificates 中将 Minimum TLS Version 设为 TLS 1.2，并确认 TLS 1.3 已启用。公网当前实测仍接受 TLS 1.0；仅修改 Sentinel 源站不能修复 Cloudflare 边缘协议。

## 4. 回滚

先停止 Sentinel，释放 80/443：

```bash
sudo docker compose down
```

在 SafeLine 控制台把站点端口从 10443 改回 443 并发布。若控制台无法使用，可用
`apply` 输出的备份路径回滚生成文件：

```bash
sudo SAFELINE_SITE_FILE=/data/safeline/resources/nginx/sites-enabled/IF_backend_1 \
  ./scripts/safeline-listener.sh restore \
  /data/safeline/backups/sentinel/<UTC时间>/IF_backend_1
```

最后验证：

```bash
sudo docker exec safeline-tengine nginx -t
curl -kI --resolve app.example.com:443:127.0.0.1 https://app.example.com/
ss -ltn 'sport = :443'
```

## 5. SafeLine 升级后的复现

1. 记录升级前后 `IMAGE_TAG` 和镜像摘要。
1. 在维护窗口执行；升级会重启 SafeLine 并造成短暂流量中断。
2. 记录升级前版本、编排文件和镜像摘要：`grep IMAGE_TAG /data/safeline/.env`、`sudo docker compose images --digests`。
3. 在 `/data/safeline` 执行官方在线升级：

```bash
cd /data/safeline
sudo bash -c "$(curl -fsSLk https://waf-ce.chaitin.cn/release/latest/manager.sh)"
```

4. SafeLine >= 9.2.3 会在 `.env` 新增 `MGT_PROXY`。Sentinel 当前不代理 9443 管理控制台，因此保持 `MGT_PROXY=0`；只有以后把管理控制台也置于代理后，才按实际可信代理层数调整。
5. 在 SafeLine 控制台确认业务站点仍为 `10443/HTTP`；重新发布后执行 `sudo UPSTREAM_PORT=10443 ./scripts/safeline-listener.sh apply`，恢复 `127.0.0.1` 绑定。
6. 执行 `./scripts/render-sites.py`、`./scripts/preflight.sh`、`sudo docker compose up -d` 和 `./scripts/verify.sh https://app.example.com`。每个其他业务域名也应独立验证。
7. 重新跑 Acunetix 完整扫描，不沿用升级前结论。
8. 可选清理旧镜像：`sudo docker image prune --filter="label=maintainer=SafeLine-CE"`；先确认没有回滚依赖，失败时手工核对后清理。

`latest/manager.sh` 会随时间变化，不是逐字节可复现输入。每次升级必须在变更记录中保存执行时间、升级前后 `IMAGE_TAG`、最终镜像摘要和扫描报告。
