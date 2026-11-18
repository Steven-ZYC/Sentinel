# Acunetix 验收标准

## 门槛

一次完整、未中止、使用真实生产域名和所有可达应用路径的扫描必须满足：

| 严重度 | 允许数量 |
| --- | ---: |
| Critical | 0 |
| High | 0 |
| Medium | <= 10 |
| Low | <= 10 |

`Informational` 单独记录，不计入上述门槛。不要通过删除目标、排除路径或把真实漏洞标
成误报来“满足”数字。

## 扫描前

1. 确认扫描授权、窗口和允许的请求速率；生产环境先使用较低并发。
2. 扫描 `https://app.example.com`，代理部署不要直接扫 Origin IP，除非明确要验证
   源站绕过风险。
3. 如应用有登录，使用权限最小的专用测试账号，并覆盖登录后路径。
4. 在所用 CDN（如有）/SafeLine 中仅放行 Acunetix 扫描器 IP；不要全局关闭 WAF。
5. 保存扫描配置、Acunetix 版本、开始时间、目标、登录序列和爬取路径数。
6. 先运行 `./scripts/verify.sh https://app.example.com`。

## 必查项

- TLS 1.0/1.1 必须握手失败；仅 TLS 1.2/1.3 成功。
- HTTP 自动 308 到 HTTPS，HTTPS 全部状态码均包含安全头。
- TRACE 不返回成功状态。
- 不可从公网直连 `sites.json` 中任何 SafeLine 业务 listener、应用端口或 SafeLine 管理端；9443 只允许明确的管理通道。
- 所有模式均不能绕过 Sentinel/WAF；代理模式还不能绕过可信 CDN/负载均衡。普通 DNS 直连到 Sentinel 属于正常链路。
- CSP 不包含无依据的 `unsafe-eval`，且浏览器控制台无真实功能所需资源被误拦截。
- Cookie 由应用设置 `Secure`、`HttpOnly` 和适当 `SameSite`；会话 cookie 不应缓存。
- 对 404、403、429、500、502、504 分别检查安全头，避免只加在 200 响应。

## 使用 Cloudflare 代理时的强制项

在 Cloudflare Dashboard 的 SSL/TLS -> Edge Certificates 将 Minimum TLS Version 设为 TLS 1.2，确认 TLS 1.3 已启用，HSTS max-age 至少 31536000，不能为 0。该设置作用于经 Cloudflare 代理的入口，不能由源站 NGINX 代替。修改后再次运行 `scripts/verify.sh`。普通 DNS 直连无需此步骤。

## 扫描后

导出 PDF 和 XML/JSON 报告，按 `日期-目标-扫描器版本` 保存到受控制品库（报告可能
含 URL、参数和凭据痕迹，不提交到公开 Git）。对每个发现记录：证据、可复现请求、
所属层（Sentinel/SafeLine/应用/Cloudflare）、修复提交或配置变更、复测结果。

如果不满足门槛，发布判定为失败。Critical/High 必须全部修复并重扫；Medium/Low 即
使数量达标也应逐条评估，门槛不是忽略漏洞的许可。只有完整重扫满足门槛，才能将验
收状态标为通过。
