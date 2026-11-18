"""Prepare the first site's configuration for the local install CLI."""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import re
import sys
import tempfile

from security_checks import renderer


def prompt(label: str, default: str = "") -> str:
    return input(f"{label}" + (f" [{default}]" if default else "") + " > ").strip() or default


def configure(project: Path) -> None:
    files = [".env", "sites.json"]
    existing = [os.path.lexists(project / name) for name in files]
    if all(existing):
        print("使用已有 .env 和 sites.json。")
        return
    if any(existing):
        raise ValueError("配置不完整，请补齐 .env 和 sites.json 后重试；已有文件保留。")

    module = renderer()
    env = module.parse_env(project / ".env.example")
    env["PUBLIC_LISTEN_ADDR"] = prompt("本机入口 IPv4")
    env["PUBLIC_LISTEN_IPV6"] = prompt("本机入口 IPv6（可留空）")
    module.public_addresses(env)
    print("Cloudflare 橙云选 cloudflare；企业 DNS 或灰云直连选 direct；企业 HTTP 代理选 trusted-proxy。")
    env["EDGE_MODE"] = prompt("入口模式（必填）")
    if env["EDGE_MODE"] == "trusted-proxy":
        env["TRUSTED_PROXY_CIDRS"] = prompt("可信代理 CIDR，多个用逗号分隔")
        env["REAL_IP_HEADER"] = prompt("代理传递的来源头", "X-Forwarded-For")
    module.edge_policy(env)
    domain = module.normalize_domain(prompt("业务域名"), "domain")
    env["TLS_MOUNT_ROOT"] = prompt("专用证书根目录", "/etc/sentinel/tls")
    base = Path(env["TLS_MOUNT_ROOT"]) / domain
    site = json.loads((project / "sites.example.json").read_text())["sites"][0]
    site["domain"] = domain
    for field, key, filename in (("certificate", "DEFAULT_TLS_CERT_PATH", "fullchain.pem"),
                                 ("private_key", "DEFAULT_TLS_KEY_PATH", "privkey.pem")):
        env[key] = site[field] = prompt(filename, str(base / filename))
    for key in ("TLS_MOUNT_ROOT", "DEFAULT_TLS_CERT_PATH", "DEFAULT_TLS_KEY_PATH"):
        if not re.fullmatch(r"/[A-Za-z0-9_./-]+", env[key]):
            raise ValueError("向导支持字母、数字、下划线、点、斜杠和连字符组成的绝对路径。")
    site["upstream"]["port"] = int(prompt("雷池 HTTP 回环端口", "10443"))
    site = {"version": 1, "sites": [site]}
    with tempfile.TemporaryDirectory(dir=project) as directory:
        stage = Path(directory)
        (stage / ".env").write_text("".join(f"{key}={value}\n" for key, value in env.items()))
        (stage / "sites.json").write_text(json.dumps(site, indent=2) + "\n")
        module.rendered_files(module.parse_public_address(env), module.parse_tls_mount_root(env),
                              module.parse_default_tls(env), module.load_sites(stage / "sites.json"), env)
        linked = []
        try:
            for name in files:
                (stage / name).chmod(0o600)
                os.link(stage / name, project / name)
                linked.append(project / name)
        except BaseException:
            for path in linked:
                path.unlink()
            raise
    print(f"已创建 {project}/.env 和 sites.json；可编辑清单增加站点。")


if __name__ == "__main__":
    project = Path(__file__).resolve().parents[1]
    try:
        lock = os.open(project, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX)
            configure(project)
        finally:
            os.close(lock)
    except (OSError, ValueError, EOFError) as error:
        sys.exit(f"配置失败：{error}")
