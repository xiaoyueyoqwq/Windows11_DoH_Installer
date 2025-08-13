# -*- coding: utf-8 -*-
"""
Windows 11 原生 DoH 安装/卸载器（完整修复版）
改动要点：
1) 首位解析：优先使用国内可用 DoH（https://223.5.5.5/dns-query 等）
2) 修复 DoH 响应解析 idna 解码报错（解析时统一使用 ASCII）
3) 回退解析：Resolve-DnsName 走 JSON，仅提取 A/AAAA 的 IPAddress，避免 CNAME 被当作 IP
4) 全部错误/早退路径均等待按键，不再“闪退”
"""

from __future__ import annotations
import ctypes
import os
import re
import ssl
import socket
import subprocess
import sys
import time
import json
import base64
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

# ================== 版本号 ==================
SCRIPT_VERSION = "DoH Installer v1.1.1"

# ================== 路径与常量 ==================
APP_DIR = Path(os.environ.get("LOCALAPPDATA", ".")) / "DoH_Installer"
APP_DIR.mkdir(parents=True, exist_ok=True)
LOG_PATH = APP_DIR / ("install_%s.log" % datetime.now().strftime("%Y%m%d_%H%M%S"))
BK_DIR = Path(os.environ.get("ProgramData", "C:\\ProgramData")) / "DoH_Installer"
BK_DIR.mkdir(parents=True, exist_ok=True)
BK_FILE = BK_DIR / "backup.json"

# 首位使用国内 DoH（仅用于“解析 DoH 目标主机名”的预解析，不影响最终写入）
PREFERRED_DOH_RESOLVERS = [
    "https://223.5.5.5/dns-query",       # AliDNS (IP端)
    "https://dns.alidns.com/dns-query",  # AliDNS (域名端)
    "https://doh.pub/dns-query",         # 腾讯
    "https://1.12.12.12/dns-query",      # 腾讯 (IP端)
    "https://1.1.1.1/dns-query",         # Cloudflare
    "https://dns.google/dns-query",      # Google
]

# 回退 DNS（非 DoH），用于 Resolve-DnsName
FALLBACK_DNS_SERVERS = ["223.5.5.5", "223.6.6.6", "1.1.1.1", "8.8.8.8"]

# ================== 基础工具 ==================
def log(msg: str):
    line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

def pause(msg: str = "按任意键退出…"):
    try:
        import msvcrt
        print(msg)
        msvcrt.getch()
    except Exception:
        input(msg)

def pause_and_exit(code: int = 0, msg: str | None = None):
    if msg:
        print(msg)
    pause()
    sys.exit(code)

def die(msg: str, code: int = 1):
    log(f"[FATAL] {msg}")
    pause_and_exit(code=code, msg=msg)

def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def run(cmd: list[str] | str, check: bool=False, capture: bool=False) -> subprocess.CompletedProcess:
    if isinstance(cmd, str):
        shell=True
        cmd_to_show = cmd
    else:
        shell=False
        cmd_to_show = " ".join(cmd)
    log(f"[RUN] {cmd_to_show}")
    return subprocess.run(
        cmd, shell=shell, check=check,
        capture_output=capture, text=True,
        encoding="utf-8", errors="ignore"
    )

def prompt_yes_no(question: str, default_yes=True) -> bool:
    prompt = " [Y/n] " if default_yes else " [y/N] "
    while True:
        try:
            ans = input(question + prompt).strip().lower()
        except EOFError:
            return default_yes
        if not ans:
            return default_yes
        if ans in ("y", "yes", "是", "好", "确定"):
            return True
        if ans in ("n", "no", "否", "不"):
            return False
        print("请输入 y 或 n。")

# ================== DoH 解析实现 ==================
def _dns_build_query(qname: str, qtype: int) -> bytes:
    """
    构造最小 DNS 查询（application/dns-message）
    Header: ID(2) | Flags(2=0x0100 RD) | QD(2=1) | AN/NS/AR(2)=0
    Question: QNAME | QTYPE | QCLASS(IN=1)
    """
    import random
    def encode_qname(name: str) -> bytes:
        parts = name.strip(".").split(".") if name else []
        b = bytearray()
        for p in parts:
            pb = p.encode("idna")  # 编码使用 IDNA（punycode）
            if len(pb) > 63:
                raise ValueError("标签长度超过 63")
            b.append(len(pb))
            b.extend(pb)
        b.append(0)
        return bytes(b)
    ID = random.randint(0, 0xFFFF)
    header = ID.to_bytes(2, "big") + b"\x01\x00" + b"\x00\x01\x00\x00\x00\x00\x00\x00"
    q = encode_qname(qname) + qtype.to_bytes(2, "big") + b"\x00\x01"
    return header + q

def _dns_parse_name(buf: bytes, off: int) -> tuple[str, int]:
    """
    解析压缩域名。注意：解析阶段统一用 ASCII 解码（响应里的 punycode 标签是 ASCII）。
    """
    labels = []
    jumped = False
    start = off
    while True:
        if off >= len(buf):
            return "", off
        l = buf[off]
        if l == 0:
            off += 1
            break
        if (l & 0xC0) == 0xC0:  # pointer
            if off + 1 >= len(buf):
                return "", off + 1
            ptr = ((l & 0x3F) << 8) | buf[off+1]
            if not jumped:
                start = off + 2
            off = ptr
            jumped = True
            continue
        off += 1
        label = buf[off:off+l]
        # 关键修复：不要使用 idna 的 ignore；这里用 ASCII 严格模式
        labels.append(label.decode("ascii", "strict"))
        off += l
    name = ".".join(labels)
    return name, (off if not jumped else start)

def _dns_parse_answers(resp: bytes, want_types=(1, 28)) -> list[str]:
    if len(resp) < 12:
        return []
    qd = int.from_bytes(resp[4:6], "big")
    an = int.from_bytes(resp[6:8], "big")
    off = 12
    # 跳过 Questions
    for _ in range(qd):
        _, off = _dns_parse_name(resp, off)
        off += 4  # QTYPE+QCLASS
    # 读取 Answers
    out = []
    for _ in range(an):
        _, off = _dns_parse_name(resp, off)
        if off + 10 > len(resp):
            break
        rtype = int.from_bytes(resp[off:off+2], "big"); off += 2
        rclass = int.from_bytes(resp[off:off+2], "big"); off += 2
        off += 4  # TTL
        rdlen = int.from_bytes(resp[off:off+2], "big"); off += 2
        rdata = resp[off:off+rdlen]; off += rdlen
        if rclass != 1:
            continue
        if rtype == 1 and rdlen == 4 and 1 in want_types:  # A
            out.append(".".join(str(b) for b in rdata))
        elif rtype == 28 and rdlen == 16 and 28 in want_types:  # AAAA
            out.append(":".join(f"{rdata[i]<<8 | rdata[i+1]:x}" for i in range(0, 16, 2)))
    return out

def doh_query(host: str, resolver_url: str, qtype: int, timeout: float=5.0) -> list[str]:
    """
    通过 DoH GET：resolver_url?dns=<base64url(dns-message)>
    """
    msg = _dns_build_query(host, qtype)
    dns_param = base64.urlsafe_b64encode(msg).rstrip(b"=").decode("ascii")
    sep = "&" if "?" in resolver_url else "?"
    url = f"{resolver_url}{sep}dns={dns_param}"
    req = Request(url, headers={
        "Accept": "application/dns-message",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "User-Agent": "DoH-Installer/1.1"
    })
    ctx = ssl.create_default_context()
    with urlopen(req, timeout=timeout, context=ctx) as resp:
        if resp.status != 200:
            return []
        data = resp.read()
        return _dns_parse_answers(data, want_types=(qtype,))

def resolve_hostname_prefer_doh(host: str, prefer_ipv4: bool=True) -> list[str]:
    """
    优先通过国内可用 DoH 解析；失败则回退 Resolve-DnsName（严格提取 A/AAAA 的 IPAddress）
    """
    ips_v4, ips_v6 = [], []
    # 先试 DoH
    for u in PREFERRED_DOH_RESOLVERS:
        try:
            v4 = doh_query(host, u, qtype=1)
            v6 = doh_query(host, u, qtype=28)
            ips_v4.extend(v4 or [])
            ips_v6.extend(v6 or [])
            if ips_v4 or ips_v6:
                break
        except Exception as e:
            log(f"[DoH] 解析 {host} via {u} 失败: {e}")
    # 回退：Resolve-DnsName → JSON，仅提取 IPAddress
    if not ips_v4 and not ips_v6:
        for s in FALLBACK_DNS_SERVERS:
            try:
                ps = (
                    "Resolve-DnsName {host} -Server {srv} -Type A,AAAA -DnsOnly -NoHostsFile | "
                    "Select-Object -Property QueryType,IPAddress | ConvertTo-Json -Depth 3"
                ).format(host=host, srv=s)
                cp = run(["powershell", "-NoProfile", "-Command", ps], capture=True)
                out = (cp.stdout or "").strip()
                if not out:
                    continue
                data = json.loads(out)
                rows = data if isinstance(data, list) else [data]
                for row in rows:
                    qtype = str(row.get("QueryType", "")).upper()
                    ip = row.get("IPAddress")
                    if not ip:
                        continue
                    if ":" in ip:
                        if qtype == "AAAA":
                            ips_v6.append(ip)
                    else:
                        if qtype == "A":
                            ips_v4.append(ip)
                if ips_v4 or ips_v6:
                    break
            except Exception as e:
                log(f"[FallbackDNS] 解析 {host} via {s} 失败: {e}")
    # 去重排序：IPv4 优先
    v4 = sorted(set(ips_v4))
    v6 = sorted(set(ips_v6))
    if prefer_ipv4:
        return v4 + v6
    return v6 + v4

# ================== 预检与系统配置 ==================
def https_preflight(ip: str, sni: str, port: int=443, path: str="/", timeout: float=5.0) -> tuple[bool, str, str]:
    """
    对目标 IP 发起 TLS（SNI=sni），并尝试轻量 HEAD 请求；返回 (ok, CN, notAfter)
    """
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert.get('subject', ()))
                cn = subject.get('commonName', '')
                not_after = cert.get('notAfter', '')
                # HEAD 试探（不强制）
                try:
                    req = f"HEAD {path or '/'} HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\nAccept: */*\r\n\r\n"
                    ssock.sendall(req.encode("ascii", "ignore"))
                    ssock.recv(1)
                except Exception:
                    pass
                return True, cn, not_after
    except Exception as e:
        log(f"[TLS] {ip}:{port} 预握手失败: {e}")
        return False, "", ""

def ensure_warp() -> bool:
    log("尝试静默安装并连接 Cloudflare WARP…")
    run(["winget", "install", "--id=Cloudflare.Warp", "-e", "--silent",
         "--accept-package-agreements", "--accept-source-agreements"])
    cli = Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "Cloudflare" / "Cloudflare WARP" / "warp-cli.exe"
    if not cli.exists():
        cli = Path(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")) / "Cloudflare" / "Cloudflare WARP" / "warp-cli.exe"
    if not cli.exists():
        log("未找到 warp-cli.exe，WARP 安装可能失败。")
        return False
    run([str(cli), "--accept-tos", "register"])
    run([str(cli), "set-mode", "warp"])
    run([str(cli), "connect"])
    deadline = time.time() + 120
    while time.time() < deadline:
        cp = run([str(cli), "status"], capture=True)
        if "Connected" in (cp.stdout or ""):
            log("WARP 已连接。")
            return True
        time.sleep(2)
    log("WARP 在超时时间内未连接成功。")
    return False

def backup_dns():
    data = {"ifaces": []}
    cp = run(["powershell", "-NoProfile", "-Command", "Get-DnsClientServerAddress | ConvertTo-Json -Depth 4"], capture=True)
    if cp.stdout:
        try:
            arr = json.loads(cp.stdout)
            if isinstance(arr, dict):
                arr = [arr]
            for it in arr or []:
                data["ifaces"].append({
                    "InterfaceIndex": it.get("InterfaceIndex"),
                    "InterfaceAlias": it.get("InterfaceAlias"),
                    "AddressFamily": it.get("AddressFamily"),
                    "ServerAddresses": it.get("ServerAddresses"),
                })
        except Exception as e:
            log(f"备份解析失败: {e}")
    try:
        with open(BK_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        log(f"已备份 DNS 到 {BK_FILE}")
    except Exception as e:
        log(f"写入备份失败: {e}")

def restore_dns_from_backup():
    if not BK_FILE.exists():
        log("未找到备份文件，将改为重置为 DHCP。")
        reset_dns_to_dhcp()
        return
    try:
        data = json.loads(BK_FILE.read_text("utf-8"))
    except Exception as e:
        log(f"备份文件损坏：{e}；将改为重置为 DHCP。")
        reset_dns_to_dhcp()
        return
    for it in data.get("ifaces", []):
        idx = it.get("InterfaceIndex")
        servers = it.get("ServerAddresses") or []
        if not idx:
            continue
        if not servers:
            run(["powershell", "-NoProfile", "-Command", f"Set-DnsClientServerAddress -InterfaceIndex {idx} -ResetServerAddresses"])
        else:
            addrs = " ".join(servers)
            run(["powershell", "-NoProfile", "-Command", f"Set-DnsClientServerAddress -InterfaceIndex {idx} -ServerAddresses {addrs}"])
    log("已根据备份恢复各接口 DNS。")

def reset_dns_to_dhcp():
    run(["powershell", "-NoProfile", "-Command",
         r"Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.HardwareInterface -eq $true } | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.IfIndex -ResetServerAddresses }"])

def configure_doh_dot_ddr(enable_doh: bool):
    if enable_doh:
        run(["netsh", "dnsclient", "set", "global", "doh=yes", "dot=no", "ddr=no"])
        run(["powershell", "-NoProfile", "-Command",
             r"Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.HardwareInterface -eq $true} | ForEach-Object { netsh dnsclient set interface name=""$($_.Name)"" ddr=no ddrfallback=no }"])
    else:
        run(["netsh", "dnsclient", "set", "global", "doh=auto", "dot=no", "ddr=yes"])
        run(["powershell", "-NoProfile", "-Command",
             r"Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.HardwareInterface -eq $true} | ForEach-Object { netsh dnsclient set interface name=""$($_.Name)"" ddr=yes ddrfallback=yes }"])

def delete_mapping(server_ip: str):
    run(["netsh", "dnsclient", "delete", "encryption", f"server={server_ip}", "protocol=doh"])
    run(["netsh", "dnsclient", "delete", "encryption", f"server={server_ip}", "protocol=dot"])

def add_mapping_doh(server_ip: str, dohtemplate: str, udpfallback_no=True):
    args = ["netsh", "dnsclient", "add", "encryption", f"server={server_ip}",
            f"dohtemplate={dohtemplate}", "autoupgrade=yes", f"udpfallback={'no' if udpfallback_no else 'yes'}"]
    run(args)

def set_all_nics_dns(server_ip: str):
    run(["powershell", "-NoProfile", "-Command",
         r"$ifaces=Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.HardwareInterface -eq $true }; "
         r"foreach($i in $ifaces){ Set-DnsClientServerAddress -InterfaceIndex $i.IfIndex -ServerAddresses " + server_ip + r" }"])

def flush_dns():
    run(["ipconfig", "/flushdns"])

def show_status(server_ip: str):
    run(["netsh", "dnsclient", "show", "global"])
    run(["netsh", "dnsclient", "show", "encryption", f"server={server_ip}"])
    run(["netsh", "dnsclient", "show", "state"])

def parse_doh_url(url: str) -> tuple[str, int, str]:
    u = urlparse(url.strip())
    if u.scheme.lower() != "https" or not u.hostname:
        raise ValueError("无效的 DoH 模板 URL（需以 https:// 开头，并包含主机名或 IP）。")
    host = u.hostname
    port = u.port or 443
    path = u.path or "/"
    if u.query:
        path = f"{path}?{u.query}"
    if u.fragment:
        path = f"{path}#{u.fragment}"
    return host, port, path

# ================== 主流程 ==================
def do_install():
    if not is_admin():
        die("请以【管理员身份】运行本程序。")

    print("=== Windows 11 原生 DoH 安装器 ===\n")
    print("说明：本工具将为你配置系统级 DNS-over-HTTPS。")
    print("提示：已将国内可用 DoH（如 https://223.5.5.5/dns-query）作为首位解析上游。")

    try:
        tpl = input("请输入 DoH 模板 URL（例如https://dns.alidns.com/dns-query）: ").strip()
    except EOFError:
        die("未能读取输入。")
    if not tpl:
        die("未输入模板 URL，已退出。")

    try:
        host, port, path = parse_doh_url(tpl)
    except Exception as e:
        die(f"模板 URL 解析失败：{e}")

    try_warp = prompt_yes_no("如遇 443 被封/域名被干扰，是否自动安装并连接 Cloudflare WARP 后再次尝试？", True)
    strict_only = prompt_yes_no("是否【只允许严格模式】（证书/主机名不匹配就终止）？", True)

    log("开始备份当前 DNS 设置…")
    backup_dns()

    log(f"优先通过国内 DoH 解析 {host} …")
    ips = resolve_hostname_prefer_doh(host, prefer_ipv4=True)
    if not ips and try_warp:
        print("DoH 解析失败，尝试通过 WARP 再次解析…")
        if ensure_warp():
            ips = resolve_hostname_prefer_doh(host, prefer_ipv4=True)
    if not ips:
        die("无法解析主机名（DoH 优先 + 回退 均失败）。")

    print("候选 IP：", ", ".join(ips))

    # 严格预握手（443/或模板端口）
    chosen_ip = None
    for ip in ips:
        ok, cn, exp = https_preflight(ip, host, port=port, path=path)
        if ok:
            print(f"[严格握手成功] {ip}: CN={cn}, 到期={exp}")
            chosen_ip = ip
            break
        else:
            print(f"[严格握手失败] {ip}:{port}")

    used_warp = False
    if not chosen_ip and try_warp:
        print("准备安装并连接 WARP 以尝试穿透 443…")
        if ensure_warp():
            used_warp = True
            for ip in ips:
                ok, cn, exp = https_preflight(ip, host, port=port, path=path)
                if ok:
                    print(f"[严格握手成功] {ip}: CN={cn}, 到期={exp}")
                    chosen_ip = ip
                    break
                else:
                    print(f"[严格握手失败] {ip}:{port}")
        else:
            log("WARP 未能连接，将继续后续流程。")

    if not chosen_ip:
        if strict_only:
            die("所有 IP 的严格握手均失败，且你选择了仅严格模式。")
        print("将跳过预检直接写入 DoH 映射并尝试（系统仍会强制主机名/证书校验）。")
        for ip in ips:
            try:
                with socket.create_connection((ip, port), timeout=3.0):
                    chosen_ip = ip
                    break
            except Exception:
                pass
        if not chosen_ip:
            die("未发现可连通 443/TCP 的 IP。请检查网络或手动开启 WARP/VPN 后重试。")

    print(f"选定服务器 IP：{chosen_ip}")
    print("开始写入系统配置（将覆盖旧有同 IP 的 DoH/DoT 映射）…")

    # 开 DoH / 关 DoT；接口也关闭 DDR
    configure_doh_dot_ddr(enable_doh=True)
    # 删除旧映射
    delete_mapping(chosen_ip)
    # 写入新映射（DoH 模板）
    add_mapping_doh(chosen_ip, tpl, udpfallback_no=True)
    # 设置网卡 DNS
    set_all_nics_dns(chosen_ip)
    # 刷新 & 显示
    flush_dns()
    show_status(chosen_ip)

    # 功能测试
    print("做一次解析测试：example.com …")
    run(["powershell", "-NoProfile", "-Command",
         f"Resolve-DnsName example.com -Server {chosen_ip} -Type A -NoHostsFile -DnsOnly"])

    print("\n完成。日志路径：", LOG_PATH)
    if used_warp:
        print("提示：你已启用 WARP，如不再需要可在卸载流程选择卸载它。")
    pause("操作完成。按任意键退出…")

def do_uninstall():
    if not is_admin():
        die("请以【管理员身份】运行本程序。")

    print("=== 卸载/恢复 ===")
    try:
        configure_doh_dot_ddr(enable_doh=False)
        if BK_FILE.exists() and prompt_yes_no("检测到之前的 DNS 备份，是否按备份恢复？", True):
            restore_dns_from_backup()
        else:
            reset_dns_to_dhcp()
            print("已将所有活动物理网卡 DNS 恢复为 DHCP。")
        ip_guess = input("如需清理加密映射，请输入要删除映射的服务器 IP（回车跳过）: ").strip()
        if ip_guess:
            delete_mapping(ip_guess)
            print(f"已请求删除 {ip_guess} 的 DoH/DoT 映射。")
        if prompt_yes_no("是否卸载 Cloudflare WARP（若之前安装过）？", False):
            run(["winget", "uninstall", "--id=Cloudflare.Warp", "-e"])
        flush_dns()
        print("已完成卸载/恢复。")
        pause("按任意键退出…")
    except Exception as e:
        die(f"卸载过程中出现异常：{e}")

def main():
    if not is_admin():
        die("** 请右键以【管理员身份】运行本程序，否则无法生效。**")
    print("===============================================")
    print("   Windows 11 原生 DoH 安装/卸载器")
    print("   " + SCRIPT_VERSION)
    print("   日志目录：%LOCALAPPDATA%\\DoH_Installer")
    print("===============================================\n")
    print("1) 安装/更新")
    print("2) 卸载并恢复系统原有上网配置")
    print("3) 退出")
    try:
        choice = input("请选择 [1/2/3]: ").strip()
    except EOFError:
        die("未能读取输入。")
    if choice == "1":
        try:
            do_install()
        except Exception as e:
            die(f"安装过程中发生错误：{e}")
    elif choice == "2":
        do_uninstall()
    else:
        pause("按任意键退出…")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        die(f"发生未处理的错误：{e}")
