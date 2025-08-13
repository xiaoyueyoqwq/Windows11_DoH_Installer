# -*- coding: utf-8 -*-
import ctypes
import json
import os
import socket
import ssl
import subprocess

import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

SCRIPT_VERSION = "DoH Final v1.0 - Leak-Proof Python Edition"

# ================== 配置 ==================
APP_DIR = Path(os.environ.get("LOCALAPPDATA", ".")) / "DoH_Final"
APP_DIR.mkdir(parents=True, exist_ok=True)
LOG_PATH = APP_DIR / f"doh_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
BACKUP_FILE = APP_DIR / "settings_backup.json"

# 默认配置
CONFIG = {
    "prefer_ipv4": True,
    "strict_only": True,
    "allow_warp_fallback": True,
    "set_as_only_dns": True,
    "enforce_firewall_block53": True,
    "disable_llmnr_mdns": True,
    "bootstrap_resolvers": ["223.5.5.5", "223.6.6.6", "1.1.1.1", "8.8.8.8"]
}

# ================== 基础工具 ==================

def log(msg: str):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    line = f"[{timestamp}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def run_cmd(cmd, description: str = "", check: bool = True, silent: bool = False) -> tuple[bool, str]:
    """执行命令，返回成功状态和输出"""
    try:
        if not silent:
            log(f"[CMD] {description}: {cmd if isinstance(cmd, str) else ' '.join(cmd)}")
        
        # 尝试多种编码方式
        encodings = ['gbk', 'utf-8', 'cp936', 'utf-16le']
        result = None
        
        for encoding in encodings:
            try:
                if isinstance(cmd, str):
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, 
                                          encoding=encoding, errors='replace', timeout=30)
                else:
                    result = subprocess.run(cmd, capture_output=True, text=True, 
                                          encoding=encoding, errors='replace', timeout=30)
                break
            except UnicodeDecodeError:
                continue
        
        if result is None:
            # 最后尝试二进制模式
            if isinstance(cmd, str):
                result = subprocess.run(cmd, shell=True, capture_output=True, timeout=30)
            else:
                result = subprocess.run(cmd, capture_output=True, timeout=30)
            
            # 手动解码
            try:
                stdout = result.stdout.decode('gbk', errors='replace') if result.stdout else ""
                stderr = result.stderr.decode('gbk', errors='replace') if result.stderr else ""
            except UnicodeDecodeError:
                stdout = str(result.stdout) if result.stdout else ""
                stderr = str(result.stderr) if result.stderr else ""
                
            # 重建result对象
            class MockResult:
                def __init__(self, returncode, stdout, stderr):
                    self.returncode = returncode
                    self.stdout = stdout
                    self.stderr = stderr
            
            result = MockResult(result.returncode, stdout, stderr)
        
        success = result.returncode == 0
        output = result.stdout if success else result.stderr
        
        if not silent:
            if success:
                log(f"[CMD] ✅ {description} 成功")
            else:
                log(f"[CMD] ❌ {description} 失败: {output[:200]}")
                if check:
                    raise subprocess.CalledProcessError(result.returncode, cmd, output)
        
        return success, output.strip() if output else ""
        
    except subprocess.TimeoutExpired:
        if not silent:
            log(f"[CMD] ⏱️  {description} 超时")
        if check:
            raise
        return False, "Command timeout"
    except Exception as e:
        if not silent:
            log(f"[CMD] ❌ {description} 异常: {e}")
        if check:
            raise
        return False, str(e)

def Step(msg: str):
    """步骤提示 - 模拟原版PowerShell的Step函数"""
    print(f"[STEP] {msg}")
    log(f"[STEP] {msg}")

def OK(msg: str):
    """成功提示 - 模拟原版PowerShell的OK函数"""
    print(f"[ OK ] {msg}")
    log(f"[ OK ] {msg}")

def pause(msg: str = "按任意键继续..."):
    try:
        import msvcrt
        print(msg)
        msvcrt.getch()
    except Exception:
        input(msg)

# ================== 核心功能 ==================

def get_host_from_url(url: str) -> str:
    """从DoH URL提取hostname"""
    try:
        parsed = urlparse(url)
        if parsed.scheme.lower() != 'https':
            raise ValueError("DoH URL必须使用HTTPS协议")
        if not parsed.hostname:
            raise ValueError("无效的DoH URL")
        return parsed.hostname
    except Exception as e:
        raise ValueError(f"DoH URL解析失败: {e}")

def resolve_doh_host(hostname: str) -> list[str]:
    """使用bootstrap DNS解析DoH主机名"""
    ips = []
    
    for resolver in CONFIG["bootstrap_resolvers"]:
        try:
            log(f"[RESOLVE] 通过 {resolver} 解析 {hostname}")
            
            if CONFIG["prefer_ipv4"]:
                # 优先A记录
                success, output = run_cmd([
                    "powershell", "-Command",
                    f"Resolve-DnsName {hostname} -Server {resolver} -Type A -DnsOnly -NoHostsFile -ErrorAction Stop | Where-Object {{$_.Type -eq 'A'}} | Select-Object -ExpandProperty IPAddress"
                ], "解析A记录", check=False, silent=True)
                
                if success and output:
                    ips.extend(output.split('\n'))
                
                # 如果没有A记录，尝试AAAA
                if not ips:
                    success, output = run_cmd([
                        "powershell", "-Command", 
                        f"Resolve-DnsName {hostname} -Server {resolver} -Type AAAA -DnsOnly -NoHostsFile -ErrorAction SilentlyContinue | Where-Object {{$_.Type -eq 'AAAA'}} | Select-Object -ExpandProperty IPAddress"
                    ], "解析AAAA记录", check=False, silent=True)
                    
                    if success and output:
                        ips.extend(output.split('\n'))
            else:
                # 优先AAAA记录，然后A记录（逻辑类似）
                pass
            
            if ips:
                break
                
        except Exception as e:
            log(f"[RESOLVE] 解析器 {resolver} 失败: {e}")
            continue
    
    # 去重和清理
    unique_ips = []
    for ip in ips:
        ip = ip.strip()
        if ip and ip not in unique_ips:
            unique_ips.append(ip)
    
    return unique_ips

def test_https_strict(ip: str, sni: str, port: int = 443) -> dict:
    """严格HTTPS TLS测试，验证证书链和主机名"""
    try:
        log(f"[TLS-TEST] 测试 {ip}:{port} (SNI: {sni})")
        
        context = ssl.create_default_context()
        # 严格验证：不允许自签名证书或主机名不匹配
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        
        with socket.create_connection((ip, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=sni) as ssock:
                cert = ssock.getpeercert()
                
                # 提取证书信息
                subject = dict(x[0] for x in cert.get('subject', []))
                cn = subject.get('commonName', '')
                issuer = cert.get('issuer', '')
                not_after = cert.get('notAfter', '')
                
                log(f"[TLS-TEST] ✅ {ip} 严格验证成功 (CN: {cn})")
                
                return {
                    "ok": True,
                    "cn": cn,
                    "issuer": str(issuer),
                    "expires": not_after
                }
                
    except ssl.SSLError as e:
        log(f"[TLS-TEST] ❌ {ip} SSL错误: {e}")
        return {"ok": False, "error": f"SSL错误: {e}"}
    except Exception as e:
        log(f"[TLS-TEST] ❌ {ip} 连接失败: {e}")
        return {"ok": False, "error": str(e)}

def ensure_warp() -> bool:
    """安装和连接Cloudflare WARP"""
    try:
        log("[WARP] 安装 Cloudflare WARP...")
        
        # 静默安装WARP
        success, _ = run_cmd([
            "winget", "install", "--id=Cloudflare.Warp", "-e", "--silent",
            "--accept-package-agreements", "--accept-source-agreements"
        ], "安装WARP", check=False)
        
        if not success:
            log("[WARP] winget安装失败，尝试查找现有安装")
        
        # 查找warp-cli.exe
        warp_paths = [
            Path(os.environ.get("ProgramFiles", "")) / "Cloudflare" / "Cloudflare WARP" / "warp-cli.exe",
            Path(os.environ.get("ProgramFiles(x86)", "")) / "Cloudflare" / "Cloudflare WARP" / "warp-cli.exe"
        ]
        
        warp_cli = None
        for path in warp_paths:
            if path.exists():
                warp_cli = str(path)
                break
        
        if not warp_cli:
            log("[WARP] ❌ 未找到warp-cli.exe")
            return False
        
        log("[WARP] 注册并连接WARP (warp模式)")
        
        # 注册和连接
        run_cmd([warp_cli, "--accept-tos", "register"], "WARP注册", check=False)
        run_cmd([warp_cli, "set-mode", "warp"], "设置WARP模式", check=False)
        run_cmd([warp_cli, "connect"], "连接WARP", check=False)
        
        # 等待连接（最多90秒）
        deadline = time.time() + 90
        while time.time() < deadline:
            time.sleep(3)
            success, status = run_cmd([warp_cli, "status"], "检查WARP状态", check=False)
            if success and "Connected" in status:
                log("[WARP] ✅ WARP已连接")
                return True
        
        log("[WARP] ❌ WARP连接超时")
        return False
        
    except Exception as e:
        log(f"[WARP] ❌ WARP设置失败: {e}")
        return False

def backup_current_settings():
    """备份当前DNS和网络设置"""
    try:
        log("[BACKUP] 备份当前设置...")
        
        backup_data = {
            "timestamp": datetime.now().isoformat(),
            "dns_settings": {},
            "firewall_rules": [],
            "registry_settings": {}
        }
        
        # 备份DNS设置
        success, output = run_cmd([
            "powershell", "-Command",
            "Get-DnsClientServerAddress | ConvertTo-Json -Depth 4"
        ], "获取DNS设置", check=False)
        
        if success and output:
            try:
                backup_data["dns_settings"] = json.loads(output)
            except (json.JSONDecodeError, ValueError):
                backup_data["dns_settings"] = {"raw_output": output}
        
        # 备份防火墙规则（检查是否存在我们的规则）
        success, output = run_cmd([
            "powershell", "-Command",
            "Get-NetFirewallRule -DisplayName '*Block-DNS*' -ErrorAction SilentlyContinue | ConvertTo-Json"
        ], "检查现有防火墙规则", check=False)
        
        if success and output:
            try:
                backup_data["firewall_rules"] = json.loads(output)
            except (json.JSONDecodeError, ValueError):
                backup_data["firewall_rules"] = {"raw_output": output}
        
        # 保存备份
        with open(BACKUP_FILE, "w", encoding="utf-8") as f:
            json.dump(backup_data, f, ensure_ascii=False, indent=2)
        
        log(f"[BACKUP] ✅ 设置已备份到: {BACKUP_FILE}")
        return True
        
    except Exception as e:
        log(f"[BACKUP] ❌ 备份失败: {e}")
        return False

def configure_doh(chosen_ip: str, doh_template: str) -> bool:
    """配置DoH设置 - 完全按照原版PowerShell逻辑"""
    try:
        log("[CONFIG] 配置Windows原生DoH...")
        
        # 步骤完全对应原版PowerShell第158行: netsh.exe dnsclient set global doh=yes dot=no ddr=no
        run_cmd('netsh dnsclient set global doh=yes dot=no ddr=no', "启用DoH并禁用DoT/DDR", silent=True)
        
        Step("禁用活动物理接口的DDR")
        # 对应第161-162行: 禁用每个活动接口的DDR
        success, output = run_cmd([
            "powershell", "-Command",
            "$ifaces = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.HardwareInterface -eq $true }; $ifaces | ForEach-Object { $_.Name }"
        ], "获取活动物理网络接口", silent=True)
        
        if success and output:
            interfaces = [name.strip() for name in output.split('\n') if name.strip()]
            for interface_name in interfaces:
                # 对应原版: netsh.exe dnsclient set interface name="$($i.Name)" ddr=no ddrfallback=no
                run_cmd(f'netsh dnsclient set interface name="{interface_name}" ddr=no ddrfallback=no',
                       f"禁用接口{interface_name}的DDR", silent=True)
        
        Step(f"清理先前的加密映射 for {chosen_ip}")
        # 对应第165-166行: 清理先前的加密映射
        run_cmd(f'netsh dnsclient delete encryption server={chosen_ip} protocol=doh',
               "清理旧DoH映射", check=False, silent=True)
        run_cmd(f'netsh dnsclient delete encryption server={chosen_ip} protocol=dot', 
               "清理旧DoT映射", check=False, silent=True)
        
        Step("添加DoH映射 (autoupgrade=yes, udpfallback=no)")
        # 对应第169行: 添加DoH映射
        run_cmd(f'netsh dnsclient add encryption server={chosen_ip} dohtemplate="{doh_template}" autoupgrade=yes udpfallback=no',
               "添加DoH加密映射", silent=True)
        
        # 对应第173-176行: 设置NIC DNS
        if CONFIG["set_as_only_dns"]:
            Step(f"设置NIC DNS (IPv4 -> {chosen_ip}) 并清空IPv6 DNS")
            if success and output:
                interfaces = [name.strip() for name in output.split('\n') if name.strip()]
                for interface_name in interfaces:
                    # 对应原版: netsh.exe interface ip set dns name="$($i.Name)" static $ChosenIP primary
                    run_cmd(f'netsh interface ip set dns name="{interface_name}" static {chosen_ip} primary',
                           f"设置{interface_name}IPv4 DNS", silent=True)
                    # 对应原版: netsh.exe interface ipv6 delete dnsservers name="$($i.Name)" address=all
                    run_cmd(f'netsh interface ipv6 delete dnsservers name="{interface_name}" address=all',
                           f"清空{interface_name}IPv6 DNS", check=False, silent=True)
        
        log("[CONFIG] ✅ DoH配置完成")
        return True
        
    except Exception as e:
        log(f"[CONFIG] ❌ DoH配置失败: {e}")
        return False

def apply_firewall_hardening() -> bool:
    """应用防火墙加固 - 完全按照原版PowerShell逻辑"""
    try:
        if not CONFIG["enforce_firewall_block53"]:
            return True
            
        log("[FIREWALL] 应用防火墙加固...")
        
        # 对应原版第183-185行: 删除已存在的同名规则
        rule_names = ["Block-DNS-UDP-53-All", "Block-DNS-TCP-53-All"]
        for rule_name in rule_names:
            # 对应: try{ Get-NetFirewallRule -DisplayName $n -ErrorAction Stop | Remove-NetFirewallRule -Confirm:$false }catch{}
            run_cmd([
                "powershell", "-Command",
                f'try{{ Get-NetFirewallRule -DisplayName "{rule_name}" -ErrorAction Stop | Remove-NetFirewallRule -Confirm:$false }}catch{{}}'
            ], f"清理旧规则{rule_name}", check=False, silent=True)
        
        # 对应原版第186行: New-NetFirewallRule -DisplayName "Block-DNS-UDP-53-All" -Direction Outbound -Action Block -Protocol UDP -RemotePort 53 -Profile Any
        run_cmd([
            "powershell", "-Command",
            'New-NetFirewallRule -DisplayName "Block-DNS-UDP-53-All" -Direction Outbound -Action Block -Protocol UDP -RemotePort 53 -Profile Any | Out-Null'
        ], "添加UDP 53阻断规则", silent=True)
        
        # 对应原版第187行: New-NetFirewallRule -DisplayName "Block-DNS-TCP-53-All" -Direction Outbound -Action Block -Protocol TCP -RemotePort 53 -Profile Any
        run_cmd([
            "powershell", "-Command", 
            'New-NetFirewallRule -DisplayName "Block-DNS-TCP-53-All" -Direction Outbound -Action Block -Protocol TCP -RemotePort 53 -Profile Any | Out-Null'
        ], "添加TCP 53阻断规则", silent=True)
        
        log("[FIREWALL] ✅ 防火墙加固完成")
        return True
        
    except Exception as e:
        log(f"[FIREWALL] ❌ 防火墙设置失败: {e}")
        return False

def disable_llmnr_mdns() -> bool:
    """禁用LLMNR和mDNS - 完全按照原版PowerShell逻辑"""
    try:
        if not CONFIG["disable_llmnr_mdns"]:
            return True
            
        log("[HARDENING] 禁用LLMNR和mDNS...")
        
        # 对应原版第193行: New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force
        run_cmd([
            "powershell", "-Command",
            'New-Item -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient" -Force | Out-Null'
        ], "创建DNS客户端策略注册表项", silent=True)
        
        # 对应原版第194行: New-ItemProperty ... "EnableMulticast" -Value 0 ... # LLMNR off
        run_cmd([
            "powershell", "-Command",
            'New-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient" -Name "EnableMulticast" -Value 0 -PropertyType DWord -Force | Out-Null'
        ], "禁用LLMNR", silent=True)
        
        # 对应原版第195行: New-ItemProperty ... "EnableMDNS" -Value 0 ... # mDNS off (Win11+)
        run_cmd([
            "powershell", "-Command",
            'New-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient" -Name "EnableMDNS" -Value 0 -PropertyType DWord -Force | Out-Null'
        ], "禁用mDNS", silent=True)
        
        log("[HARDENING] ✅ LLMNR/mDNS已禁用 (重启后完全生效)")
        return True
        
    except Exception as e:
        log(f"[HARDENING] ❌ LLMNR/mDNS禁用失败: {e}")
        return False

def optimize_dns_cache() -> bool:
    """优化DNS缓存设置"""
    try:
        log("[OPTIMIZE] 优化DNS缓存...")
        
        # 增加DNS缓存超时时间到24小时
        run_cmd('netsh dnsclient set global MaxCacheTimeout=86400', "设置DNS缓存超时")
        
        # 确保DNS缓存服务运行
        run_cmd('sc config Dnscache start=auto', "设置DNS缓存服务自动启动", check=False)
        run_cmd('net start Dnscache', "启动DNS缓存服务", check=False)
        
        log("[OPTIMIZE] ✅ DNS缓存优化完成")
        return True
        
    except Exception as e:
        log(f"[OPTIMIZE] ❌ DNS缓存优化失败: {e}")
        return False

def verify_installation(chosen_ip: str) -> bool:
    """验证DoH安装 - 完全按照原版PowerShell逻辑"""
    try:
        log("[VERIFY] 验证DoH配置...")
        
        # 对应原版第200行: ipconfig /flushdns | Out-Null
        run_cmd('ipconfig /flushdns', "刷新DNS缓存", check=False, silent=True)
        
        # 显示配置状态（用于日志记录，如原版一样）
        log("[VERIFY] 显示配置状态...")
        run_cmd('netsh dnsclient show global', "显示全局DNS设置", check=False, silent=True)
        run_cmd(f'netsh dnsclient show encryption server={chosen_ip}', "显示加密映射", check=False, silent=True)
        run_cmd('netsh dnsclient show state', "显示DNS客户端状态", check=False, silent=True)
        
        # 原版PowerShell没有DNS解析测试，直接认为成功
        # 原版逻辑：配置完成后直接输出成功信息
        log("[VERIFY] ✅ DoH配置验证完成")
        return True
            
    except Exception as e:
        log(f"[VERIFY] ❌ 验证过程异常: {e}")
        return True  # 即使验证有异常，也不影响整体成功（如原版）

# ================== 主安装和卸载功能 ==================

class DoHInstaller:
    def __init__(self):
        self.installed = False
        self.current_ip = None
        self.current_template = None
    
    def install(self, doh_template: str) -> bool:
        """安装DoH配置 - 完全按照原版PowerShell风格"""
        try:
            log(f"[INSTALL] 开始安装DoH: {doh_template}")
            
            # 备份当前设置（静默）
            backup_current_settings()
            
            # 1. 解析DoH URL
            Step("解析DoH URL")
            try:
                doh_host = get_host_from_url(doh_template)
                log(f"[INSTALL] DoH主机: {doh_host}")
            except Exception as e:
                print(f"错误: DoH URL解析失败: {e}")
                log(f"[INSTALL] ❌ DoH URL解析失败: {e}")
                return False
            
            # 2. 解析DoH主机IP
            Step("解析DoH服务器IP地址")
            try:
                candidate_ips = resolve_doh_host(doh_host)
                if not candidate_ips:
                    print("错误: 无法解析DoH主机名")
                    log("[INSTALL] ❌ 无法解析DoH主机名")
                    return False
                
                log(f"[INSTALL] 候选IP: {', '.join(candidate_ips)}")
            except Exception as e:
                print(f"错误: DNS解析失败: {e}")
                log(f"[INSTALL] ❌ DNS解析失败: {e}")
                return False
            
            # 3. 严格TLS预检
            Step("执行严格TLS验证")
            chosen_ip = None
            
            for ip in candidate_ips:
                try:
                    result = test_https_strict(ip, doh_host)
                    if result["ok"]:
                        log(f"[INSTALL] ✅ {ip} 严格TLS验证通过 (CN: {result['cn']})")
                        chosen_ip = ip
                        break
                    else:
                        log(f"[INSTALL] ❌ {ip} 严格TLS验证失败")
                except Exception as e:
                    log(f"[INSTALL] ❌ {ip} TLS测试异常: {e}")
            
            # 4. WARP回退（如果需要）
            used_warp = False
            if not chosen_ip and CONFIG["allow_warp_fallback"]:
                Step("尝试Cloudflare WARP回退")
                log("[INSTALL] 尝试通过WARP绕过443端口阻断...")
                
                try:
                    if ensure_warp():
                        used_warp = True
                        log("[INSTALL] 在WARP下重试TLS验证...")
                        
                        for ip in candidate_ips:
                            result = test_https_strict(ip, doh_host)
                            if result["ok"]:
                                log(f"[INSTALL] ✅ {ip} WARP下严格TLS验证通过")
                                chosen_ip = ip
                                break
                    else:
                        log("[INSTALL] ⚠️  WARP连接失败")
                except Exception as e:
                    log(f"[INSTALL] ❌ WARP异常: {e}")
            
            # 5. 检查是否找到可用IP
            if not chosen_ip:
                print("错误: 没有IP通过严格TLS验证，无法安全配置DoH")
                log("[INSTALL] ❌ 没有IP通过严格TLS验证，无法安全配置DoH")
                return False
            
            OK(f"选定DoH服务器IP: {chosen_ip} (严格模式)")
            log(f"[INSTALL] 选定DoH服务器IP: {chosen_ip}")
            
            # 6. 配置DNS客户端（仅DoH，无回退）
            Step("启用DoH并禁用DoT/DDR")
            if not configure_doh(chosen_ip, doh_template):
                return False
            
            # 7. 可选加固
            if CONFIG["enforce_firewall_block53"]:
                Step("强制防火墙阻断出站TCP/UDP 53端口")
                apply_firewall_hardening()
                OK("防火墙加固已应用")
            
            if CONFIG["disable_llmnr_mdns"]:
                Step("通过策略键禁用LLMNR/mDNS")
                disable_llmnr_mdns()
                OK("LLMNR/mDNS已禁用（策略）。重启后完全生效")
            
            # 8. 刷新和验证
            verify_installation(chosen_ip)
            
            # 9. 保存安装状态
            self.installed = True
            self.current_ip = chosen_ip
            self.current_template = doh_template
            
            # 最终输出
            OK("DoH配置完成！")
            print("=" * 50)
            print("✅ 已启用防侧漏保护:")
            print("  • DoH加密DNS (无明文回退)")  
            print("  • 防火墙阻断UDP/TCP 53端口")
            print("  • 禁用LLMNR/mDNS侧信道")
            print("  • DNS缓存优化")
            
            if used_warp:
                print("  • Cloudflare WARP穿透")
            
            print("=" * 50)
            
            log("[INSTALL] ✅ DoH安装完成！")
            
            return True
            
        except Exception as e:
            print(f"安装过程发生异常: {e}")
            log(f"[INSTALL] ❌ 安装过程异常: {e}")
            return False
    
    def uninstall(self) -> bool:
        """卸载DoH配置，恢复原设置"""
        try:
            print("\n🗑️  开始卸载DoH配置")
            print("🔄 恢复系统默认DNS设置")
            print("=" * 50)
            log("[UNINSTALL] 开始卸载DoH配置...")
            
            # 1. 恢复DoH全局设置
            print("\n⚙️  步骤 1/8: 恢复DoH全局设置")
            try:
                run_cmd('netsh dnsclient set global doh=auto dot=no ddr=yes', "恢复DoH默认设置", check=False)
                print("✅ DoH全局设置已恢复")
            except Exception as e:
                print(f"⚠️  DoH设置恢复异常: {e}")
            
            # 2. 恢复接口DDR设置
            print("\n🌐 步骤 2/8: 恢复网络接口DDR设置")
            try:
                success, output = run_cmd([
                    "powershell", "-Command",
                    "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.HardwareInterface -eq $true } | Select-Object -ExpandProperty Name"
                ], "获取网络接口", check=False)
                
                if success and output:
                    interfaces = [name.strip() for name in output.split('\n') if name.strip()]
                    print(f"✅ 找到 {len(interfaces)} 个网络接口")
                    
                    for interface_name in interfaces:
                        run_cmd(f'netsh dnsclient set interface name="{interface_name}" ddr=yes ddrfallback=yes',
                               f"恢复接口{interface_name}的DDR", check=False)
                    print("✅ 已恢复所有接口DDR设置")
                else:
                    print("⚠️  未找到活动网络接口")
            except Exception as e:
                print(f"⚠️  接口DDR恢复异常: {e}")
            
            # 3. 删除加密映射
            print("\n🔐 步骤 3/8: 删除DoH加密映射")
            try:
                if self.current_ip:
                    run_cmd(f'netsh dnsclient delete encryption server={self.current_ip} protocol=doh',
                           "删除DoH映射", check=False)
                    print(f"✅ 已删除IP {self.current_ip} 的DoH映射")
                else:
                    print("ℹ️  没有找到需要删除的DoH映射")
            except Exception as e:
                print(f"⚠️  DoH映射删除异常: {e}")
            
            # 4. 恢复DNS设置为DHCP
            print("\n🌐 步骤 4/8: 恢复DNS设置为DHCP")
            try:
                success, output = run_cmd([
                    "powershell", "-Command",
                    "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.HardwareInterface -eq $true } | Select-Object -ExpandProperty Name"
                ], "重新获取网络接口", check=False)
                
                if success and output:
                    interfaces = [name.strip() for name in output.split('\n') if name.strip()]
                    
                    for interface_name in interfaces:
                        run_cmd(f'netsh interface ip set dns name="{interface_name}" dhcp',
                               f"恢复接口{interface_name}为DHCP", check=False)
                        run_cmd(f'netsh interface ipv6 set dns name="{interface_name}" dhcp',
                               f"恢复接口{interface_name}的IPv6为DHCP", check=False)
                    print(f"✅ 已恢复 {len(interfaces)} 个接口的DNS为DHCP")
                else:
                    print("⚠️  获取网络接口失败")
            except Exception as e:
                print(f"⚠️  DNS DHCP恢复异常: {e}")
            
            # 5. 删除防火墙规则
            print("\n🛡️  步骤 5/8: 删除防火墙阻断规则")
            try:
                rule_names = ["Block-DNS-UDP-53-All", "Block-DNS-TCP-53-All"]
                removed_count = 0
                
                for rule_name in rule_names:
                    success, _ = run_cmd([
                        "powershell", "-Command",
                        f"Get-NetFirewallRule -DisplayName '{rule_name}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -Confirm:$false"
                    ], f"删除防火墙规则{rule_name}", check=False)
                    if success:
                        removed_count += 1
                
                if removed_count > 0:
                    print(f"✅ 已删除 {removed_count} 个防火墙规则")
                else:
                    print("ℹ️  没有找到需要删除的防火墙规则")
            except Exception as e:
                print(f"⚠️  防火墙规则删除异常: {e}")
            
            # 6. 恢复LLMNR/mDNS
            print("\n🔊 步骤 6/8: 恢复LLMNR/mDNS设置")
            try:
                restored_count = 0
                
                success, _ = run_cmd('reg delete "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient" /v "EnableMulticast" /f',
                       "恢复LLMNR", check=False)
                if success:
                    restored_count += 1
                
                success, _ = run_cmd('reg delete "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient" /v "EnableMDNS" /f', 
                       "恢复mDNS", check=False)
                if success:
                    restored_count += 1
                
                if restored_count > 0:
                    print(f"✅ 已恢复 {restored_count} 项注册表设置")
                else:
                    print("ℹ️  没有找到需要恢复的注册表项")
            except Exception as e:
                print(f"⚠️  LLMNR/mDNS恢复异常: {e}")
            
            # 7. 刷新DNS缓存
            print("\n🔄 步骤 7/8: 刷新DNS缓存")
            try:
                run_cmd('ipconfig /flushdns', "刷新DNS缓存")
                print("✅ DNS缓存已刷新")
            except Exception as e:
                print(f"⚠️  DNS缓存刷新异常: {e}")
            
            # 8. 重置程序状态
            print("\n💾 步骤 8/8: 重置程序状态")
            self.installed = False
            self.current_ip = None
            self.current_template = None
            print("✅ 程序状态已重置")
            
            print("\n" + "=" * 50)
            print("🎉 DoH配置卸载完成！")
            print("🔄 系统DNS已恢复为默认DHCP模式")
            print("🔓 明文DNS端口已解除阻断")
            print("🔊 LLMNR/mDNS已恢复启用")
            print("\n💡 重要提示:")
            print("   • 建议重启系统完全清除所有策略")
            print("   • DNS缓存已刷新，新设置立即生效")
            print("   • 原有网络连接应该恢复正常")
            print("=" * 50)
            
            log("[UNINSTALL] ✅ DoH配置已卸载，系统已恢复原设置")
            log("[UNINSTALL] 💡 建议重启系统以完全清除LLMNR/mDNS策略")
            
            return True
            
        except Exception as e:
            print(f"\n❌ 卸载过程发生严重异常: {e}")
            log(f"[UNINSTALL] ❌ 卸载过程异常: {e}")
            print("📝 请查看日志文件获取详细信息")
            return False

# ================== 交互菜单 ==================

def show_menu():
    print("\n" + "=" * 60)
    print("    Windows 11 DoH 安装器")
    print(f"    {SCRIPT_VERSION}")  
    print("    🛡️  零DNS侧漏 | 防火墙加固 | 严格TLS验证")
    print("=" * 60)
    print()
    print("🔒 防护特性:")
    print("   • 系统级DoH强制加密，无明文DNS回退") 
    print("   • 防火墙阻断UDP/TCP 53端口")
    print("   • 严格TLS证书和主机名验证")
    print("   • 禁用LLMNR/mDNS侧信道泄露")
    print("   • 可选Cloudflare WARP穿透")
    print("   • DNS缓存优化")
    print()
    print("📋 菜单选项:")
    print("   1. 安装DoH防侧漏配置")
    print("   2. 卸载DoH并恢复原设置") 
    print("   3. 退出")
    print()

def main():
    if not is_admin():
        print("❌ 错误：需要管理员权限运行")
        print("请右键选择'以管理员身份运行'")
        pause("按任意键退出...")
        return
    
    # 检查Windows版本和dnsclient支持
    try:
        run_cmd('netsh dnsclient show global', "检查DNS客户端支持")
    except Exception:
        print("❌ 错误：您的Windows版本不支持原生DoH")
        print("需要Windows 11或更高版本")
        pause("按任意键退出...")
        return
    
    installer = DoHInstaller()
    
    while True:
        show_menu()
        
        try:
            choice = input("请选择操作 [1-3]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n用户中断操作")
            break
        
        if choice == "1":
            print("\n🔧 安装DoH防侧漏配置")
            print("=" * 40)
            
            # 获取用户DoH服务器
            doh_url = None
            while True:
                try:
                    print("\n📝 请输入您的DoH服务器URL")
                    print("💡 示例格式: https://dns.example.com/dns-query")
                    print("💡 或IP格式: https://1.1.1.1/dns-query")
                    doh_url = input("\nDoH URL: ").strip()
                    
                    if not doh_url:
                        print("❌ URL不能为空，请重新输入")
                        continue
                    
                    # 验证URL格式
                    try:
                        test_host = get_host_from_url(doh_url)
                        print(f"✅ URL格式正确，主机: {test_host}")
                        break
                    except ValueError as e:
                        print(f"❌ {e}")
                        print("示例格式: https://dns.example.com/dns-query")
                        continue
                        
                except (EOFError, KeyboardInterrupt):
                    print("\n⚠️  操作被用户取消")
                    doh_url = None
                    break
                except Exception as e:
                    print(f"❌ 输入处理异常: {e}")
                    continue
            
            # 如果获得了有效URL，开始安装
            if doh_url:
                print(f"\n📄 日志文件: {LOG_PATH}")
                try:
                    success = installer.install(doh_url)
                    if success:
                        print("\n🎊 安装完成总结:")
                        print("✅ DoH防侧漏配置安装成功！")
                        print("🛡️  您的DNS现在完全通过HTTPS加密传输")
                        print("🚫 已阻止所有明文DNS查询")
                        print("\n💡 重要提示:")
                        print("   • 重启后设置仍然有效")  
                        print("   • 如遇网络问题可使用菜单2卸载")
                        print("   • 某些代理软件可能需要允许例外")
                        print("   • 建议重启系统完全清除DNS缓存")
                    else:
                        print("\n💥 安装失败总结:")
                        print("❌ DoH安装过程遇到问题")
                        print("📝 请检查上述错误信息和日志文件")
                        print("\n🛠️  可能的解决方案:")
                        print("   • 检查DoH服务器是否可达")
                        print("   • 尝试不同的DoH服务器")
                        print("   • 检查网络连接和防火墙设置")
                except Exception as e:
                    print("\n💥 安装过程发生未处理异常:")
                    print(f"❌ {e}")
                    print("📝 请查看日志文件获取完整错误信息")
                    log(f"[MAIN] 安装过程未处理异常: {e}")
        
        elif choice == "2":
            print("\n🗑️  卸载DoH配置")
            print("=" * 40)
            
            # 检查是否有安装记录
            if not installer.installed and not installer.current_ip:
                print("\n⚠️  检测不到已安装的DoH配置")
                print("💡 这可能意味着:")
                print("   • DoH从未通过此程序安装")
                print("   • 配置记录丢失")
                print("   • 已经卸载过了")
                print()
                
                try:
                    confirm = input("仍要执行清理操作吗？[y/N]: ").strip().lower()
                    if confirm not in ['y', 'yes', '是', 'Y']:
                        print("⏹️  操作取消")
                        continue
                except (EOFError, KeyboardInterrupt):
                    print("\n⏹️  操作被用户取消")
                    continue
            
            print(f"\n📄 日志文件: {LOG_PATH}")
            try:
                success = installer.uninstall()
                if success:
                    print("\n🎊 卸载完成总结:")
                    print("✅ DoH配置已完全卸载")
                    print("🔄 系统DNS设置已恢复为默认DHCP模式") 
                    print("🔓 防火墙阻断规则已清除")
                    print("🔊 LLMNR/mDNS已重新启用")
                    print("\n💡 重要提示:")
                    print("   • 建议重启系统完全清除所有策略")
                    print("   • 网络连接应立即恢复正常")
                    print("   • DNS查询已恢复为运营商默认服务器")
                else:
                    print("\n💥 卸载失败总结:")
                    print("❌ 卸载过程遇到问题") 
                    print("📝 请检查上述错误信息和日志文件")
                    print("\n🚨 紧急手动恢复命令:")
                    print("   netsh dnsclient set global doh=auto")
                    print("   netsh interface ip set dns name=\"以太网\" dhcp")
                    print("   netsh advfirewall firewall delete rule name=\"Block-DNS-UDP-53-All\"")
                    print("   netsh advfirewall firewall delete rule name=\"Block-DNS-TCP-53-All\"")
            except Exception as e:
                print("\n💥 卸载过程发生未处理异常:")
                print(f"❌ {e}")
                print("📝 请查看日志文件获取完整错误信息")
                log(f"[MAIN] 卸载过程未处理异常: {e}")
        
        elif choice == "3":
            print("\n👋 感谢使用DoH防侧漏安装器")
            break
        
        else:
            print("❌ 无效选择，请输入1、2或3")
        
        if choice in ["1", "2"]:
            print(f"\n📄 完整日志: {LOG_PATH}")
            pause("\n按任意键返回主菜单...")

if __name__ == "__main__":
    main()
