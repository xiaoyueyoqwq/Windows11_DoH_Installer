# Windows 11 原生 DoH 安装/卸载器

## 功能
- 以管理员身份运行的交互式安装器
- 输入 DoH 模板 URL（默认示例：`https://223.5.5.5/dns-query`）
- 解析 → 严格 HTTPS 预握手（SNI=主机名）→ 选用可用 IP
- 关闭 DoT/DDR，启用 DoH；删除旧映射后写入新映射
- 将所有活动物理网卡 IPv4 DNS 设为选定 IP（仅此一个）
- 可选：网络屏蔽 443 时自动安装并连接 Cloudflare WARP 再重试
- 卸载：恢复 DoH/DDR 默认、DNS 恢复为 DHCP（或按备份恢复）、可选卸载 WARP
- 打个广告：各位可以试试[果冻网络加速服务](https://rule.66a.net/free.php)，免费好用很良心

## 使用
1. 下载 `doh_installer.py` 到 Windows 11。
2. **以管理员身份**运行 PowerShell：
   ```powershell
   python doh_installer.py
   ```
   按提示操作。

## 打包为 EXE
已写好 PyInstaller 打包脚本：
```bat
py -3.11 -m PyInstaller --onefile --uac-admin --name DoT-Installer .\doh_installer.py
```
生成的 `dist\DoH-Installer.exe` 可直接双击运行（自动请求管理员）。

> 提示：若系统未安装 PyInstaller，先执行：
> ```powershell
> pip install pyinstaller
> ```
