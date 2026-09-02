# 校园网自动连接

连上校园网时不再需要手动点认证页，开机后会自动认证。梯子（Clash / 系统代理 / TUN）开着时，认证请求会绕过代理；如果本机开着 Clash 控制端口，还会在认证前临时切到 Direct，成功后再切回去。

只用于登录**你自己的**校园网账号，请遵守学校网络使用规定。

## 能做什么

1. **开机自动连**：登录系统后后台检查，没认证就自动点/登录，掉线也会重试。
2. **梯子开着也能认证 / 拔插网线后也能用**：
   - 认证请求不走系统 HTTP 代理
   - 尽量绑在校园网网卡上发，避免进 Clash TUN
   - 自动发现 Clash / Mihomo API（`9090` / `9097` 等）
   - 认证期间切 Direct，并临时关掉 TUN（拔插网线后 TUN 经常把默认路由截死）
   - 如果恢复 TUN 后系统又不通，会保持 TUN 关闭并写进日志
3. **常见认证页**：深澜 (srun)、锐捷 (eportal)、DrCOM，以及只需要点「连接」的页面。
4. **守护进程**：网卡 IP 一变（插上网线）立刻重试，不需要等很久。

## 环境要求

- Python 3.10 或更高
- Windows / macOS / Linux
- 已经能拿到校园网 IP（Wi-Fi 或网线已连上，只是还没点认证页）

## 安装

### Windows

1. 安装 [Python](https://www.python.org/downloads/)，勾选 **Add python.exe to PATH**。
2. 双击 `scripts\install.bat`。
3. 按提示填写学号、密码（如果页面只是点一下连接，账号密码留空）。
4. 选择安装开机自启。

以后也可以双击 `scripts\connect.bat` 立刻连一次。

### Linux / macOS

```bash
chmod +x scripts/install.sh scripts/connect.sh
./scripts/install.sh
```

## 常用命令

在项目目录里：

```bash
# Windows
.venv\Scripts\python -m campus_connect setup     # 交互配置 + 开机自启
.venv\Scripts\python -m campus_connect probe     # 探测认证页、网卡、梯子
.venv\Scripts\python -m campus_connect login     # 马上认证一次
.venv\Scripts\python -m campus_connect status    # 看当前能不能上网
.venv\Scripts\python -m campus_connect watch     # 后台守护
.venv\Scripts\python -m campus_connect install   # 只装开机自启
.venv\Scripts\python -m campus_connect uninstall
```

```bash
# Linux / macOS
.venv/bin/python -m campus_connect probe
.venv/bin/python -m campus_connect login
```

日志默认写在用户目录：

- Windows: `%USERPROFILE%\.campus-auto-connect\campus-connect.log`
- Linux / macOS: `~/.campus-auto-connect/campus-connect.log`

## 配置

第一次 `setup` 会生成 `config.yaml`（已加入 `.gitignore`，不要发给别人）。

对照 `config.example.yaml`，最常改这几项：

| 项 | 含义 |
| --- | --- |
| `username` / `password` | 校园网账号。一键连接可留空 |
| `portal_url` | 认证页地址。`probe` 能找到的话建议填上 |
| `backend` | `auto` 即可。也可强制 `srun` / `ruijie` / `drcom` / `generic` |
| `click_only` | 只点连接、不登录账号时设为 `true` |
| `campus_nic_name` | 物理网卡名。有 VMware 时建议填 `以太网`（以 `probe` 为准） |
| `vpn.clash_api` | Clash 控制地址，一般不用填，会自动扫端口 |
| `vpn.clash_secret` | Clash 的 secret，有就填 |
| `vpn.clash_disable_tun` | 认证时临时关 TUN，默认 true |
| `vpn.pre_commands` | 认证前额外执行的命令（例如暂时退出某个客户端） |

## 梯子是怎么处理的

校园网认证页往往只能从校园网直连访问。梯子一开（尤其是 TUN 模式），浏览器点「连接」会失败，所以以前得先关掉梯子。

另一种更常见的情况：**认证其实已经过了（网关记得你的电脑），但拔插网线后 TUN 把默认路由截走**，表现就是：没有弹出认证页，却必须先关掉梯子才能上网。这不是脚本制造的，而是梯子 TUN 和校园网卡抢路由。

本脚本会：

1. 清掉 `HTTP_PROXY` 等环境变量，`requests` 也不读系统代理。
2. 找到校园网卡，用这块网卡的 IP 当认证请求源地址。
3. 再单独测「系统默认路由」能不能上网。如果网卡直连是通的、默认路由不通，就判定为梯子把路截了。
4. 发现 Clash 控制端口时：临时改 Direct、关掉 TUN、刷新 DNS；成功后再尝试恢复。若一恢复又不通，就保持 TUN 关闭。
5. 临时关掉 Windows 系统代理（用完恢复）。

如果你用的不是 Clash（例如 v2rayN TUN），把暂时退出客户端的命令写到 `vpn.pre_commands`，连上后再用 `post_commands` 拉起来。Clash 更稳的用法是：**校园网环境改用系统代理，不要开 TUN**。

## 第一次连不上时

1. 先连上校园网，**暂时**关掉梯子，运行 `probe`。
2. 看输出里的认证页 URL 和类型，填进 `config.yaml` 的 `portal_url`。
3. 当前目录会生成 `portal-dump.html`，把认证页保存下来方便对照。
4. 深澜如果报 ac_id 错误，把页面地址里的 `ac_id=` 填到 `srun.ac_id`。
5. 再开梯子，运行 `login`，确认绕过代理也能成功。
6. 成功后再 `install` 开机自启。

如果认证页完全不像上面三种，把 `backend` 设成 `generic`（点按钮/提交表单），或用 `custom` 自己写一条 HTTP 请求。

## 原理简述

校园网在你没点认证前，会把访问普通网站的 HTTP 请求重定向到认证页。脚本做的事和浏览器里点「连接 / 登录」一样：发现重定向 → 按学校网关的接口提交 → 之后流量就能出校。它不会破解网关，也不会绕过学校的计费和账号体系。
