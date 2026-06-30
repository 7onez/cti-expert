# :cn: CTI Expert — 网络威胁情报与开源情报

🇬🇧 [English](README.md)&nbsp;&nbsp;·&nbsp;&nbsp;🇻🇳 [Tiếng Việt](README.vi.md)&nbsp;&nbsp;·&nbsp;&nbsp;🇨🇳 **[中文](README.zh-CN.md)**

---

### 什么是 CTI Expert？

一个 Claude Code 技能，将 Claude 转变为训练有素的网络威胁情报和开源情报分析师。使用 **67+ 个命令**、**36 种技术**进行结构化情报收集——核心功能无需 API 密钥。部分技术支持可选的免费 API 密钥以获取增强访问（如 Wigle、VirusTotal、URLScan.io）。

**v2.4 新功能：** 跨平台操作系统检测（Windows/macOS/Linux），按系统自动安装，DOCX 生成自愈（UTF-8 + pandoc）；**uv** 优先工具链（uv venv/pip/tool，PEP 723 `uv run` 零配置脚本）；**跨代理**支持——可在 Claude Code **和** OpenAI Codex 上通过 `AGENTS.md` 运行；信息窃取日志分析器（`/cti-expert /stealer-log`）——家族识别、受害者与操作者画像、跨日志关联、IOC 与原始数据提取；管理后台 / 敏感端点检测（admin/adm/kef/ador/panel…）；集成 **agent-browser**（vercel-labs）作为主要交互式浏览器采集器；全新干净环境/VPS 安装加固 + CI。

**v2.3 新功能：** 面向所有 TLD 的通用 WHOIS（whoisdomain + CLI + Whoxy API；.vn、.th、.sg、.kr…）、反向与历史 WHOIS；Scrapling 自适应网页采集（静态 → 反爬 → JS 渲染）；无头浏览器自动开启；AgentFlow 并行富化（DAG）；HTML 解析 ~2ms；最低要求 Python 3.10+。

**v2.2 新功能：** 图像取证与人脸搜索（FaceCheck.id、TinEye、FotoForensics、picarta.ai AI地理定位）、区块链调查（Blockchair、Etherscan、WalletExplorer、Chainabuse）、交通追踪（ADS-B Exchange飞机追踪、Marine Traffic船舶追踪、VIN解码器）、暗网调查（Ahmia.fi Tor搜索、ransomwatch）、社交媒体扩展（Reddit、Instagram、TikTok、Telegram）、人员搜索（TruePeopleSearch、IDCrawl）、11个跨平台Google mega-dork模板覆盖73个域名。

**v2.1 新功能：** 攻击路径可视化（`/cti-expert /render threat-path`）、攻击面映射（`/cti-expert /render attack-surface`）、STIX 2.1 IOC 导出（`/cti-expert /report ioc`）、时间风险追踪（`/cti-expert /drift`）、Wayback 快照（`/cti-expert /snapshots`、`/cti-expert /diff`）、新手引导（`/cti-expert /onboard`）、发现解释（`/cti-expert /clarify`）、盲点分析（`/cti-expert /blind-spots`）、来源检查（`/cti-expert /source-check`）、会话比较（`/cti-expert /workspace diff`）、质量评分（`/cti-expert /quality`）、来源可靠性 A-F 等级、4 种新实体类型。

**核心能力：** 对任何目标类型（个人、域名、组织、用户名、电子邮件、IP、WiFi）进行多向量侦察，具备自动发现验证、暴露风险评分，以及多格式结构化情报交付。

**工作流程：** AEAD 生命周期——获取原始数据 &rarr; 通过枢轴扩展丰富 &rarr; 评估发现 &rarr; 交付结构化报告（Markdown + 带图表、图形、专业格式的 Word 文档）。

---

### 安装

> **推荐：** 使用 **Claude Code CLI** — 提供完整的终端工作流、持久会话和直接技能调用。[点击下载](https://docs.anthropic.com/en/docs/claude-code/overview) 或运行 `npm install -g @anthropic-ai/claude-code`。

#### 为什么推荐 Claude Code CLI？

整个 CTI Expert 工作流针对 Claude Code CLI 进行了优化：
- **持久会话** — 调查通过 `/cti-expert /workspace save` 跨重启保存
- **完整工具访问** — 文件写入、Python 脚本、DOCX 生成均原生运行
- **直接调用技能** — 在终端中直接输入 `/cti-expert`
- **并行 Agent** — AgentFlow 在 CLI 下运行效果最佳

#### 🖥️ 在哪里运行 — 本技能在 CLI 中体验最佳

> [!IMPORTANT]
> CTI Expert **执行密集**：运行 `uv`/Python、安装 OSINT 工具、写入 `.md`/`.docx`/`.json` 报告、访问大量外部站点、保存案例工作区。关键在于**真实的本地 shell + 持久化文件 + 开放网络**——**CLI 或本地桌面代理**能提供这些，而临时的**云沙箱则不能**。这对 **Claude** 和 **Codex** 同样适用。

| 环境 | 运行调查 | 原因 |
|---|---|---|
| **Claude Code CLI** · **Codex CLI** | ✅ **最佳** | 真实 shell、持久化、后台任务、开放网络——正是本技能所需 |
| **Claude Code 桌面版** · **Codex IDE 扩展** | ✅ 很好 | 同样的本地执行能力；阅读渲染后的报告、图表与示意图最为舒适 |
| **claude.ai/code（网页）** · **Codex 云端 / ChatGPT 网页** | ⚠️ 受限 | 分析推理与查询生成可用，但文件不会持久化到你的磁盘，且对外网络通常受限 |

> [!TIP]
> **在 CLI 中运行调查**（Claude Code 或 Codex）；如果你更喜欢在桌面/IDE 窗口中阅读，可在那里打开生成的 `.docx`/报告。网页/云端环境仅用于分析推理，不要用于执行密集的侦察。

---

#### 第一步 &mdash; 安装 Claude Code CLI

```bash
npm install -g @anthropic-ai/claude-code
```

> 需要 Node.js 18+。完整文档：[docs.anthropic.com/en/docs/claude-code/overview](https://docs.anthropic.com/en/docs/claude-code/overview)

---

#### 第二步 &mdash; 克隆 + 一键安装

`scripts/install.sh` 安装脚本处理所有内容：Python venv 依赖、系统工具（`whois`、`dig`、`jq`、`exiftool`）、OSINT 工具（`maigret`、`sherlock`、`holehe`、`h8mail` 等），以及可选的无头浏览器和 Go 工具。

<table>
<tr>
<th>操作系统</th>
<th>命令</th>
</tr>
<tr>
<td><b>Linux / macOS</b></td>
<td>

```bash
git clone https://github.com/7onez/cti-expert.git ~/.claude/skills/cti-expert
bash ~/.claude/skills/cti-expert/scripts/install.sh
```

</td>
</tr>
<tr>
<td><b>Windows（Git Bash 或 WSL）</b></td>
<td>

```bash
git clone https://github.com/7onez/cti-expert.git ~/.claude/skills/cti-expert
bash ~/.claude/skills/cti-expert/scripts/install.sh
```

</td>
</tr>
<tr>
<td><b>Windows（PowerShell — 手动）</b></td>
<td>

```powershell
git clone https://github.com/7onez/cti-expert.git "$env:USERPROFILE\.claude\skills\cti-expert"
pip3 install -r "$env:USERPROFILE\.claude\skills\cti-expert\scripts\requirements.txt"
```

</td>
</tr>
</table>

> **Windows 用户：** 安装脚本在 **Git Bash**（随 [Git for Windows](https://git-scm.com/download/win) 附带）或 **WSL** 中原生运行。PowerShell 是仅安装 Python 依赖的备用方案。

---

#### 安装选项

```bash
bash scripts/install.sh               # 基础：Python 依赖 + 系统工具 + OSINT 工具
bash scripts/install.sh --headless    # + Scrapling 无头浏览器（~200MB Chromium）
bash scripts/install.sh --go          # + Go 工具（subfinder、amass、gau、gitleaks、httpx）
bash scripts/install.sh --all         # + 以上所有内容
```

| 标志 | 安装内容 | 大小 |
|------|---------|------|
| *(无)* | Python 包、whois、dig、jq、exiftool、maigret、sherlock、holehe、h8mail、theHarvester、trufflehog、waymore、xeuledoc、agentflow | ~50 MB |
| `--headless` | Scrapling StealthyFetcher + DynamicFetcher + Chromium | +200 MB |
| `--go` | subfinder、amass、gau、gitleaks、httpx、phoneinfoga | +150 MB |
| `--all` | 全部内容 | ~400 MB |

---

#### 验证安装

```bash
claude   # 打开 Claude Code CLI
# 然后输入：
/cti-expert
```

---

#### 备选方案 &mdash; Claude Code 桌面版（macOS / Windows）

> 下载：[claude.ai/download](https://claude.ai/download) &mdash; 支持 **macOS** 和 **Windows**

1. **安装 Claude Code 桌面版** &mdash; 从 [claude.ai/download](https://claude.ai/download) 下载并安装应用
2. **下载 CTI Expert** &mdash; 访问 [GitHub 仓库](https://github.com/7onez/cti-expert)，点击绿色 **"Code"** 按钮，然后选择 **"Download ZIP"**
3. **解压到 skills 文件夹** &mdash; 解压文件，将文件夹重命名为 `cti-expert` 并移动到：

   | 操作系统 | 路径 |
   |---------|------|
   | **macOS** | `~/.claude/skills/` （Finder &rarr; Cmd+Shift+G） |
   | **Windows** | `%USERPROFILE%\.claude\skills\` （文件资源管理器地址栏） |

4. **运行安装脚本** &mdash; 在 Claude Code Desktop 终端中运行：

   ```bash
   bash ~/.claude/skills/cti-expert/scripts/install.sh
   ```

   或在 Windows PowerShell（仅 Python）：

   ```powershell
   pip3 install -r "$env:USERPROFILE\.claude\skills\cti-expert\scripts\requirements.txt"
   ```

5. **重启 Claude Code 桌面版** &mdash; 关闭并重新打开应用
6. **验证** &mdash; 输入 `/cti-expert` 确认技能已加载

<details>
<summary><b>系统要求</b></summary>
<br>

| 要求 | 版本 | 用途 |
|------|------|------|
| [Claude Code CLI](https://docs.anthropic.com/en/docs/claude-code/overview) | 最新版 | **推荐** — 终端运行时 |
| [Claude Code 桌面版](https://claude.ai/download) | 最新版 | 图形界面运行时（macOS/Windows） |
| Node.js | 18+ | Claude Code CLI 所需 |
| Python | 3.10+ | DOCX 报告生成、Scrapling、AgentFlow |
| pip 包 | 见 `requirements.txt` | 图表、图形、样式 |
| git | 任意版本 | 克隆仓库 |

</details>

---

### 快速入门

```bash
/cti-expert /case example.com                   # 完全自动案例
/cti-expert /flow person                        # 人员调查流程
/cti-expert /flow domain                        # 域名侦察流程
/cti-expert /sweep @username                    # 对账号进行多向量侦察
/cti-expert /query example.com                  # 12-15 个高级搜索查询
/cti-expert /username johndoe                   # 平台枚举（3000+）
/cti-expert /email-deep user@domain.com         # 深度电子邮件调查
/cti-expert /github-osint github.com/org/repo   # GitHub 资料、仓库、代码、提交、分叉
/cti-expert /exposure domain.com                # 综合风险评分（0-100）
/cti-expert /report                             # 技术 INTSUM 报告
/cti-expert /workspace save                     # 保存工作空间 + 自动生成 .docx
```

---

### 功能领域

| 领域 | 能力 |
|------|------|
| **身份与人员** | 人员查询（50+ 数据点）、电话调查、深度邮件分析、用户名枚举（3000+ 平台）、GitHub 开发者足迹 |
| **域名与基础设施** | 子域枚举、技术指纹、DNS 取证、流量分析 |
| **分析与验证** | 图像验证、元数据取证、网页取证、泄露数据库 |
| **WiFi 与地理定位** | 通过 Wigle.net WiFi 定位、高级地理定位（W3W、Plus Codes、MGRS） |
| **安全审计** | 云审计（AWS/GCP/Azure）、OWASP 审计、依赖审计、提示注入审计 |
| **报告与导出** | Markdown 报告、带图表的 DOCX、案例工作空间、专业格式 |

---

### 道德与负责任使用

**此技能仅用于合法研究和专业安全调查。**

**允许：** 新闻事实核查、人力资源筛选（需征得同意）、企业安全研究、授权渗透测试、法律/合规调查、个人声誉监控。

**禁止：** 人肉搜索、骚扰、跟踪、未授权监控、社会工程、欺诈、隐私侵犯、犯罪活动。

---

## 🙏 致谢与鸣谢

CTI Expert 站在开源社区和免费公益数据提供方的肩膀上。在此向下列每一个项目、厂商和免费 API 致以诚挚的感谢——没有你们的付出，就没有这个技能。*(列出并不代表关联或背书；请始终遵守各提供方的服务条款。)*

| 类别 | 我们致谢的项目与免费服务 |
|------|--------------------------|
| **代理与运行时** | [Anthropic — Claude Code](https://claude.com/claude-code) · [OpenAI — Codex](https://developers.openai.com/codex) · [Astral — uv](https://docs.astral.sh/uv/) · [Python](https://www.python.org) · [Node.js](https://nodejs.org) · [Rust](https://www.rust-lang.org) |
| **浏览器与网页采集** | [agent-browser — Vercel Labs](https://github.com/vercel-labs/agent-browser) · [Scrapling](https://github.com/D4Vinci/Scrapling) · [Chromium](https://www.chromium.org) |
| **用户名、人物与社交** | [Maigret](https://github.com/soxoj/maigret) · [Sherlock](https://github.com/sherlock-project/sherlock) · [Blackbird](https://github.com/p1ngul1n0/blackbird) · [instaloader](https://github.com/instaloader/instaloader) · [Osintgram](https://github.com/Datalux/Osintgram) · [toutatis](https://github.com/megadose/toutatis) · [ShareTrace](https://github.com/7onez/sharetrace) |
| **邮箱与泄露数据** | [Holehe](https://github.com/megadose/holehe) · [h8mail](https://github.com/khast3x/h8mail) · [theHarvester](https://github.com/laramies/theHarvester) · [Have I Been Pwned](https://haveibeenpwned.com) · [Hudson Rock](https://www.hudsonrock.com) · [LeakCheck](https://leakcheck.io) |
| **域名、DNS 与基础设施** | [Subfinder](https://github.com/projectdiscovery/subfinder) · [Amass](https://github.com/owasp-amass/amass) · [httpx](https://github.com/projectdiscovery/httpx) · [GAU](https://github.com/lc/gau) · [crt.sh](https://crt.sh) · [Whoxy](https://www.whoxy.com) · [ViewDNS](https://viewdns.info) · [whoisdomain](https://github.com/mboot-github/WhoisDomain) · [Shodan InternetDB](https://internetdb.shodan.io) · [ipwho.is](https://ipwho.is) |
| **威胁情报** | [VirusTotal](https://www.virustotal.com) · [URLScan.io](https://urlscan.io) · [GreyNoise](https://www.greynoise.io) · [AbuseIPDB](https://www.abuseipdb.com) · [AlienVault OTX](https://otx.alienvault.com) · [abuse.ch](https://abuse.ch) (URLhaus · ThreatFox · MalwareBazaar) · [CIRCL](https://www.circl.lu) · [NVD](https://nvd.nist.gov) · [ransomware.live](https://www.ransomware.live) |
| **凭据与代码** | [TruffleHog](https://github.com/trufflesecurity/trufflehog) · [Gitleaks](https://github.com/gitleaks/gitleaks) · [GitHub CLI](https://cli.github.com) |
| **电话** | [PhoneInfoga](https://github.com/sundowndev/phoneinfoga) · FreeCNAM · WhoCalld |
| **地理定位与 WiFi** | [OpenStreetMap](https://www.openstreetmap.org) · [what3words](https://what3words.com) · [Overpass Turbo](https://overpass-turbo.eu) · [WiGLE](https://wigle.net) |
| **图像取证** | [ExifTool](https://exiftool.org) · [TinEye](https://tineye.com) · [FaceCheck.id](https://facecheck.id) · [FotoForensics](https://fotoforensics.com) · [picarta.ai](https://picarta.ai) |
| **区块链** | [Blockchair](https://blockchair.com) · [Etherscan](https://etherscan.io) · [WalletExplorer](https://www.walletexplorer.com) · [Chainabuse](https://www.chainabuse.com) |
| **交通追踪** | [ADS-B Exchange](https://www.adsbexchange.com) · [Flightradar24](https://www.flightradar24.com) · [MarineTraffic](https://www.marinetraffic.com) · [VesselFinder](https://www.vesselfinder.com) |
| **暗网** | [Ahmia](https://ahmia.fi) · [OnionSearch](https://github.com/megadose/OnionSearch) · [ransomwatch](https://github.com/joshhighet/ransomwatch) |
| **云与文档** | [MSFTRecon](https://github.com/Arcanum-Sec/msftrecon) · [Xeuledoc](https://github.com/Malfrats/xeuledoc) · [oletools](https://github.com/decalage2/oletools) · [poppler](https://poppler.freedesktop.org) · [qpdf](https://github.com/qpdf/qpdf) · [mat2](https://0xacab.org/jvoisin/mat2) · [The Sleuth Kit](https://www.sleuthkit.org) |
| **网页存档** | [Internet Archive — Wayback](https://web.archive.org) · [Waymore](https://github.com/xnl-h4ck3r/waymore) |
| **报告与工具** | [pandoc](https://pandoc.org) · [python-docx](https://github.com/python-openxml/python-docx) · [Matplotlib](https://matplotlib.org) · [NetworkX](https://networkx.org) · [jq](https://jqlang.github.io/jq/) · [ASN](https://github.com/nitefood/asn) |
| **标准与框架** | [OWASP](https://owasp.org) · [MITRE ATT&CK](https://attack.mitre.org) · [STIX 2.1 (OASIS)](https://oasis-open.github.io/cti-documentation/) · [NIST SP 800-61](https://csrc.nist.gov/pubs/sp/800/61/r2/final) · [CWE](https://cwe.mitre.org) |

> 有我们应当致谢的项目，或希望修改/移除你的项目署名？欢迎提交 issue 或 PR——我们会尽快处理。💙

---

**作者：** [Hieu Ngo](https://chongluadao.vn) &bull; [hieu.ngo@chongluadao.vn](mailto:hieu.ngo@chongluadao.vn) &bull; **版本：** 2.4 &bull; **许可证：** MIT
