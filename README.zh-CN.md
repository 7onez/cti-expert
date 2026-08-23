<div align="center">

# CTI Expert

### 网络威胁情报与开源情报分析工具箱

**把 Claude 变成一名训练有素的情报分析师 —— 74+ 条命令、49 种技术，核心功能零 API 密钥。**

<br>

<p>
  <a href="#安装">安装</a>&nbsp;&nbsp;|&nbsp;&nbsp;<a href="#演示">查看演示</a>&nbsp;&nbsp;|&nbsp;&nbsp;<a href="#快速入门">快速入门</a>&nbsp;&nbsp;|&nbsp;&nbsp;<a href="#命令参考">命令列表</a>&nbsp;&nbsp;|&nbsp;&nbsp;<a href="#参与贡献">参与贡献</a>
</p>

<br>

<!-- Feature Badges -->
<p>
  <a href="https://github.com/7onez/cti-expert"><img src="https://img.shields.io/badge/version-2.8-0080ff?style=for-the-badge&logo=semver&logoColor=white" alt="Version 2.8"></a>&nbsp;
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-00c853?style=for-the-badge&logo=opensourceinitiative&logoColor=white" alt="License: MIT"></a>&nbsp;
  <a href="#命令参考"><img src="https://img.shields.io/badge/commands-74+-ff6d00?style=for-the-badge&logo=windowsterminal&logoColor=white" alt="74+ Commands"></a>&nbsp;
  <a href="#技术目录"><img src="https://img.shields.io/badge/techniques-49-aa00ff?style=for-the-badge&logo=hackthebox&logoColor=white" alt="49 Techniques"></a>&nbsp;
  <a href="#安装"><img src="https://img.shields.io/badge/API_keys-none_for_core-00bfa5?style=for-the-badge&logo=shield&logoColor=white" alt="No API Keys for Core"></a>
</p>

<!-- GitHub Stats -->
<p>
  <a href="https://github.com/7onez/cti-expert/stargazers"><img src="https://img.shields.io/github/stars/7onez/cti-expert?style=flat-square&logo=github&label=Stars" alt="Stars"></a>&nbsp;
  <a href="https://github.com/7onez/cti-expert/network/members"><img src="https://img.shields.io/github/forks/7onez/cti-expert?style=flat-square&logo=github&label=Forks" alt="Forks"></a>&nbsp;
  <a href="https://github.com/7onez/cti-expert/releases"><img src="https://img.shields.io/github/downloads/7onez/cti-expert/total?style=flat-square&logo=github&label=Downloads&color=brightgreen" alt="Downloads"></a>&nbsp;
  <a href="https://github.com/7onez/cti-expert/issues"><img src="https://img.shields.io/github/issues/7onez/cti-expert?style=flat-square&logo=github&label=Issues" alt="Issues"></a>&nbsp;
  <a href="https://github.com/7onez/cti-expert/pulls"><img src="https://img.shields.io/github/issues-pr/7onez/cti-expert?style=flat-square&logo=github&label=PRs" alt="Pull Requests"></a>&nbsp;
  <a href="https://github.com/7onez/cti-expert/commits"><img src="https://img.shields.io/github/last-commit/7onez/cti-expert?style=flat-square&logo=github&label=Last%20Commit" alt="Last Commit"></a>&nbsp;
  <a href="https://github.com/7onez/cti-expert"><img src="https://img.shields.io/github/repo-size/7onez/cti-expert?style=flat-square&logo=github&label=Size" alt="Repo Size"></a>&nbsp;
  <a href="https://github.com/7onez/cti-expert/graphs/contributors"><img src="https://img.shields.io/github/contributors/7onez/cti-expert?style=flat-square&logo=github&label=Contributors" alt="Contributors"></a>
</p>

<!-- Language Selector -->
<p>
  🇬🇧 <a href="README.md">English</a>&nbsp;&nbsp;·&nbsp;&nbsp;🇻🇳 <a href="README.vi.md">Tiếng Việt</a>&nbsp;&nbsp;·&nbsp;&nbsp;🇨🇳 <a href="README.zh-CN.md"><b>中文</b></a>
</p>

<br>

<sub>作者 <a href="https://www.linkedin.com/in/hieu-minh-ngo-hieupc/"><b>Hieu Ngo</b></a> &bull; <a href="mailto:hieu.ngo@chongluadao.vn">hieu.ngo@chongluadao.vn</a> &bull; <a href="https://chongluadao.vn">chongluadao.vn</a></sub>

</div>

<br>

---

<br>

## 🤝 赞助与支持方

<div align="center">

**CTI Expert 完全开放构建。以下机构以数据、工具和一线调查经验支持本项目。**

<p>
  <a href="https://rexxfield.com"><img src="https://img.shields.io/badge/Rexxfield-网络犯罪调查-B3272D?style=for-the-badge" alt="Rexxfield"></a>&nbsp;
  <a href="https://www.hudsonrock.com"><img src="https://img.shields.io/badge/Hudson_Rock-信息窃取器情报-1B2A4A?style=for-the-badge" alt="Hudson Rock"></a>&nbsp;
  <a href="https://paranoidlab.com"><img src="https://img.shields.io/badge/ParanoidLab-暗网_%26_IAB-0F172A?style=for-the-badge" alt="ParanoidLab"></a>
</p>
<p>
  <a href="https://any.run"><img src="https://img.shields.io/badge/ANY.RUN-沙箱_%26_TI_Lookup-FF6A2B?style=for-the-badge" alt="ANY.RUN"></a>&nbsp;
  <a href="https://zetalytics.com"><img src="https://img.shields.io/badge/ZETAlytics-被动_DNS-0B7285?style=for-the-badge" alt="ZETAlytics"></a>&nbsp;
  <a href="https://intelx.io"><img src="https://img.shields.io/badge/IntelX-泄露与暗网检索-2B6E6B?style=for-the-badge" alt="Intelligence X"></a>
</p>

</div>

| 支持方 | 他们带来什么 | 在工具链中的位置 |
|--------|--------------|------------------|
| [**Rexxfield**](https://rexxfield.com) | 自 2008 年起从事网络犯罪调查与受害者侧办案——本技能的办案流程与归因标准正是以其实战方法论为蓝本 | 调查方法论 |
| [**Hudson Rock**](https://www.hudsonrock.com) | 信息窃取器感染情报——哪台主机泄露了哪些凭据、在什么时间 | `/breach-deep` · `/stealer-log` |
| [**ParanoidLab**](https://paranoidlab.com) | 覆盖论坛、交易市场与私密 Telegram 的暗网、初始访问代理（IAB）与窃取器日志监控 | 暗网采集与研判 |
| [**ANY.RUN**](https://any.run) | 交互式恶意软件沙箱 + **TI Lookup**——从加壳样本中获取沙箱实测的 C2 与真实端点 | `/binary` · `/hash-id` |
| [**ZETAlytics**](https://zetalytics.com) | 具备罕见地理多样性的全球被动 DNS——历史解析与同址共存枢轴 | `/webpivot` · `/cti-pivot` |
| [**IntelX**](https://intelx.io) | Intelligence X——粘贴站、泄露库、暗网与 phonebook 选择符检索 | `/webpivot` · `/email-deep` |

> [!IMPORTANT]
> **ANY.RUN 仅以只读方式使用。** `anyrun_lookup` 只查询 TI Lookup 中**已经**被引爆过的哈希。本技能**从不提交样本**——公开沙箱任务全网可读且不可撤回。该边界由一项回归测试强制保障（[`tests/test_no_sample_submission.py`](tests/test_no_sample_submission.py)），而非仅靠约定。

<sub>此处列出仅表示对本项目的支持，<b>不</b>意味着上述机构与本工具存在任何隶属、背书或认证关系。上表标注的集成均为可选且需要 API 密钥——<b>所有核心技术在零密钥情况下依然可用</b>。请始终遵守各提供方的服务条款。本技能所依赖的开源项目与免费公益服务的完整清单见<a href="#-致谢与鸣谢">致谢与鸣谢</a>。</sub>

<br>

---

<br>

## 什么是 CTI Expert？

一个 **Claude Code 技能**，把 Claude 变成一名训练有素的网络威胁情报与开源情报分析师。它以 **74+ 条命令**、**49 种技术**执行结构化情报收集 —— 核心功能无需任何 API 密钥。若想充分发挥能力，把你自己的**免费*或*付费** API 密钥写入技能的 `.env` —— 每个密钥都会被**自动检测**并解锁更高层级的访问（例如 Wigle、VirusTotal、URLScan.io、Shodan、Censys、SecurityTrails、WhoisXML）。

> [!TIP]
> **默认无密钥，有你的密钥则更强。** 每一项核心技术都能零密钥运行。把任意免费或付费密钥放入 `.env`（或运行 `/apikeys set <service> <KEY>`），技能会自动检测并解锁更高层级的枢轴：反向 favicon→主机、被动 DNS、证书检索、兄弟域名发现。缺失或失效的密钥绝不会中断运行 —— 它只会降级为一条提示。配置指南：[handbook/api-keys.md](handbook/api-keys.md)。

> [!TIP]
> **一个技能，两个层次。** cti-expert 是*广度采集器* —— 撒下大网（`/sweep`、`/webpivot`、`/subdomain`、`/username`、`/email-deep`…）。仓库内还内置了一条*深度流水线*（`intel_engine/`），把原始采集变成一个真正的案件：持久化知识库、带版本的案件、跨案件关联，以及经过校准的研判。整个流程读起来像一句话 —— **广泛采集 → "这个运营者以前见过吗？" → 聚类 → 过滤误报 → 研判。** 无需任何外部配置：后端解析为 `SELF`；深度层依赖只需安装一次 `uv venv && uv pip install -r requirements.txt`。架构说明：[connectors/intel-backend.md](connectors/intel-backend.md)。

<table>
<tr>
<td width="50%">

**核心能力**

对任意目标类型 —— 个人、域名、组织、用户名、邮箱、IP、WiFi —— 进行多向量侦察，配合自动化发现验证、暴露面评分与结构化情报交付。

</td>
<td width="50%">

**AEAD 工作流**

**A**cquire 采集原始数据 &rarr; **E**nrich 通过枢轴扩展富化 &rarr; **A**ssess 研判发现 &rarr; **D**eliver 交付结构化报告（交互式 HTML + Markdown + JSON/CSV + IOC 包；Word 按需生成）。

</td>
</tr>
</table>

<br>

---

<br>

## 演示

### 完整案件调查

<div align="center">
<img src="assets/demo-full-case.gif" alt="完整案件演示 —— /case 命令运行一次完整调查" width="800">
</div>

<br>

### CTI 报告生成

<div align="center">
<img src="assets/demo-cti-report.gif" alt="CTI 报告演示 —— Markdown + DOCX 报告输出" width="800">
</div>

<br>

### 截图

<div align="center">

| INTSUM 报告 | 网络拓扑 | 风险研判 |
|:---:|:---:|:---:|
| <img src="assets/intsum.png" alt="INTSUM 报告" width="280"> | <img src="assets/network-topology.png" alt="网络拓扑图" width="280"> | <img src="assets/risk-assessment.png" alt="风险研判评分" width="280"> |

</div>

<br>

---

<br>

## v2.8 新功能

> **这是引擎追上上游、并把安全护栏挪到 harness 真正看得见的位置的版本。** v2.7 让深度流水线落了地；v2.8 把 vendor 进来的引擎**向前推进了约 30 个 commit** —— **24 → 46 个 MCP 工具**、一项全新的交互技能，以及一个跑到收敛为止的案件循环 —— 然后修好了它底下那一层：有两项安全属性此前被执行在 Claude Code 根本触及不到的时刻。现在两者都在真正干活的地方生效。

| 类别 | 新增内容 | 详情 |
|------|---------|------|
| **引擎同步 —— 24 → 46 个 MCP 工具** | 这是一次三方合并，不是一次复制 —— 而这个区别就是全部故事 | vendor 进来的 `intel_engine/` 落后了约 30 个 commit。与其相信脑子里记着的一份本地补丁清单，不如把每个 vendor 文件都按**对照上游全部历史的 blob 同一性**做分类：114 个纯拷贝、**15 个刻意打过补丁的**、**6 个只属于 cti-expert 的**。一次直来直去的 `rsync` 会悄悄回退三处真实行为 —— `wp_common` 多出的那一层 `.env` 深度（cti-expert 比上游多嵌套一级，因此上游版本会把**每一个 API key 都解析成空**，而无密钥的一轮采集随后就会把*"没有兄弟域名"*当成关于对象的事实报出来）、`pivot_extract` 默认开启的反向 WHOIS，以及 `collect_core` 的单一来源化 —— 还会顺手删掉 `email_permute`，并把三个 RULE 4 的 shim 变回真实拷贝。CLI op 从 **48 → 69**，全部可解析 |
| **Engage —— 认证面** | 先找到登录入口；然后，只在明确确认之后，**进到里面去** | 探测是被动且免费的：定位登录表单、密码字段和注册页，并按**字段**而不是按标签分类 —— 出现确认密码就意味着*注册*，邀请码是一个**枢轴，而不是 OTP**。再往前一步，`engage_account` 用**合成身份**注册账号，读取公开页面藏起来的会员区（后台面板、充值/提现流程、推广层级、客服账号）。它拒绝非合成身份、拒绝直连出网，并在 CAPTCHA 前停下。注册账号是向外的、可被归因的、无法撤销的 —— **其闸门与向沙箱提交样本完全同级** |
| **案件循环** | 判断的单位是**聚类**而不是案件 —— 而且跑到收敛为止，不是跑到某个随意的深度 | `/clusters` 在做出任何判断*之前*先把一个案件切分成同一运营者的连通分量，并显示每个绑定指标**在全库范围内的普遍度** —— 于是一个在这里连起 3 个域名、却在全库出现在 400 个域名上的指标，一眼就是噪声而不是归属线索。`/frontier` 报告尚未解决的缺口：已经发现的免费下一批种子，加上**被暂缓、等待批准的计费线索**。`/loop` 反复执行采集 → 评估直到案件收敛；`/reopen` 在出现新种子时重开一个已收敛的案件；`/scope` 在开工时就推导出接案信息 —— 禁触类别、受害方归属、出网闸门 —— 而不是跑到一半再去假设 |
| **六个全新采集层** | 每一个都堵上了旧答案出错的一种具体方式 | **`/liveness`** —— 返回 200 的停放页/默认页/停用页/软 404 **不算**活着，而 404/403/机器人墙**不算**死了；只有 NXDOMAIN 才报死亡，而每一个仍被对方控制的名字都会被标上 `reuse_watch`。**`/pssl`** —— 被动 SSL 走的是历史上的**证书 → IP** 方向，用来还原躲在 CDN 后面的源站，并带一道基础率护栏，把共享的 CDN 证书（实测覆盖 915 个地址）挡在聚类之外。**`/paths`** —— 把 URL *路径*当作指标（`path_kit:`），针对那种轮换主机、靠目录来决定给受害者看哪套模板的运营者；通用路径不会产出任何东西。**`/serp`** —— 广告透明度中心指出**谁付了钱**（一个经过验证、真实扣费的广告主），并配有带证伪对照的 cloaking 探测。**`/docmeta`** —— PDF 的 `/Info` 与 XMP、含 GPS 的 EXIF、PNG 数据块。**`/victims`** —— 从受害者集合反推**入侵向量** |
| **RULE 1 现在在写入那一刻生效** | 防泄露关卡此前执行在一个代理 harness 很少走到的时刻 | `leakcheck.sh` 只作为 *git* 的 pre-commit hook 运行。Claude Code 持续写文件、却很少提交，因此一条泄露出去的指标可能整场会话都躺在工作区里 —— 而 `git commit --no-verify` 干脆直接跳过这道关卡。[`hooks/leakguard.py`](hooks/leakguard.py) 把检查挪到了 **`Write`/`Edit` 上的 PreToolUse**，那里根本不存在这个开关。它**没有重新实现那些匹配规则** —— 而是调用 `leakcheck.sh`，因为第二份拷贝一定会漂移，而漂移过的护栏只会报"干净"。作用范围是刻意收窄的：只在 cti-expert 的检出目录内、且 git 不忽略的路径上才拒绝，所以把案件数据写进 `intel_engine/cases/` —— 那本来就是正确做法 —— 永远不会被拦 |
| **向外动作的闸门挪到了 vendor 代码之上** | 一道只隔着"一次糟糕合并"的闸门，不算闸门 | `submit()` 在缺少 `confirm=True` 时会拒绝；Engage 的工具会拒绝非合成身份。这些闸门都是真的 —— 而它们住在 `intel_engine/` 里，也就是 **vendor** 的那部分。重新同步它是一次跨约 150 个文件的三方合并，其中一处刻意的本地行为会被*悄无声息地*回退；就在本次发布里，就有三处这样的回退是靠人工抓出来的。[`hooks/actionguard.py`](hooks/actionguard.py) 位于工具之上、在 cti-expert 自己的代码树里，并按工具**名称**触发。它返回**询问**并附上风险简报，绝不硬性拦截 —— 一道你必须关掉才能干活的护栏，就是一道终将被关掉的护栏。双模式工具按**参数**而不是按工具设闸：常规采集全程静默，只有 `--submit` 才会询问 |
| **MCP 列表过期这个故障终于有了名字** | 一场会话正驱动着四周前的工具面，而任何地方都没有报错 | Claude Code 在 MCP server **连接时**解析它的工具列表，并在整场会话里沿用。我们发现有一场会话握着 **17** 个工具，而磁盘上的引擎提供着 **46** 个 —— 并且没有任何提示；模型只是从头到尾没看见那些新工具，然后绕开它们的缺席去干活。[`hooks/sessionguard.py`](hooks/sessionguard.py) 在 SessionStart 时报告已解析出的 backend 层级，并在 `@tool` 数量**相对上一场会话发生变化**时发出提醒 —— 而那正是缓存下来的注册信息变旧的时刻 |
| **可以作为 Claude Code 插件安装** | 技能 + 命令 + MCP + hook 打成**一个**整体 | `register.sh` 为技能、命令和 MCP server 建立符号链接 —— 但它装不了 **hook**，而上面那两道护栏恰恰住在那里。[`.claude-plugin/plugin.json`](.claude-plugin/plugin.json) 把四者打包在一起：`/plugin marketplace add <clone>`，然后 `/plugin install cti-expert`。hook 路径采用带 `${CLAUDE_PLUGIN_ROOT}` 的 exec 形式，因此没有任何东西被写死到某一台机器上，也没有任何路径会被 shell 解析。两个 PreToolUse hook 都**向开放方向失败** —— 一个 hook 的 bug 绝不能把你的仓库搞瘫；`audit.sh` 与 git 的 pre-commit hook 仍然是兜底 |
| **OPSEC 关卡是被满足的，不是被放宽的** | 上游长出了一条提交样本的通路，所以这项测试必须被诚实地满足 | ANY.RUN 的 API 大半是一套*提交*用的 API，而上游引擎为它加了一条带闸门的通路 —— 这按设计就会让 [`tests/test_no_sample_submission.py`](tests/test_no_sample_submission.py) 失败。修法不是削弱断言：`REQUIRES_ANALYST_CONFIRMATION` 标记被放在 `submit()` 函数本身上，四个属于提交生命周期的 endpoint 被**逐一列出**（一个未经审阅的新 key 仍然会让测试变红），并且测试现在同时要求这个标记**以及它所声称的那次拒绝** —— 于是标记无法退化成一句咒语式的魔法字符串。已通过逐项植入故障验证：拿掉标记 → 红；拿掉拒绝逻辑 → 红；恢复 → 绿 |
| **真正会把仓库搞坏的，正是那份重新同步流程** | 写下来却会*悄悄*失败的指引，比没有指引更糟 | [STRUCTURE.md](STRUCTURE.md) 曾告诉下一个人"复制进 `intel_engine/`，然后把 5 个 shim 重新贴回去"。这是错的，而且它的失败没有任何报错：采集器照样在跑，只是什么都找不到了。现在它记录的是站得住的流程 —— 按 **blob 同一性**分类、以距离最小的基线做三方合并、检查旧基线会造出的重复 `@tool` 块 —— 外加 `zsh` 的分词陷阱：一份没加引号的 `rsync` 排除列表会变成**什么都不排除**。vendor 引擎自带的 **17 道关卡**现在也随包提供，并与 cti-expert 自己的 6 道一起运行；`audit.sh` 还新增了一项检查：`hooks.json` 注册的每条路径都必须仍然可解析，因为一个被改名的脚本会在沉默中让它的 hook 失效 |

<details>
<summary><b>v2.7 新功能</b></summary>

## v2.7 新功能

> **这是深度流水线正式落地的版本。** v2.6 打磨的是采集端；v2.7 让 cti-expert 成为一套**双层系统** —— 广度采集器**加上**一条自带持久化知识库、完全自包含的情报流水线 —— 冷启动下一条命令即可触达，并由一道在每次 push 时用仓库自身规则检查仓库的关卡守着。

| 类别 | 新增内容 | 详情 |
|----------|-----------|---------|
| **一个技能，两个层次** | 深度流水线现已**内置** —— 无需另行搭建后端 | `intel_engine/` 完整内置了 **Collect → Correlate → Assess** 流水线：持久化**知识库**、带版本的案件、跨案关联、经校准的研判与渲染（WebPivot · IntelAnalysis · IntelGraph · IntelReport · BinaryPivot）。`/backend` 解析为 **SELF** —— 无需配置，无需托管。深度层依赖只需安装一次：`uv venv && uv pip install -r requirements.txt`。目录树从 **22 个顶层目录收敛到 14 个**，统一收束在单一 `SKILL.md` 之后。参见 [STRUCTURE.md](STRUCTURE.md) |
| **8 条已注册命令** | `/cti` 可**在任意项目中冷启动直接使用** | 以往每条命令都需要先加载技能。[`scripts/register.sh`](scripts/register.sh) 会把技能与 `commands/*.md` 软链接进 `~/.claude/`，并写入本机专属的 `.mcp.json`，因此 `/cti`、`/cti-recall`、`/cti-case`、`/cti-pivot`、`/cti-cluster`、`/cti-check`、`/cti-report` 与 `/cti-status` 立即可用。**现在只需记住一条命令 —— `/cti <目标>`** —— 它按目标类型（域名 · IP · 邮箱 · 用户名 · 电话 · 钱包 · 哈希 · APK）自动路由并跑通对应链路。其余命令仍为约定命令 |
| **`--deep` 是真正的并行** | 采集**与**研判**两端**都做子代理扇出 | `/cti --deep` 会为每个发现的前沿种子派生一个子代理 —— 先经回溯与误报控制剪枝，**并发上限 6，深度上限 2 跳**，`--passive` 向所有子代理传递 —— 随后统一收敛回同一个案件。本版新增：当收敛产生**2 个及以上聚类**时，*Assess* 阶段同样扇出，每个聚类一个代理（ACH、置信度、风险，均限定在该聚类内），而**跨聚类判断仍集中**在编排器手中。广度并行，综合归一 |
| **IntelX + ANY.RUN** | 泄露/暗网选择符检索与沙箱实测 C2 —— 证据**分级，而非合并** | `intelx_search` 覆盖粘贴站、窃取器日志、暗网与历史 WHOIS。关键在于命中会被**分级**：泄露库或窃取器日志中的出现属于**暴露面证据，明确不可用于聚类** —— 同一个 combolist 里的两个地址共享的是*受害者群体*，而不是同一个操作者。过于宽泛的选择符会在本地直接拒绝，以免一个泛泛的名字白白消耗一次查询额度。`anyrun_lookup` 回答的是携带该指标的样本究竟*做了什么* —— 加壳程序真正连往的端点 —— 且为**只读：本技能从不提交样本**，由 [`tests/test_no_sample_submission.py`](tests/test_no_sample_submission.py) 强制保障 |
| **证据归档此前一直静默失效** | 包装层丢弃了 **22 个参数**，其中包括 `--archive-missing` | 内置引擎此前处于半迁移状态 —— 模块化的 `wp_*` 层已就位，但实际运行的采集器仍是拆分前那份 2,274 行的单体，于是 harness 的 `--help` 探测把采集器不再声明的参数统统过滤掉了。**因此证据归档根本没有运行。** `collect_core` 现在零丢弃，支持面从 **19 提升到 42**。被丢弃的参数仍会有意地在工具结果中显示：静默丢弃正是这类缺陷赖以藏身的失效模式 |
| **无密钥的回答依然诚实** | 能力核算 —— 缺少密钥绝不会被当成结论 | `wp_capabilities` 会明确指出**每个缺失的密钥让你损失了哪一类证据**，因此无密钥运行下未发现同源站点时，报告写的是*"未查询"*，而不是*"不存在同源站点"*。同期上线：**Censys**（无密钥 CenQL 构造器、免费额度查询、月度额度守卫）、**资产发现**（JS 包、source map、SPA 路由、well-known 文件）、**仿冒域名狩猎**、**JARM** TLS 栈指纹，以及多引擎 `search_pivot`。所有拒绝名单、供应商registry与置换表都已从代码移出，变成分析师可自行调整的 `references/*.json` |
| **不再有死胡同** | 六种标识符虽被识别，却没有任何枢轴 | 蛛网地图能识别 `document`、`image`、`youtube_channel`、`coordinates`、`vin` 与 `ipv6` —— 然后就在那里悄然中断。现已接上：**文档** → exiftool + oletools 溯源作者 → 人物/邮箱/组织；**图片** → EXIF GPS → 坐标，反向图搜与人脸检索一律标为**低置信并挂起待旁证，绝不自动合并**；YouTube 频道 → 简介面板链接；**坐标与 VIN 仅做富化，刻意不产生新种子**，因此它们无法凭空造出错误归因；IPv6 → 反向/被动 DNS + ASN，与 IPv4 对齐。并由一条不变式测试守住：*每一种可分类的类型都必须至少有一个枢轴* |
| **仓库自我校验** | `audit.sh` + CI + 提交前泄露扫描 | [`scripts/audit.sh`](scripts/audit.sh) 就是那道关卡：每个 `DISPATCH` op 必须指向真实存在的脚本，五个共享采集器必须是一份正本加一个再导出 shim，`@tool` 数量必须与贡献规则一致，模块可字节编译，测试全绿。它在**每次 push 与 PR 时于 GitHub Actions 运行**，且只扫描 PR *新增*的行，因此精心挑选的示例值不会被反复误报。[`scripts/install-hooks.sh`](scripts/install-hooks.sh) 将标识符泄露扫描挂成 **pre-commit 钩子**。随附五套零依赖测试 —— 采集核心、指标分类、误报账本、不提交样本，以及邮箱候选噪声控制 |
| **每个采集回合都以表格开场** | 一眼看清产出，再看叙述 | 此前采集只在叙述文字和持久化导出文件中呈现结果，没有任何机制保证对话里出现按域名归纳的摘要。新的输出规则要求每个采集回合**先给出** markdown 表格 —— **解析情况 · 首要枢轴 · 风险 · 聚类 · 是否曾见** —— 让你一眼看到收获，而不必逐字去找 |
| **可移植、不绑定框架** | 技能中已不存在任何助手框架耦合 | 移除了强制的语音通知代码块，并把自定义目录从框架专属路径改为中立的 `~/.config/cti-expert/`（仓库/当前目录的 `.env` 仍然优先）。本版还包括：**赞助与支持方**板块 —— Rexxfield · Hudson Rock · ParanoidLab · ANY.RUN · ZETAlytics · IntelX —— 以及以 **SVG** 重建的工作流程图，其中包含一张全新的端到端工具与技能时序图 |

</details>

<details>
<summary><b>v2.6 新功能</b></summary>

## v2.6 新功能

| 类别 | 新增内容 | 详情 |
|----------|-----------|---------|
| **`/case` 无人值守运行** | 枢轴循环默认 **`autonomy=auto`**；新增的侦察命令自动触发 | 蛛网地图现在**无需批准提示即可扩展至闭合** —— 真正约束扩展范围的是置信度门控，而不是人工提示（精确匹配链接自动追踪，弱链接暂挂，去重与深度上限不变）。深度摘要仍会打印，因此整个运行依旧可审计。v2.6 的侦察命令**无需任何参数**即进入流水线：`/icp` 作用于每个域名/URL/组织目标，`/cn-corp` 作用于发现的任何公司名或 USCC，`/iban` 作用于任何支付细节，`/hash-id` 作用于每个哈希（先于 `/hash`）—— 其中三个由发现驱动的命令还会把产出**作为新种子回流进循环**。`/redact` 保持**按需启用**（`--redact`）：脱敏后的报告是更弱的成果物，生成它应当是一个刻意的决定。可用 `--checkpoint`、`--no-cn`、`--reach balanced\|focused`、`--depth N` 收窄范围 |
| **中国／华语圈侦察** | `/icp` + `/cn-corp` —— 西方注册机构触及不到的归因层 | **ICP 备案（工信部备案）**把域名映射到其注册的在华主体，而**备案序列号**可反向枢轴到同一备案下的每一个兄弟站点 —— 这是一条与共用 GA ID 同等强度的同一运营者链接。随后是注册链：**GSXT**（权威源数据）→ 天眼查／企查查／爱企查 → **信用中国**失信名单 → 最终受益人（UBO），并附 USCC 校验与吊销状态标记。新增 **Quake（360）**与 **ZoomEye** 作为独立的网络空间测绘索引，为 `/dork-sweep` 增加 **Baidu 层**（第 1–4 层几乎不收录中国境内内容），以及 **CJK 变体生成** —— 拼音、简↔繁与公司名词干 —— 作为 `/pivot-suggest` 的新维度。参见 [`techniques/china-recon.md`](techniques/china-recon.md) |
| **法币支付通道** | `/iban` —— 银行账号成为选择子，就像钱包早已是那样 | 多数受害者从不接触加密货币 —— 他们做的是银行转账。[`iban_analyze.py`](scripts/iban_analyze.py) 执行 **ISO 7064 mod-97** 校验（可在*不联系任何人*的前提下证明支付页上的"银行账号"是伪造的）、把 BBAN 拆解为银行／分行／账号，并标记**司法辖区不一致** —— 这正是受益人在境外的经典钱骡模式。通过校验的账号导出为 `financial/iban` 类 IOC；未通过的则记录为行为性发现。同时覆盖**越南／东南亚的非 IBAN 通道**：VietQR/NAPAS BIN、卡 BIN、电子钱包、BIC。参见 [`techniques/fiat-payment-osint.md`](techniques/fiat-payment-osint.md) |
| **可分享报告** | `/redact` —— 可逆的 PII 脱敏 | [`redact.py`](scripts/redact.py) 用**稳定的编号占位符**替换 PII（`[EMAIL_1]` 在整个案件中始终指向同一个地址），并写出一份**可逆的 JSON 映射**，因此报告可以流出组织之外，之后仍能还原为证据。支持 `.md`/`.json`/`.csv`；往返逐字节一致。基础设施默认*不*脱敏 —— 在 CTI 报告里，行为体的域名本身就是分析内容，而非附带的 PII |
| **分析严谨性** | 概率锚定的可能性表述 + 5W1H + ACH | 判断现在都附带**带概率区间的可能性表述**（*几乎不可能* → *几乎确定*），并与证据置信度并列呈现，因为单说一句"MODERATE"，写的人和读的人心里差着 30 个百分点。`/coverage` 增加 **5W1H 复核** —— 技术矩阵衡量的是投入，所以一个案件可以拿到 96% 却仍未回答任何**为什么**或**如何做到**。`/threat-model` 现在要求为归因提供 **ACH 矩阵**：按*不一致项*为竞争假设打分、点名次优假设，并写明哪些证据会改变排序。参见 [`handbook/analytic-standards.md`](handbook/analytic-standards.md) |
| **哈希定型** | `/hash-id` —— 在任何哈希查询之前 | 32 位十六进制既可能是 MD5 **也可能是 NTLM** —— 前者是文件哈希，后者是凭据材料，查错服务会返回一句自信的"未知样本"，读起来像是脱罪证据。它把文件哈希路由到 MalwareBazaar/VT，把凭据哈希路由到 `/breach-deep`，绝不送往公开的破解服务 |

</details>

<details>
<summary><b>v2.5 新功能</b></summary>

## v2.5 新功能

| 类别 | 新增内容 | 详情 |
|----------|-----------|---------|
| **递归枢轴** | `/case` 化身**蛛网地图** —— 扩展整张网络 | `/case` 现在运行一个递归 BFS 枢轴引擎（[`pivot_orchestrator.py`](scripts/pivot_orchestrator.py) + [`engine/pivot-orchestration.md`](engine/pivot-orchestration.md)）：每一个发现的标识符（邮箱／域名／IP／用户名／钱包／…）都成为新种子，关系图逐跳扩展**直到前沿耗尽**。带置信度门控（精确匹配链接自动追踪，弱链接／PII 链接暂挂）、防环安全（去重 + 深度上限），并**按深度设检查点**。默认：active · exhaustive · checkpoint-per-depth |
| **归档 IOC 收割** | `/webpivot --harvest` —— 站点曾经暴露过的每一个选择子 | [`wayback_harvest.py`](scripts/webpivot/wayback_harvest.py) 在域名的**整个 Wayback 历史**上运行完整提取器，合并**邮箱、电话、加密钱包、追踪／验证 ID、SaaS 运营者 ID 与社交账号**并附首见／末见时间 —— 找回一个网络后来清除掉的选择子。直接输出 case-schema 的 `indicators[]` 进入 IOC 包；对域名/URL 目标在 `/case` 中自动运行。`/webpivot` 现在还提取**电话号码**（`tel:` + 格式化形式）作为排序后的枢轴线索 |
| **归档访问** | 抓取 Claude Code 的 WebFetch 够不到的归档页面 | WebFetch 被 `web.archive.org` 阻止（抓取层的 robots.txt）。[`wayback_fetch.py`](scripts/webpivot/wayback_fetch.py) 绕过了它 —— CDX 查询 → 解析最近快照 → 拉取原始 `id_`，带重试／退避（`--near`、`--list`、`--url-only`、`--json`） |
| **Web 枢轴** | `/webpivot` —— 测绘页面背后的基础设施 | 从页面 DOM 提取 favicon **mmh3**、GA/GTM/AdSense ID、钱包与 SaaS 运营者令牌 → 排序后的枢轴；通过 `/rank-relations`（加权评分 + 噪声黑名单）、`/cert-pivot`、`/pivot-suggest`、`/crypto-balance`、`/email-hygiene`、`/sensitive-paths` 做同一运营者关联。对域名/URL 目标在 `/case` 中自动运行 |
| **默认无密钥** | 100% 免费 —— 无需密钥，无需注册 | crt.sh（证书透明度）+ 被动 DNS + 匿名 urlscan **始终运行**；零成本完成完整枢轴，无需任何配置 |
| **付费密钥自动检测** | 放入一个密钥 → 它自行升级 | `/webpivot` **自动检测**你设置的任何付费密钥（Shodan、Censys、FOFA、DNSLytics、SecurityTrails、urlscan-PRO、WhoisXML）并解锁其更高层级 —— 无需参数，无需重跑；缺失／失效的密钥降级为一条提示，绝不中断运行。用 `/apikeys` 管理密钥 |
| **攻击面** | `/appliance-scan` —— 边界／VPN 设备 → KEV 映射 | 以被动优先的方式指纹识别面向互联网的 Citrix/F5/Cisco/Ivanti/Forti/Palo Alto/Exchange 设备（Shodan InternetDB/Censys）→ 匹配出 **CISA KEV/CVE** 清单；为 `/vuln-check` + `/threat-model` 提供输入 |
| **身份织网** | `/saas-map` —— SaaS 租户 + IdP 暴露面 | DNS-TXT 租户令牌（Google/Atlassian/Zscaler/Salesforce/Workday…）、非微软 IdP 指纹（Okta/Auth0/OneLogin/Ping/Keycloak/ADFS）、无需认证的 API/GraphQL/OpenAPI 规范发现 |
| **凭据** | 只读存活验证 | 发现的密钥通过仅查询身份的端点（AWS STS、GitHub scopes、Slack `auth.test`、`…/v1/models`）确认为有效 —— 绝不调用写入型接口 —— 并凭账户／权限证据升级为 CRITICAL |
| **完整性** | 证据门控的分析 | 每一条论断都引用一个可解析的发现；采集到的不可信数据会被标记，绝不执行 |
| **侦察** | 原生 `asn` 命令 | Windows 上无需密钥的 IP/ASN/域名查询（ipwho.is + RDAP）；Linux/macOS/WSL 自动安装完整版 nitefood/asn |
| **系统工具** | Windows 上自动安装 `whois` + `dig` + `asn` | winget `Microsoft.Sysinternals.Whois` + `ISC.Bind`；此前需手动操作 |
| **可靠性** | Windows PowerShell 5.1 加固 | 修复 native-stderr 导致的脚本中止、`OSArchitecture` 探测崩溃，以及 maigret 改用 `uv tool --force`；在 WinPS 5.1 上可干净安装 |
| **打包** | CLI 工具自动加入 PATH | `~/.local/bin`（uv 工具 + `asn`）自动加入 PATH —— 当前会话**及**永久生效 |

</details>

<details>
<summary><b>v2.4 新功能</b></summary>

## v2.4 新功能

| 类别 | 新增内容 | 详情 |
|----------|-----------|---------|
| **平台** | 跨平台操作系统检测（Windows/macOS/Linux） | 按系统自动安装；DOCX 生成自愈（UTF-8 + 自动定位 pandoc） |
| **打包** | uv 优先的工具链 | `uv venv` / `uv pip` / `uv tool`；PEP 723 `uv run` 零配置脚本；pip/pipx/venv 作为回退 |
| **可移植性** | 跨代理支持 | 通过 `AGENTS.md` + 一份可直接复制的 `/cti-expert` Codex 提示词，可在 Claude Code **和** OpenAI Codex 中运行 |
| **CTI** | 信息窃取日志分析器（`/stealer-log`） | 家族识别、受害者与运营者画像、跨日志行为体关联、IOC 与原始数据提取 |
| **侦察** | 管理后台／敏感端点检测 | 子域前缀 + 路径 + CJK 分类器（`admin`、`adm`、`kef`、`ador`、`panel`…） |
| **采集** | 集成 agent-browser | 主要的交互式浏览器（[vercel-labs](https://github.com/vercel-labs/agent-browser)）：CDP、无障碍树快照、截图；与 Scrapling 互补，核心功能无需 API 密钥 |
| **可靠性** | 全新 VPS 安装加固 + CI | root/sudo + 前置依赖引导；在最小化 root Ubuntu 容器上做冒烟测试 + GitHub Actions |

<details>
<summary><b>v2.3 新功能</b></summary>

## v2.3 新功能

| 类别 | 新增内容 | 详情 |
|----------|-----------|---------|
| **WHOIS** | 面向所有 TLD 的通用 WHOIS | whoisdomain + CLI + Whoxy API；.vn、.th、.sg、.kr，27+ 个 ccTLD 服务器 |
| **WHOIS** | 反向与历史 WHOIS（免费） | Whoxy 反向 API、历史查询、ViewDNS |
| **网页采集** | Scrapling 自适应采集 | 三层：静态 → 反爬 → JS 渲染；无头浏览器自动开启 |
| **网页采集** | 默认自动开启无头浏览器 | 自动识别 JS 密集型站点并通过 DynamicFetcher 渲染 |
| **编排** | AgentFlow 并行富化 | 面向 3 个以上主体的 DAG 并行枢轴扩展 |
| **性能** | HTML 解析约 2ms | Scrapling 解析器取代缓慢的 HTTP 抓取 |
| **平台** | 最低 Python 3.10+ | Scrapling 与 AgentFlow 的要求 |

<details>
<summary><b>v2.2 新功能</b></summary>

## v2.2 新功能

| 类别 | 新增内容 | 详情 |
|----------|-----------|---------|
| **图像取证** | 人脸检索、反向图搜、篡改检测、AI 地理定位 | FaceCheck.id、TinEye、FotoForensics、Forensically、picarta.ai、GeoSpy、Pic2Map |
| **区块链** | 加密钱包追踪、交易图谱、诈骗识别 | Blockchair、Etherscan、WalletExplorer、OXT.me、Chainabuse、Breadcrumbs |
| **交通** | 航空器追踪（未过滤）、船舶 AIS、车辆 VIN 查询 | ADS-B Exchange、Flightradar24、Marine Traffic、VesselFinder、NICB VINCheck |
| **暗网** | Tor 检索、勒索软件监控、onion 服务发现 | Ahmia.fi、onionsearch、DarknetLive、ransomwatch |
| **社交媒体** | Reddit、Instagram、TikTok、Telegram 调查 | Osintgram、instaloader、toutatis、RedditMetis、TGStat、TelegramDB、Bellingcat TikTok Timestamp |
| **人员搜索** | 美国人员搜索引擎、免费反向查询 | TruePeopleSearch、FastPeopleSearch、IDCrawl、That's Them |
| **超级 Dork** | 11 套跨平台 Google dork 模板，覆盖 73 个独立域名 | 社交、Telegram 生态、开发平台、论坛、粘贴站、暗网、泄露库、商业、图像、即时通讯、招聘 |
| **IoT** | 摄像头目录、IoT 设备检索 | Insecam、Thingful |

<details>
<summary><b>v2.1 新功能</b></summary>

| 类别 | 新增命令 | 作用 |
|----------|-------------|--------------|
| **情报** | `/render threat-path`、`/render attack-surface` | 攻击路径流程 + 基础设施暴露面可视化 |
| **情报** | `/snapshots`、`/diff` | Wayback Machine 快照与版本差异对比 |
| **情报** | `/drift`、`/report ioc` | 时间维度风险追踪 + IOC 导出（STIX 2.1） |
| **UX** | `/onboard`、`/clarify`、`/quality` | 新手教程、发现解释、质量评分 |
| **UX** | `/blind-spots`、`/source-check` | 盲点分析 + 批量 URL 验证 |
| **UX** | `/workspace diff` | 比较两次已保存的调查会话 |
| **数据模型** | 来源可靠性 A-F | 在信任分之外补充来源级评级 |
| **数据模型** | 4 种新实体类型 | 设备、图像、加密地址、自定义 |
| **数据模型** | HIGH 冲突严重级 | 4 级严重度：CRITICAL/HIGH/NOTABLE/MINOR |

</details>

</details>

</details>

</details>

<br>

---

<br>

## 安装

> **推荐：** 使用 **Claude Code CLI** —— 它提供完整的终端工作流、持久会话与直接的技能调用。[点此下载](https://docs.anthropic.com/en/docs/claude-code/overview) 或运行 `npm install -g @anthropic-ai/claude-code`。

### 为什么推荐 Claude Code CLI？

整个 CTI Expert 工作流都是围绕 Claude Code CLI 优化的。CLI 为你提供：
- **持久会话** —— 调查通过 `/workspace save` 跨终端重启保留
- **完整工具访问** —— 文件写入、Python 脚本、DOCX 生成，全部原生运行
- **技能调用** —— 在终端直接输入 `/cti-expert`，无需浏览器
- **后台代理** —— AgentFlow 的并行富化在 CLI 下效果最佳

#### 🖥️ 在哪里运行 —— 本技能最适合 CLI

> [!IMPORTANT]
> CTI Expert 是**执行密集型**的：它运行 `uv`/Python、安装 OSINT 工具、写出 `.md`/`.html`/`.json`/`.csv` 报告与 IOC 包、访问大量外部站点，并保存案件工作区。关键在于**真实的本地 shell + 持久化文件 + 开放网络** —— **CLI 或本地桌面代理**能给你这些，而临时的**云端沙箱不能**。这一点对 **Claude** 与 **Codex** 同样适用。

| 环境 | 运行案件 | 原因 |
|---|---|---|
| **Claude Code CLI** · **Codex CLI** | ✅ **最佳** | 真实 shell、持久化、后台任务、开放网络 —— 正是本技能的设计前提 |
| **Claude Code 桌面版** · **Codex IDE 扩展** | ✅ 很好 | 同样的本地执行能力；**阅读**渲染后的报告、图表与示意图最为舒适 |
| **claude.ai/code（网页）** · **Codex 云端 / ChatGPT 网页** | ⚠️ 受限 | 推理与查询生成可用，但文件不会持久化到你的磁盘，出网也常受限制 |

> [!TIP]
> **在 CLI 中运行调查**（Claude Code 或 Codex）；若你更愿意在桌面／IDE 窗口里阅读，可在那里打开生成的 `.docx`／报告。网页／云端环境只用于分析推理，不要用于执行密集的侦察。

---

### 第一步 &mdash; 安装 Claude Code CLI

```bash
npm install -g @anthropic-ai/claude-code
```

> 需要 Node.js 18+。完整文档：[docs.anthropic.com/en/docs/claude-code/overview](https://docs.anthropic.com/en/docs/claude-code/overview)

---

### 第二步 &mdash; 克隆 + 一键安装脚本

安装脚本会处理一切：Python 依赖、系统工具（`whois`、`dig`、`asn`、`jq`、`exiftool`）、OSINT 工具（`maigret`、`sherlock`、`holehe`、`h8mail` 等），以及可选的无头浏览器与 Go 工具。它由 **[uv](https://docs.astral.sh/uv/)**（Astral 出品的超快 Rust 包管理器）驱动 —— 脚本先引导安装 uv，然后用 `uv venv` / `uv pip` / `uv tool` 完成所有 Python 安装，仅在 uv 无法安装时才回退到 `pip`/`pipx`/`venv`。Windows（PowerShell）用 `install.ps1`，macOS/Linux/Git Bash/WSL 用 `install.sh`。

<table>
<tr>
<th>平台</th>
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
<td><b>Windows（PowerShell —— 原生）</b></td>
<td>

```powershell
git clone https://github.com/7onez/cti-expert.git "$env:USERPROFILE\.claude\skills\cti-expert"
powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\.claude\skills\cti-expert\scripts\install.ps1"
```

</td>
</tr>
</table>

> **Windows 用户：** `install.ps1` 是一个**完整的原生安装脚本**（winget 系统工具 + Python venv + OSINT 工具）—— 不需要 Git Bash 或 WSL。它接受同样的 `-Headless`、`-Go`、`-All` 参数（例如 `install.ps1 -All`）。Git Bash / WSL 用户可以改用 `install.sh`。DOCX 生成器会自愈 UTF-8 输出并自动定位 pandoc，因此报告在 Windows 上无需额外环境配置即可构建。技能本身会在运行时检测操作系统，并用正确的包管理器（`winget` / `brew` / `apt`）安装任何缺失的工具 —— 参见 `scripts/platform-setup.md`。

---

### 安装选项

**macOS / Linux / Git Bash / WSL：**

```bash
bash scripts/install.sh               # 核心：Python 依赖 + 系统工具 + OSINT 工具
bash scripts/install.sh --headless    # + Scrapling 无头浏览器（约 200MB Chromium）
bash scripts/install.sh --go          # + Go 工具（subfinder、amass、gau、gitleaks、httpx）
bash scripts/install.sh --all         # + 以上全部
```

**Windows（PowerShell）：**

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install.ps1              # 核心
powershell -ExecutionPolicy Bypass -File scripts\install.ps1 -Headless    # + Scrapling 无头浏览器
powershell -ExecutionPolicy Bypass -File scripts\install.ps1 -Go          # + Go 工具
powershell -ExecutionPolicy Bypass -File scripts\install.ps1 -All         # + 以上全部
```

| 参数 | 安装内容 | 体积 |
|------|-----------------|------|
| *(无)* | Python 包、whois、dig、asn、jq、exiftool、maigret、sherlock、holehe、h8mail、theHarvester、waymore、xeuledoc、agentflow | 约 50 MB |
| `--headless` | Scrapling StealthyFetcher + DynamicFetcher + Chromium | +200 MB |
| `--go` | subfinder、amass、gau、gitleaks、httpx、trufflehog、phoneinfoga | +150 MB |
| `--all` | 全部 | 约 400 MB |

---

### 第三步 &mdash; 把命令注册到 Claude Code

`install.sh` 安装的是 OSINT **工具**。这一步只需做一次，它把**技能、8 条 `/cti*` 斜杠命令以及 MCP 工具**接入 Claude Code，使它们在任意项目的冷启动提示符下都能用 —— 它会把 `commands/*.md` 软链接进 `~/.claude/commands/`，并写出这台机器专属的 `.mcp.json`。该步骤是幂等的，`git pull` 之后重跑也安全。

```bash
# 注册技能 + 8 条命令 + 写出本机专属的 .mcp.json
bash ~/.claude/skills/cti-expert/scripts/register.sh

# 推荐：把内置深度流水线（intel_engine）的依赖安装一次
cd ~/.claude/skills/cti-expert && uv venv && uv pip install -r requirements.txt
```

> **Windows（原生 PowerShell）：** 请从 **Git Bash 或 WSL** 运行 `register.sh` —— 它使用了软链接。之后，在所有平台上都要**重启 Claude Code**，让技能与命令在启动时加载。

---

### 验证安装

```bash
claude              # 打开 Claude Code CLI，然后输入：
/cti-status         # 健康检查 —— 后端层级、MCP 工具、API 额度余额
/cti example.com    # ……或者直接开始调查
```

> `/cti-status` 一次性确认后端、MCP 工具与 API 额度余额。如果 `/cti*` 命令没有被识别，请重跑**第三步**（`register.sh`）并重启 Claude Code。你也可以输入 `/cti-expert` 直接加载技能，然后用自然语言描述你的目标。

---

### 在 ChatGPT / Codex 中使用（跨代理）

CTI Expert 是可移植的：分析逻辑是纯 Markdown，脚本是自带操作系统检测的 Python/shell，因此它不仅能在 Claude Code 中运行，也能在 **OpenAI Codex**（以及其他支持 [`AGENTS.md`](AGENTS.md) 的代理）中运行。

```bash
# 1. 把技能克隆到任意位置
git clone https://github.com/7onez/cti-expert.git

# 2a. 仓库内：在克隆目录中打开 Codex —— 它会自动加载 AGENTS.md。然后让它遵循 SKILL.md。
# 2b. 斜杠命令：复制内置的 Codex 提示词，使 /cti-expert 在 Codex CLI/IDE 中可用
cp cti-expert/codex/cti-expert.md ~/.codex/prompts/cti-expert.md   # Windows：复制到 %USERPROFILE%\.codex\prompts\
```

- **[`AGENTS.md`](AGENTS.md)** 是跨代理的运行时契约（操作系统检测、uv、路径）。Codex 会从仓库根目录自动拼接它；你也可以从 `~/.codex/AGENTS.md` 引用它。
- **`codex/cti-expert.md`** 是一份可直接复制的自定义提示词 → 让 Codex 拥有 `/cti-expert <target>` 斜杠命令。
- **纯 ChatGPT（无代码执行）：** 推理、查询生成与报告起草都能工作（把 `SKILL.md`/`AGENTS.md` 作为指令或 Custom-GPT 知识加载）；只有本地步骤（DOCX 构建、CLI 工具运行）需要 Codex 或 Claude Code 这类具备代码能力的运行环境。

> 路径都相对技能目录（包含 `SKILL.md` 的那个文件夹）解析，因此没有任何地方假定 Claude 专属的 `~/.claude/skills/` 位置。

---

### 备选方案 &mdash; Claude Code 桌面版（macOS / Windows）

> 下载：[claude.ai/download](https://claude.ai/download) &mdash; 支持 **macOS** 与 **Windows**

**分步操作（无需终端）：**

1. **安装 Claude Code 桌面版** &mdash; 从 [claude.ai/download](https://claude.ai/download) 下载并安装应用
2. **下载 CTI Expert** &mdash; 打开 [GitHub 仓库](https://github.com/7onez/cti-expert)，点击绿色的 **"Code"** 按钮，然后选择 **"Download ZIP"**
3. **解压到你的 skills 文件夹** &mdash; 解压下载的文件，把解压出的文件夹移动到 skills 目录并重命名为 `cti-expert`：

   | 平台 | 如何定位 |
   |----------|----------------|
   | **macOS** | 打开 **访达** &rarr; 按 **Shift + Cmd + G** &rarr; 输入 `~/.claude/skills/` &rarr; 按 **前往** &rarr; 把文件夹移到这里 |
   | **Windows** | 打开 **文件资源管理器** &rarr; 在地址栏输入 `%USERPROFILE%\.claude\skills\` &rarr; 按 **回车** &rarr; 把文件夹移到这里 |

   > **注意：** 如果 `skills` 文件夹不存在，先在 `.claude` 文件夹内创建它。

4. **运行安装脚本 + 注册** &mdash; 打开 Claude Code 桌面版终端并运行：

   ```bash
   bash ~/.claude/skills/cti-expert/scripts/install.sh      # OSINT 工具
   bash ~/.claude/skills/cti-expert/scripts/register.sh     # 技能 + 8 条命令 + MCP
   ```

   或在 Windows PowerShell 上（仅 Python 依赖；`register.sh` 请从 Git Bash/WSL 运行）：

   ```powershell
   pip3 install -r "$env:USERPROFILE\.claude\skills\cti-expert\scripts\requirements.txt"
   ```

5. **重启 Claude Code 桌面版** &mdash; 关闭并重新打开应用
6. **验证** &mdash; 在对话中输入 `/cti-status`，确认技能与命令均已加载（或输入 `/cti-expert` 直接加载技能）

<details>
<summary><b>系统要求</b></summary>
<br>

| 要求 | 版本 | 用途 |
|-------------|---------|---------|
| [Claude Code CLI](https://docs.anthropic.com/en/docs/claude-code/overview) | 最新版 | **推荐**的终端运行时 |
| [Claude Code 桌面版](https://claude.ai/download) | 最新版 | 图形界面运行时（macOS/Windows） |
| Node.js | 18+ | Claude Code CLI 所需 |
| [uv](https://docs.astral.sh/uv/) | 最新版 | **推荐** —— 由安装脚本自动引导；管理 Python、venv、包与 CLI 工具 |
| Python | 3.10+ | DOCX 报告生成、Scrapling、AgentFlow（uv 可以帮你装好） |
| pip 包 | 见 `requirements.txt` | 图表、示意图、样式 |
| git | 任意版本 | 克隆仓库 |

</details>

<br>

---

<br>

## 快速入门

### 命令是怎么工作的 —— 请先读这段

**只需要记住一条命令：`/cti <目标>`。** 它会看你给了什么 —— 域名、IP、邮箱、用户名、电话、钱包、哈希或 APK —— 并自动运行相应的调查链。通常这就够了。

它之下还有 **8 条已注册命令**，Claude Code 在任意项目的冷启动提示符下都能识别（无需先加载技能）：

| 命令 | 作用 |
|---------|--------------|
| **`/cti <target>`** | **入口** —— 按目标类型路由并运行整条链 |
| `/cti-recall <seed>` | *"这个我以前见过吗？"* —— 比对每一个既往案件。**务必先跑这条。** |
| `/cti-case <ID> <seeds>` | 完整的确定性流水线：采集 → 入库 → 聚类 → 研判 |
| `/cti-pivot <url\|ip>` | 从单个目标采集枢轴要素 |
| `/cti-cluster <domain>` | 扩展并关联一个已有案件 |
| `/cti-check <indicator>` | 误报控制 —— 是真实的同一运营者链接，还是共享噪声？ |
| `/cti-report <ID>` | 渲染关系图 + 一份精美的 PDF/DOCX |
| `/cti-status` | 健康检查 —— 后端、MCP 工具、API 额度余额 |

本页上**其余每一条**命令（`/case`、`/webpivot`、`/report`、`/sweep`…）都是**约定命令**：技能加载之后可用的简写 —— 通过 `/cti`，或直接输入 `/cti-expert` 打开技能。在冷启动提示符下，请使用上面的已注册命令，或者干脆用自然语言描述你的目标 —— 效果完全相同。

### 1 &mdash; 调查任何东西

```bash
/cti example.com          # 域名  → 完整流水线
/cti user@domain.com      # 邮箱  → 泄露 + 基础设施 + 跨平台
/cti @username            # 账号  → 3000+ 平台枚举，然后枢轴
/cti 185.1.1.1            # IP    → ASN、同居主机、开放端口、被动 DNS
/cti ./trader.apk         # 文件  → 静态 IOC，与 Web 基础设施聚类
```

> `/cti` 会为目标挑选合适的技术，然后把枢轴图**扩展至闭合 —— 无需批准提示**。加 `--deep` 触发并行子代理扇出，加 `--quick` 只跑单轮，加 `--passive` 应对敌意目标（不做任何直接接触）。默认输出：Markdown + 交互式 HTML + JSON + CSV + IOC 包。

### 2 &mdash; 端到端跑完一个案件

```bash
/cti-recall example.com               # 永远第一步——这个种子我们见过吗？
/cti-case CASE-0001 example.com       # 对一个或多个种子运行完整流水线
/cti-cluster CASE-0001                # 扩展：同伙、共享指标、TLS 重叠
/cti-report CASE-0001 --pdf           # 交付：关系图 + PDF/DOCX
```

### 3 &mdash; 引导式流程

> 下面这些命令是**约定命令** —— 技能加载之后再输入。

```bash
/flow person           # 人员调查流程
/flow domain           # 域名侦察流程
/flow image            # 图像验证流程
```

### 4 &mdash; 定向侦察

```bash
/sweep @username                    # 对账号做多向量侦察
/query example.com                  # 12-15 条高级搜索查询
/username johndoe                   # 平台枚举（3000+）
/email-deep user@domain.com         # 深度邮箱调查
/subdomain example.com              # 证书透明度 + 暴力枚举
/github-osint github.com/org/repo   # GitHub 资料、仓库、代码、提交、分叉
/threat-check 185.1.1.1             # IP/域名/URL 威胁情报
/scam-check suspicious-site.xyz     # 钓鱼／诈骗域名核查
/breach-deep user@domain.com        # 多源泄露查询
```

### 5 &mdash; 分析与研判

```bash
/exposure domain.com                # 综合风险评分（0-100）
/threat-model                       # 基于发现构建威胁模型
/validate                           # 验证全部发现
/coverage                           # 检查调查完整度
```

### 6 &mdash; 报告

```bash
/report                             # 技术 INTSUM 报告
/report brief                       # 高管摘要
/brief                              # 通俗语言摘要
/workspace save                     # 保存案件工作区状态（稍后恢复）
```

<br>

---

<br>

## 最佳实践

让调查保持快速、低成本且正确的一些习惯 —— 大部分由技能自身强制执行，
但了解它们会有帮助。

**跑一个案件**
- **从 `/cti <目标>` 开始。** 它是唯一入口，会按目标类型路由
  （域名、IP、邮箱、用户名、电话、钱包、哈希、APK）。不要手动调用采集器。
- **先回忆，再采集。** `/cti-recall <seed>`（或 `/cti` 的第 0 步）是整个工具箱里
  最便宜的一次调用 —— 它告诉你某个种子是否已经被归因，从而省下额度，也避免
  与既往研判自相矛盾。
- **对任何敌意目标用 `--passive`。** 出网门控会拒绝直接抓取敌意基础设施；被动模式基于
  Wayback/urlscan 的存档工作，你的 IP 永远不会接触它。
- **聚类前先筛查指标。** `/cti-check <indicator>`（误报控制）——
  错误的合并会指认无辜者，错误的拆分会丢掉整个案件。
- **`--deep` 在 3 个以上活跃种子时才划算**（并行子代理扇出）；单个种子则直接
  内联运行。
- **行为异常时用 `/cti-status`** —— 后端层级、MCP 工具与 API 余额，一次
  全部看清。

**成本与密钥**
- **两本独立的账：** 模型推理（`/cost`）与第三方 API 额度（`api_usage`）——
  永远不是同一个数字。
- **默认无密钥；`/apikeys` 用于升级。** 密钥能丰富枢轴（Shodan/Censys/FOFA/…），但
  没有任何功能强制要求它们。

**如果你在开发这个技能**
- 每个克隆运行一次 `bash scripts/install-hooks.sh` —— 把泄露检查挂成 pre-commit 钩子。
- 推送前运行 `bash scripts/audit.sh` —— 漂移／泄露／测试门禁（每个 PR 的 CI 也会跑）。
- 分类逻辑的改动必须**连同**它的测试一起提交（RULE 5）。

<br>

---

<br>

## 功能特性

<table>
<tr>
<td width="33%" valign="top">

### 身份与人员

- 人员查询 —— 50+ 数据点
- 电话 —— 运营商、声誉、关联关系
- 邮箱 —— 账号、泄露、基础设施
- 用户名 —— 3000+ 平台枚举
- GitHub 开发者足迹 —— 资料、组织、仓库、提交、分叉

</td>
<td width="33%" valign="top">

### 域名与基础设施

- 通过 CT 日志做子域枚举
- CMS、CDN、分析工具指纹识别
- DNS 取证与 WHOIS 深度／反向查询
- 流量分析与受众画像
- ICP 备案 &rarr; 在华主体 + 兄弟域名枢轴
- IBAN／银行账号校验与归因

</td>
<td width="33%" valign="top">

### 分析与验证

- 人脸检索（FaceCheck.id）与反向图搜（TinEye）
- 图像取证（FotoForensics、Forensically）
- AI 照片地理定位（picarta.ai、GeoSpy）
- 文档／邮件元数据取证
- Google Docs 身份提取
- 100+ 粘贴站与泄露库
- 带概率区间的可能性判断、5W1H 覆盖度、ACH

</td>
</tr>
<tr>
<td width="33%" valign="top">

### WiFi、地理与交通

- 通过 Wigle.net 查询 SSID/BSSID
- W3W、Plus Codes、MGRS、街景
- 航空器追踪（ADS-B Exchange、Flightradar24）
- 船舶追踪（Marine Traffic、VesselFinder）
- 车辆 VIN 查询与车牌识别

</td>
<td width="33%" valign="top">

### 安全审计

- 云审计（AWS/GCP/Azure）
- OWASP Top 10 源码审计
- CVE 与供应链漏洞检查
- LLM／代理／MCP 提示注入审计

</td>
<td width="33%" valign="top">

### 报告与导出

- INTSUM、高管简报、通俗语言版
- 带图表、示意图、时间线的 DOCX
- 保存／加载案件工作区
- 法务、记者、HR、威胁分析师格式
- 面向对外分享的可逆 PII 脱敏

</td>
</tr>
</table>

<br>

---

<br>

## AEAD 案件生命周期

每一次调查都经历四个自动化阶段：

```
                         ╭──────────────────────────────────────╮
                         │          AEAD 案件生命周期           │
                         ╰──────────────────────────────────────╯

   ┌─── ACQUIRE 获取 ───────────────────────────────────────────────────┐
   │  通过 /sweep、/query、/username、/phone 等采集原始数据             │
   │  数据库检索、枚举、采集缺口记录                                    │
   └────────────────────────────────┬───────────────────────────────────┘
                                    ▼
   ┌─── ENRICH 富化 ────────────────────────────────────────────────────┐
   │  通过 /branch、/crossref、/link-subjects、/signatures 扩展线索     │
   │  共享标识符检测、关系测绘                                          │
   └────────────────────────────────┬───────────────────────────────────┘
                                    ▼
   ┌─── ASSESS 研判 ────────────────────────────────────────────────────┐
   │  通过 /exposure、/threat-model、/validate、/coverage 评分与验证    │
   │  风险评分、完整性检查、证据链                                      │
   └────────────────────────────────┬───────────────────────────────────┘
                                    ▼
   ┌─── DELIVER 交付 ───────────────────────────────────────────────────┐
   │  通过 /report、/brief、/render、/workspace save 打包输出           │
   │  自动保存 .md、.html、.json、.csv + IOC 集合                       │
   └────────────────────────────────────────────────────────────────────┘
```

> 任何时候运行 `/progress` 都能看到当前阶段与待办任务。

<br>

### 工作流程图

**端到端工具与技能流** —— 用一张时序图呈现整个系统：目标从 `/cti` 进入，穿过第 1 层的 49 项技术与 24 个工具的 MCP 接口，流经 WebPivot / BinaryPivot / 知识库 / IntelAnalysis，最终以渲染好的关系图与 PDF 交付：

<div align="center">
<img src="assets/workflow-skills.svg" alt="cti-expert 端到端工具与技能流 —— 跨双层时序图" width="900">
</div>

**完整 `/cti` · `/case` 流水线（AEAD）** —— 递归蛛网扩展，以及 `/webpivot`、`/icp`、`/iban` 与关联分析各自的位置：

<div align="center">
<img src="assets/workflow-case.svg" alt="cti-expert /case 流水线（AEAD）" width="820">
</div>

**`/webpivot` + 关联 + 付费 API 密钥流程：**

<div align="center">
<img src="assets/workflow-apikeys.svg" alt="cti-expert /webpivot + 关联 + API 密钥工作流" width="820">
</div>

<sub>来源：<a href="workflow-skills.puml"><code>workflow-skills.puml</code></a> · <a href="workflow-case.puml"><code>workflow-case.puml</code></a> · <a href="workflow-apikeys.puml"><code>workflow-apikeys.puml</code></a> —— 由 <a href="https://plantuml.com">PlantUML</a> 渲染为 <b>SVG</b> 存放于 <a href="assets/"><code>assets/</code></a>（矢量图，任意缩放都清晰，且无需 Git-LFS）。修改源文件后重新渲染：</sub>

```bash
plantuml -tsvg -o assets workflow-case.puml workflow-apikeys.puml workflow-skills.puml
# 需要用于幻灯片的位图时追加 -tpng —— 注意 assets/*.png 由 Git-LFS 管理
```

<sub>参见 <a href="handbook/api-keys.md">API 密钥与 webpivot 指南</a>。</sub>

<br>

---

<br>

## 命令参考

> 下面的表格都是**约定命令** —— 技能加载之后（通过 `/cti` 或 `/cti-expert`）可用的完整技术词汇表。那 8 条已注册的入口命令（`/cti`、`/cti-recall`、`/cti-case`…）在上面的 [快速入门](#快速入门) 中。权威参考请见 **[SKILL.md](SKILL.md)**。

<details>
<summary><b>Acquire 采集</b> —— 数据收集类命令</summary>
<br>

| 命令 | 用途 |
|---------|---------|
| `/case [target]` | 完整流水线 —— 所有适用的技术 |
| `/sweep [target]` | 多向量侦察（个人／域名／组织／用户名／邮箱／IP） |
| `/query [subject]` | 12-15 条高级搜索运算符查询 |
| `/username [handle]` | 3000+ 平台枚举 |
| `/phone [number]` | 运营商查询、声誉、关联关系 |
| `/email-deep [email]` | 账号、泄露、基础设施 |
| `/subdomain [domain]` | CT 日志 + 被动枚举 |
| `/github-osint [target]` | GitHub 用户／组织／仓库资料、代码、提交、分叉 |
| `/threat-check [target]` | IP／域名／URL／哈希威胁情报 |
| `/breach-deep [email]` | 多源泄露查询 |

</details>

<details>
<summary><b>Enrich 富化</b> —— 横向扩展类命令</summary>
<br>

| 命令 | 用途 |
|---------|---------|
| `/branch [data]` | 横向扩展（邮箱&rarr;用户名、用户名&rarr;邮箱等） |
| `/crossref` | 跨主体的共享标识符检测 |
| `/link-subjects [A] [B]` | 定义主体之间的关联 |
| `/show-connections` | 展示已记录的关联 |
| `/graph` | 完整的 ASCII 主体关系图 |

</details>

<details>
<summary><b>Assess 研判</b> —— 评分与验证类命令</summary>
<br>

| 命令 | 用途 |
|---------|---------|
| `/exposure [target]` | 综合风险评分（0-100） |
| `/threat-model` | 基于发现构建威胁模型 |
| `/validate` | 验证发现的证据链 |
| `/coverage` | 检查调查完整度 |

</details>

<details>
<summary><b>Deliver 交付</b> —— 报告生成类命令</summary>
<br>

| 命令 | 用途 |
|---------|---------|
| `/report` | 技术 INTSUM 报告 |
| `/report brief` | 高管摘要 |
| `/brief` | 通俗语言摘要 |
| `/workspace save` | 持久化案件工作区状态（稍后恢复） |

</details>

<details>
<summary><b>Web 基础设施枢轴与关联</b> —— 基础设施与同一运营者分析</summary>
<br>

| 命令 | 用途 |
|---------|---------|
| `/webpivot [url]` | 提取 favicon／追踪码／钱包／SaaS 运营者要素 &rarr; 排序后的枢轴查询（Shodan/FOFA/urlscan）。参数：`--rank`、`--cert`、`--graph`、`--history`、`--whois` |
| `/rank-relations` | 跨页面为同一运营者关系评分并排序（加权信号、噪声过滤、聚类） |
| `/cert-pivot [domain]` | 找出使用同一 TLS 证书的其他主机 + SAN 兄弟域名（无需密钥；有密钥则用 Shodan/Censys） |
| `/pivot-suggest` | 从发现中排序"接下来该枢轴什么"（leet／变体／时间／域名簇，**CJK 拼音 + 繁体 + 公司名词干**） |
| `/crypto-balance [addr]` | 钱包的链上余额 + 全生命周期流水，按现价计值 |
| `/iban [value]` | 校验并拆解一个银行账号（mod-97、BBAN 拆分、银行代码、钱骡信号） |
| `/email-hygiene [email]` | 为邮箱域名打 0-100 分 + A-F 等级（一次性／MX／免费／角色地址） |
| `/sensitive-paths [list]` | 对 Wayback／URL 列表分类，找出暴露路径（.git/.env/备份/配置） |

</details>

<details>
<summary><b>中国／华语圈侦察</b> —— ICP 备案、中国注册机构、CN 索引</summary>
<br>

| 命令 | 用途 |
|---------|---------|
| `/icp [domain\|serial]` | ICP 备案 &rarr; 注册的在华主体 + 备案号；用**备案序列号**反查同一备案下的兄弟域名 |
| `/cn-corp [name\|USCC]` | GSXT &rarr; 天眼查／企查查／爱企查 &rarr; 信用中国 链条：高管、股东、子公司、UBO、吊销状态标记 |
| `/dork-sweep [t] --baidu` | Baidu 层 —— 第 1&ndash;4 层（Google/Bing/DDG）几乎不收录中国境内托管的内容 |
| `/pivot-suggest --cjk` | 拼音、简&harr;繁与公司名词干变体 |

需要中国大陆出网的注册机构（天眼查／企查查／爱企查）会被记为**采集缺口**，绝不作为阻断项。

</details>

<details>
<summary><b>报告卫生</b></summary>
<br>

| 命令 | 用途 |
|---------|---------|
| `/redact [file]` | 可分享的报告变体 —— 稳定的 `[EMAIL_1]` 占位符 + 可逆 JSON 映射（`.md`/`.json`/`.csv`）。按需启用；默认导出集保持未脱敏 |
| `/hash-id [hash]` | 在查询前先识别哈希的算法 —— 文件哈希还是凭据材料 |

</details>

<details>
<summary><b>深度流水线与知识库</b> —— 内置（vendored <code>intel_engine</code>）</summary>
<br>

内置于技能的 `intel_engine/` 之下（`intel_engine/harness/`、`tools/`、`knowledge/`、`cases/`）。`/backend` 解析为 SELF —— 无需配置。深度层依赖只需安装一次：`uv venv && uv pip install -r requirements.txt`。参见 [connectors/intel-backend.md](connectors/intel-backend.md)。

| 命令 | 用途 |
|---------|---------|
| `/backend` | 检测后端并报告层级 —— 第 1 层（typed MCP）→ 第 2 层（CLI）→ 第 3 层（无状态）。`/backend check` 展示完整的解析轨迹 |
| `/kb [query]` | 查询共享知识库 —— 统计、实体／簇／共享指标查找、已确认运营者账本 |
| `/recall [seed]` | *"这个我以前见过吗？"* —— 在采集前把种子比对每一个既往案件 |
| `/risk [case]` | 为案件中的主机评分：新注册域／防弹托管／资金链路等红旗 |
| `/reverse-whois [email\|name]` | 对注册人做反向 WHOIS → 只保留高价值枢轴（过滤隐私代理与批量注册） |
| `/cert-overlap [d1 d2 …]` | 跨域名的、知识库感知的 TLS/SAN 同一运营者判定 |
| `/reference [check\|add\|list]` | 误报控制账本 —— BENIGN 与 SIGNAL 指纹 |
| `/harness [open\|continue\|status]` | 全案件编排 —— 持久、带版本、跨案件直至收敛 |
| `/graph --render` | IntelGraph 出版级案件图渲染 → PNG/SVG |
| `/report pdf` | IntelReport 用 pandoc 渲染研判报告 → 精美 PDF/DOCX |
| `/binary [file\|url]` | 从诈骗 APK/exe 提取静态 IOC（签名证书、包名、C2 主机、钱包）→ 与 Web 基础设施聚类 |

所有后端命令在第 2 层通过 `scripts/backend/intel.py` 调度（第 1 层则走 typed MCP 工具）；不可用时 → 降级为一条提示。

</details>

<br>

---

<br>

## 技能层级

输出的信息密度与自动化程度会随你的熟练度自动调整。**随时切换层级 —— 输出会立即改变：** `/novice` 进入新手层级，`/novice off` 给你专家层级，中间的熟练者是默认层级。

<table>
<tr>
<th width="33%">新手</th>
<th width="33%">熟练者</th>
<th width="33%">专家</th>
</tr>
<tr>
<td valign="top">

低术语模式、分步引导，以及尽职调查、背景核查、安全审查的预置模板。

**切换：** `/novice`

**试试：** `/flow person`、`/flow domain`、`/template list`

</td>
<td valign="top">

高级搜索运算符、手动枢轴扩展、自定义威胁建模、带讲解的引导式流程。

**切换：** 默认层级 —— 无需命令

**试试：** `/query [target]`、`/branch [data]`、`/crossref`、`/threat-model`

</td>
<td valign="top">

原始技术直调、自定义证据权重、CONTESTED 发现的裁定、直接数据库查询。

**切换：** `/novice off`

**试试：** `/username [handle]`、`/email-deep [email]`、`/secrets [target]`、`/threat-check [target]`

</td>
</tr>
</table>

<br>

---

<br>

## 技术目录

<details>
<summary><b>49 种技术</b> —— 点击展开完整目录</summary>
<br>

| 技术 | 覆盖范围 | 是否需要 API 密钥？ |
|-----------|----------|-------------------|
| `fx-metadata-parsing.md` | EXIF、邮件头、文档取证 | 否 |
| `fx-image-verification.md` | 图像真实性、来源溯源、反向检索 | 否 |
| `fx-breach-discovery.md` | 泄露库 + 粘贴站枚举 | 可选（HIBP 批量、DeHashed 付费） |
| `fx-http-fingerprint.md` | HTTP 签名分析、服务器指纹识别 | 否 |
| `fx-leak-monitoring.md` | 泄露与失窃数据监控自动化 | 混合（IntelligenceX/Shodan 付费） |
| `fx-dns-cert-history.md` | 历史 DNS + SSL/TLS 证书时间线 | 否 |
| `fx-document-forensics.md` | PDF/Office 作者、生成链、隐藏内容 | 否 |
| `fx-network-mapping.md` | 网络拓扑、实体图构建 | 否 |
| `username-osint.md` | 3000+ 平台枚举 | 否 |
| `phone-osint.md` | 运营商查询、VoIP、FreeCNAM、WhoCalld | 否 |
| `email-osint.md` | 深度邮箱调查、泄露历史 | 否 |
| `threat-intel.md` | GreyNoise、AbuseIPDB、OTX、VirusTotal、CIRCL CVE、NVD | 可选（VT/URLScan 免费密钥） |
| `web-traffic-analysis.md` | SimilarWeb、Semrush 估算 | 否 |
| `domain-advanced.md` | CT 日志、Amass、Subfinder、被动枚举 | 否 |
| `social-media-platforms.md` | Twitter/X、Discord、Strava、BlueSky、ShareTrace、Reddit、Instagram、TikTok、Telegram | 部分（Discord 需要 token） |
| `image-forensics-and-face-search.md` | FaceCheck.id、TinEye、FotoForensics、Forensically、picarta.ai、GeoSpy、Pic2Map | 否 |
| `blockchain-investigation.md` | Blockchair、Etherscan、WalletExplorer、OXT.me、Chainabuse、Breadcrumbs | 可选（批量查询需 Etherscan API） |
| `fiat-payment-osint.md` | IBAN mod-97 + BBAN 拆解、BIC、VietQR/NAPAS BIN、卡 BIN、账号复用枢轴 | 否 |
| `china-recon.md` | ICP 备案、GSXT/信用中国/天眼查/企查查/爱企查、USCC、Quake/ZoomEye/FOFA、Baidu dork、CJK 变体 | 部分（CN 索引需免费密钥；聚合站需中国大陆出网） |
| `transport-tracking.md` | ADS-B Exchange、Flightradar24、Marine Traffic、VesselFinder、VIN 解码 | 否 |
| `darknet-investigation.md` | Ahmia.fi、onionsearch、DarknetLive、ransomwatch | 否 |
| `advanced-geolocation-techniques.md` | W3W、Plus Codes、MGRS、Overpass Turbo | 否 |
| `wifi-ssid-osint.md` | Wigle.net SSID/BSSID 地理定位 | 免费账号（Wigle API） |
| `web-dns-forensics.md` | 区域传送、GitHub、Telegram、WHOIS | 可选（WHOIS API） |
| `scam-check.md` | 钓鱼／诈骗域名核验 | 否 |
| `ioc-export.md` | IOC 导出（STIX 2.1、扁平列表） | 否 |
| `cloud-audit.md` | AWS/GCP/Azure 的 IAM、网络、计算审计 | 否 |
| `dependency-audit.md` | CVE、供应链、CI/CD 安全 | 否 |
| `disk-forensics.md` | Sleuth Kit、文件雕复、痕迹恢复 | 否 |
| `incident-triage.md` | NIST 800-61、遏制、IOC 提取 | 否 |
| `owasp-audit.md` | OWASP Top 10 源码审计 | 否 |
| `prompt-injection-audit.md` | LLM／代理／MCP 安全评估 | 否 |
| `fx-visitor-intelligence.md` | 访客统计、技术栈、地理分析 | 否 |
| `fx-social-topology.md` | 社交图谱构建与分析 | 否 |
| `fx-geolocation.md` | GPS、W3W、Plus Codes、MGRS、街景 | 否 |
| `secret-scanning.md` | 代码中的凭据／密钥检测 | 可选（GitDorker 需 GitHub token） |
| `github-osint.md` | GitHub 资料、组织、仓库、代码、提交、分叉与协作关系侦察 | 可选（GitHub token 提升 API 限额） |
| `fx-email-header-analysis.md` | 邮件头分析、SPF/DKIM | 否 |
| `fx-edge-appliance-recon.md` | 边界／VPN 设备指纹 → CISA KEV/CVE 目录 + 端口风险矩阵 | 否（Shodan/Censys 可选） |
| `fx-saas-identity-recon.md` | SaaS 租户（DNS-TXT）+ IdP 指纹 + API/GraphQL/规范发现 | 否 |
| `web-pivot.md` | Web 基础设施枢轴 —— favicon mmh3、追踪码／钱包／SaaS 运营者要素 → 排序后的枢轴 | 可选（付费密钥可升级层级） |
| `whois-universal.md` | 面向多 TLD 的通用 WHOIS 级联 —— gTLD/ccTLD（.vn/.th/.sg/.kr）、反向与历史查询 | 可选（反向／历史需 Whoxy/WhoisXML） |
| `web-collection-scrapling.md` | 自适应网页采集 —— 静态 → 反爬 → JS 渲染 | 否 |
| `agent-browser.md` | 交互式浏览器采集 —— CDP、无障碍树快照、截图证据 | 否（chat 模式可选） |
| `agentflow-enrichment.md` | 面向 3 个以上主体的并行 DAG 富化编排 | 否 |
| `microsoft-tenant-recon.md` | M365/Azure 租户侦察 —— 租户 ID、联合身份、MDI、SharePoint | 否 |
| `stealer-log-analysis.md` | 信息窃取日志分流 —— 家族识别、受害者与运营者画像、跨日志关联、IOC | 否 |
| `fx-dork-sweep.md` | 零认证 dork 扫描 —— Telegram 生态、文档托管站、文件类型族 | 否 |
| `fx-document-leak-hunt.md` | 覆盖 18 个平台的文档泄露搜寻，并做严重度分级 | 否 |

</details>

<br>

---

<br>

## 报告格式

你从不需要专门索要输出。每一次 `/report`、`/brief` 与 `/case` 都会自动写出完整一套 —— 一个用于探索案件的交互式网页，外加供工具链与取证使用的机器可读文件。需要把报告分享到团队之外？加上 `--redact`，PII 就会被替换成稳定的占位符（之后还能还原）。

<table>
<tr>
<td width="50%" valign="top">

### 🌐 交互式 HTML 报告 —— *你真正会去读的那一份*

单个自包含文件 —— 不联网、不需服务器，任何浏览器都能打开。

- **仪表盘** —— KPI、暴露面仪表，以及饼图／柱状图／环形图
- **实体图** —— 可拖拽、可缩放，点击任意节点即可查看详情
- **基础设施与时间线** —— 拓扑图加上可交互的事件历史
- **指标与选择子** —— 每一个 IOC、联系方式、账号与钱包，并标注行为体 ↔ 受害者归属
- **导航** —— 全局搜索、分类菜单、深色／浅色主题、打印成 PDF

</td>
<td width="50%" valign="top">

### 📄 Markdown · JSON · CSV · IOC 包 —— *供工具链与取证使用*

同一个案件，换成其他工具能读的格式。

- **Markdown** —— 书面报告：INTSUM、高管简报、通俗语言版或法务版
- **JSON** —— 结构化案件数据，可喂给流水线与其他工具
- **CSV** —— 发现与指标，可直接导入表格或 SIEM
- **IOC 包** —— STIX 2.1、扁平列表，以及全部选择子的 CSV
- **Word (.docx)** —— 按需生成，或用 `/report legal`（封面、目录、图表）

</td>
</tr>
</table>

**每一种报告变体都只是一条命令** —— 五格式默认套件（`.md` · `.html` · `.json` · `.csv` · IOC 包）在每次 `/report`、`/brief` 与 `/case` 时自动保存；下面的变体则用于指定某种具体格式或读者对象：

| 命令 | 格式 | 最适合 |
|---------|--------|----------|
| `/report` · `/report html` | 交互式 HTML *（默认，主交付物）* | 所有人 —— 从分析师到高管 |
| `/report` | 技术 INTSUM（Markdown） | 分析师、安全团队 |
| `/report brief` | 高管简报 | 决策者、管理层 |
| `/brief` | 通俗语言摘要 | 非技术相关方 |
| `/report legal` | 法务证据格式 *（自动附加 DOCX/PDF）* | 律师、合规团队 |
| `/report journalist` | 侧重信源引用 | 记者、媒体 |
| `/report json` · `/report csv` | JSON · CSV 导出 | 流水线、电子表格、SIEM |
| `/report ioc` | IOC／选择子包（STIX 2.1 · 扁平 · CSV） | SIEM / TIP 摄入、威胁情报共享 |
| `/report docx` | Word 文档 *（图表、封面、目录）* | 正式分享 —— 按需生成 |
| `/cti-report <ID> --pdf` | IntelReport pandoc PDF/DOCX | 精美的、出版级案件交付物 |

<sub>由 <code>scripts/generate-cti-html.py</code>（HTML）· <code>scripts/generate-cti-iocs.py</code>（IOC）· <code>scripts/generate-cti-docx-hybrid.py</code>（DOCX）· <code>intel_engine/IntelReport</code>（pandoc PDF/DOCX）生成</sub>

<br>

---

<br>

## 架构

<details>
<summary><b>项目结构</b> —— 点击展开</summary>
<br>

cti-expert 是**一个技能，两个层次** —— 一个广度*采集器*，加上一条内置、自包含的*深度流水线*。`STRUCTURE.md` 是权威的布局图。

```
cti-expert/
├── SKILL.md                    技能的唯一入口 —— 命令与技艺
├── README.md                   本文件  ·  README.vi.md · README.zh-CN.md
├── STRUCTURE.md                权威布局 + 防漂移规则
├── AGENTS.md                   跨代理运行时契约（Claude Code + Codex）
├── CLAUDE.md                   贡献者规则（仅在构建本仓库时加载）
│
├── commands/                   8 条已注册斜杠命令 —— 冷启动即可用
│   ├── cti.md                  /cti —— 入口，按目标类型路由
│   ├── cti-recall.md · cti-case.md · cti-pivot.md · cti-cluster.md
│   └── cti-check.md · cti-report.md · cti-status.md
│
│  ── LAYER 1 · 广度采集层 —— cti-expert 自有工具 ───────────────────
├── scripts/                    采集器、后端调度器、报告生成器
│   ├── backend/                backend.py（层级解析）· intel.py（T2 CLI 调度）
│   ├── webpivot/               pivot_extract · cert_pivot · wayback_* · rank_relations …
│   ├── generate-cti-html.py    交互式、离线、自包含的 HTML 报告
│   ├── generate-cti-iocs.py    IOC／选择子导出（STIX 2.1 · 扁平 · CSV）
│   ├── generate-cti-docx-hybrid.py   DOCX 报告（图表、示意图、封面）
│   ├── iban_analyze.py · redact.py · stealer_log_parse.py · pivot_orchestrator.py
│   ├── install.sh · install.ps1      一体化跨平台安装脚本
│   └── audit.sh · leakcheck.sh · install-hooks.sh   漂移 · 泄露 · 预提交门禁
│
├── techniques/                 49 种采集技术（OSINT 技艺本体）
├── handbook/                   枢轴要素、API 密钥、运营者查询、分析规范
├── engine/                     案件数据模型设计文档（schema、发现、枢轴逻辑）
├── analysis/ · validation/     模式与暴露面引擎 · QA + 覆盖度矩阵
├── experience/                 UX —— 技能层级、引导式流程、案件模板
├── workflows/ · guides/        专业场景指南 · 实战演练
├── connectors/                 intel-backend · Maltego · Notion · Obsidian 导出
├── tests/                      零依赖回归测试（RULE 5 分类 + collect_core）
│
│  ── LAYER 2 · 深度流水线 —— 内置、自包含 ─────────────────────────
└── intel_engine/               Collect → Correlate → Assess 流水线 + 知识库
    ├── harness/                流水线大脑 —— orchestrator.py · mcp_server.py · tools.py（24 个 @tool）
    ├── tools/                  intel.py（确定性流水线）· kb/（KB + 关联）· cert_overlap
    ├── WebPivot/               引擎侧采集器助手 + 去重再导出的 shim
    ├── IntelGraph/             出版级案件图渲染（PNG/SVG）
    ├── IntelReport/            用 Pandoc 渲染研判报告 → 精美 PDF/DOCX
    ├── IntelAnalysis/          关联、归因、置信度校准
    ├── BinaryPivot/            从诈骗 APK / exe 提取静态 IOC
    └── knowledge/ · cases/     本地运行时数据 —— 已 gitignore，绝不提交
```

</details>

<br>

---

<br>

## 专业工作流

| 工作流 | 适用人群 | 文件 |
|----------|----------|------|
| **记者信源核实** | 记者、事实核查员 | `workflows/wf-journalist.md` |
| **HR 背景筛查** | HR 从业者、招聘人员 | `workflows/wf-hr-screening.md` |
| **网络威胁情报** | 安全分析师、IR 团队 | `workflows/wf-threat-analyst.md` |
| **私家侦探** | 持照 PI、法务团队 | `workflows/wf-private-investigator.md` |

> 用 `/flow [type]` 启动交互式引导提示。

<br>

---

<br>

## 道德与负责任使用

> **本技能仅用于合法研究与专业安全调查。**

<table>
<tr>
<th>允许</th>
<th>禁止</th>
</tr>
<tr>
<td valign="top">

- 记者事实核查与信源核实
- HR 背景筛查（需征得同意）
- 企业安全研究与威胁情报
- 授权的渗透测试与安全审计
- 法律／合规调查
- 个人声誉监控（自查）

</td>
<td valign="top">

- 人肉搜索、骚扰或跟踪
- 未经授权的监控
- 社会工程或欺诈
- 侵犯隐私
- 犯罪活动

</td>
</tr>
</table>

**你对本技能的一切使用负责。** 请遵守当地法律、法规与平台服务条款。始终尊重隐私与同意的边界。

<br>

---

<br>

## 参与贡献

我们欢迎研究贡献、新技术与工作流改进。

<details>
<summary><b>贡献指南</b></summary>
<br>

**新增技术：**
1. 创建 `techniques/fx-[name].md`，包含方法说明、免费工具清单、局限性

**工作流改进：**
1. 在 `workflows/` 中记录，并写明成功标准

**Pull request 流程：**
1. Fork 并创建特性分支：`git checkout -b feature/technique-name`
2. 在 SKILL.md 与 README.md 中记录变更
3. 至少在 3 个真实目标上测试
4. 提交带说明的 PR

**Bug 反馈：** 提交 issue 时附上命令输出、运行环境与目标类型。

</details>

<br>

---

<br>

## 许可证

**MIT 许可证** + 道德使用附加条款

你可以在 MIT 许可证下自由使用、修改与分发本技能，前提是保留原始署名、遵守上述道德使用准则，并对任何衍生作品做出清晰标注。

完整条文见 [LICENSE](LICENSE)。

<br>

---

<br>

## 🙏 致谢与鸣谢

CTI Expert 站在开源社区与免费公益数据提供方的肩膀上。在此向下面每一个项目、厂商与免费 API 致以诚挚的感谢 —— 没有你们的工作，就没有这个技能。*（列出并不代表关联或背书；请始终遵守各提供方的服务条款。）*

| 类别 | 我们致谢的项目与免费服务 |
|----------|---------------------------------------------|
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
| **中国／华语圈侦察** | [ENScan_GO](https://github.com/wgpsec/ENScan_GO) · [Kunyu](https://github.com/knownsec/Kunyu) · [fofax](https://github.com/xiecat/fofax) · [PyDork](https://github.com/blacknon/pydork) · [MediaCrawler](https://github.com/NanmiCoder/MediaCrawler) · [pypinyin](https://github.com/mozillazg/python-pinyin) · [OpenCC](https://github.com/BYVoid/OpenCC) · [jieba](https://github.com/fxsjy/jieba) · [FOFA](https://fofa.info) · [Quake (360)](https://quake.360.net) · [ZoomEye](https://www.zoomeye.ai) · [GSXT](https://www.gsxt.gov.cn) · [信用中国](https://www.creditchina.gov.cn) · [Cninfo](http://www.cninfo.com.cn) |
| **支付通道与哈希** | [ISO 13616 / ISO 7064](https://www.iso.org)（IBAN 与 mod-97 标准） · [NAPAS / VietQR](https://vietqr.vn) · [name-that-hash](https://github.com/HashPals/Name-That-Hash) |
| **技艺与方法论** | [SOsintOps — Speculator Project](https://github.com/SOsintOps/Speculator-Project) · [Wukong](https://github.com/SOsintOps/Wukong)（中国层工具调研与访问现实矩阵） · [Exploratores](https://github.com/SOsintOps/Exploratores)（可逆脱敏与 IBAN 分析*技术* —— 依其公开文档独立重新实现；该项目为 AGPL-3.0，**未复制任何源码**） |
| **交通追踪** | [ADS-B Exchange](https://www.adsbexchange.com) · [Flightradar24](https://www.flightradar24.com) · [MarineTraffic](https://www.marinetraffic.com) · [VesselFinder](https://www.vesselfinder.com) |
| **暗网** | [Ahmia](https://ahmia.fi) · [OnionSearch](https://github.com/megadose/OnionSearch) · [ransomwatch](https://github.com/joshhighet/ransomwatch) |
| **云与文档** | [MSFTRecon](https://github.com/Arcanum-Sec/msftrecon) · [Xeuledoc](https://github.com/Malfrats/xeuledoc) · [oletools](https://github.com/decalage2/oletools) · [poppler](https://poppler.freedesktop.org) · [qpdf](https://github.com/qpdf/qpdf) · [mat2](https://0xacab.org/jvoisin/mat2) · [The Sleuth Kit](https://www.sleuthkit.org) |
| **网页存档** | [Internet Archive — Wayback](https://web.archive.org) · [Waymore](https://github.com/xnl-h4ck3r/waymore) |
| **报告与工具** | [pandoc](https://pandoc.org) · [python-docx](https://github.com/python-openxml/python-docx) · [Matplotlib](https://matplotlib.org) · [NetworkX](https://networkx.org) · [jq](https://jqlang.github.io/jq/) · [ASN](https://github.com/nitefood/asn) |
| **标准与框架** | [OWASP](https://owasp.org) · [MITRE ATT&CK](https://attack.mitre.org) · [STIX 2.1 (OASIS)](https://oasis-open.github.io/cti-documentation/) · [NIST SP 800-61](https://csrc.nist.gov/pubs/sp/800/61/r2/final) · [CWE](https://cwe.mitre.org) |

> 有我们应当致谢的项目，或希望修改／移除你项目的署名？欢迎提交 issue 或 PR —— 我们会尽快处理。💙

<br>

---

<br>

<div align="center">

### 由 [Hieu Ngo](https://www.linkedin.com/in/hieu-minh-ngo-hieupc/) 用心打造

<p>
  <a href="https://www.linkedin.com/in/hieu-minh-ngo-hieupc/"><img src="https://img.shields.io/badge/LinkedIn-Hieu_Ngo-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white" alt="LinkedIn"></a>&nbsp;
  <a href="mailto:hieu.ngo@chongluadao.vn"><img src="https://img.shields.io/badge/Email-hieu.ngo%40chongluadao.vn-0080ff?style=for-the-badge&logo=gmail&logoColor=white" alt="Email"></a>&nbsp;
  <a href="https://chongluadao.vn"><img src="https://img.shields.io/badge/Web-chongluadao.vn-00c853?style=for-the-badge&logo=googlechrome&logoColor=white" alt="Website"></a>&nbsp;
  <a href="https://github.com/7onez"><img src="https://img.shields.io/badge/GitHub-7onez-181717?style=for-the-badge&logo=github&logoColor=white" alt="GitHub"></a>
</p>

<sub>如果这个工具对你的工作有帮助，欢迎点个 star。它能帮更多人发现它。</sub>

</div>
