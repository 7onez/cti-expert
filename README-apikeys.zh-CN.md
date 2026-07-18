# cti-expert — Web 枢纽分析与付费 API 密钥

**语言：** [English](README-apikeys.md) · [Tiếng Việt](README-apikeys.vi.md) · 中文

如何使用 **`/webpivot`**（Web 基础设施枢纽分析）与 **`/apikeys`**（付费密钥管理）。
cti-expert **默认完全无需密钥 / 免费** 即可运行 —— 付费 API 密钥仅用于*增强*，不设置任何密钥也能正常工作。

---

## 快速上手

```bash
AK=~/.claude/skills/cti-expert/scripts/apikeys/apikeys.py

uv run "$AK"                              # status —— 查看已配置哪些密钥（无需密钥即可开始）
uv run "$AK" set censys censys_pat_XXXX  # 添加一个付费密钥（以 Censys 为例）
uv run "$AK" test censys                 # 🟢 有效 / 🔴 无效 / 🟠 错误
uv run "$AK" unlocks                      # 你的密钥解锁了什么

/webpivot https://suspicious-site.top    # 使用 —— 密钥会自动生效
```

---

## 1. API 密钥存储在哪里？（唯一的一个文件）

cti-expert 只有**唯一一个**密钥文件：

```
~/.claude/skills/cti-expert/.env          ( = $SKILL_DIR/.env )
```

- 该文件在你**首次**运行 `/apikeys set …` 时**自动创建** —— 在此之前它**并不存在**（所以现在看不到属正常）。
- `chmod 600` + **已加入 .gitignore** —— 绝不会被提交到 git。

**你看到的其它 `.env` 文件都不是 cti-expert 的密钥库** —— 请忽略它们。它们只是*源*项目里自带的模板：

| 你看到的文件 | 它实际是什么 |
|---|---|
| `WebPivot/.env.example`、`quarry/.env.example` | **原始仓库**里的示例模板（仅供参考） |
| `quarry/.env.docker.example` | quarry 的 Docker 模板 |
| `scripts/webpivot/.env`（若你自行创建过） | 向后兼容的旧路径；**技能根目录的 `.env` 才是标准** |

**各处的读取优先级：** **环境变量 → 技能的 `.env` 文件 → 无密钥模式。** 环境变量始终优先于文件（便于共享主机 / CI）。

---

## 2. 添加或修改密钥的两种方式

### A) 使用 `/apikeys` 命令（推荐）

```bash
AK=~/.claude/skills/cti-expert/scripts/apikeys/apikeys.py

# Censys 需要 Personal Access Token，外加可选的 Org ID：
uv run "$AK" set censys censys_pat_XXXXXXXXXXXX     # 可用服务 id（"censys"）…
uv run "$AK" set CENSYS_ORG_ID 1234-5678-org        # …也可用确切的 ENV_VAR 名称
uv run "$AK" set CENSYS_API_SECRET censys_pat_XXXX  # （别名同样接受）

# 让密钥不出现在 shell 历史里 —— 通过 stdin 传入：
printf %s "$MYKEY" | uv run "$AK" set censys

uv run "$AK" unset censys                            # 删除某个密钥
```

### B) 直接编辑 `.env` 文件

仓库自带一个 **[`.env.example`](.env.example)**，列出所有受支持的密钥（均为空），每个都注明解锁什么、去哪里申请。复制它并填入你拥有的密钥：

```bash
cp .env.example .env       # 在技能根目录（~/.claude/skills/cti-expert）运行
```

或用任意编辑器打开 `~/.claude/skills/cti-expert/.env`，添加 `KEY=VALUE` 行：

```dotenv
# cti-expert API keys — chmod 600, gitignored. Never commit.
CENSYS_API_KEY=censys_pat_XXXXXXXXXXXX
CENSYS_ORG_ID=1234-5678-org
SHODAN_API_KEY=你的_shodan_密钥
```

两种方式写入的是**同一个**文件。运行 `uv run "$AK" status` 确认已被识别。

---

## 3. 每个密钥解锁什么？

运行 `uv run "$AK" status --all` 查看完整目录（17 个服务），或参见
[`handbook/api-keys.md`](handbook/api-keys.md)。无密钥/免费路径已覆盖其中大部分；密钥用于解锁更高配额或反查能力：

| 服务 | 环境变量 | 解锁 |
|---|---|---|
| Shodan | `SHODAN_API_KEY` | `/webpivot`：以 favicon **mmh3** 反查 → 主机；`/cert-pivot`：以 **TLS 证书指纹** 反查 → 主机 |
| Censys | `CENSYS_API_KEY`（或 `CENSYS_API_ID`+`CENSYS_API_SECRET`） | `/webpivot`：以 favicon **MD5** 反查；`/cert-pivot`：证书 **fingerprint_sha256** → 主机 |
| FOFA | `FOFA_KEY`（+`FOFA_EMAIL`） | `/webpivot`：`icon_hash` + 追踪码 body 反查 |
| DNSLytics | `DNSLYTICS_API_KEY` | `/webpivot`：AdSense/GA ID → **同源关联域名** |
| SecurityTrails | `SECURITYTRAILS_API_KEY` | 被动 DNS、子域名、DNS/WHOIS 历史 |
| urlscan.io PRO | `URLSCAN_API_KEY` | 已认证的 DOM 内容检索 |
| WhoisXML | `WHOISXML_API_KEY` | 当前 + 历史 + **反向 WHOIS** |
| Blockchair | `BLOCKCHAIR_API_KEY` | `/crypto-balance`：多链**全生命周期收/发资金流**（无密钥已提供余额 + 交易数） |
| Subscan | `SUBSCAN_API_KEY` | `/crypto-balance`：更高配额的 **Polkadot (DOT)** 查询 |
| Hudson Rock / IntelX / ChongLuaDao | `HUDSONROCK_API_KEY` / `INTELX_API_KEY` / `CHONGLUADAO_API_KEY` | 泄露 / 失窃 / 暗网数据源；ChongLuaDao 还为 `/email-hygiene` 提供一次性邮箱检测 |
| GitHub · SerpAPI · BrightData · CertSpotter · ZoneCruncher | … | 代码发现 · 自动化 dork · 证书透明 · liveDNS |

---

## 4. 哪个工作流会用到这些密钥？（以及无密钥回退）

密钥接入 `pivot_extract.py` 的 **`enrich_live()`** 阶段，由 **`/webpivot`**（以及针对域名/URL 目标的
**`/case`**）调用：

1. **提取**页面中的 artifact —— favicon 哈希、GA/GTM/AdSense ID、加密钱包、SaaS 运营者令牌、邮箱、DOM 指纹。
2. **无密钥基线 —— 始终运行：** crt.sh（证书透明）、HackerTarget 被动 DNS、匿名 urlscan。
3. **付费 —— 仅当你设置了对应密钥：** Shodan（favicon mmh3 + 证书指纹 → 主机）、Censys（favicon MD5 +
   证书 SHA-256）、FOFA、DNSLytics（GA/AdSense → 同源关联域名）、SecurityTrails（被动 DNS）、urlscan-PRO、
   WhoisXML、Blockchair/Subscan（为 `/crypto-balance` 提供钱包资金流）。每条命中都会作为 `live_results`
   附加到枢轴点，并在 `--leads` 中显示。

> **新增无密钥关联工具：** `/rank-relations`（对同一运营者关系加权评分 + 噪声黑名单）、`/cert-pivot`（证书
> SAN 兄弟域名）、`/pivot-suggest`、`/crypto-balance`、`/email-hygiene`、`/sensitive-paths`。上述密钥仅作*增强*。

> **若未设置任何密钥，一切仍与之前完全一样 —— 无密钥 / 免费。** 缺少对应密钥时每个付费步骤都会被跳过；任何错误
>（密钥无效、配额用尽）只会显示一行提示 —— 绝不会中断整次运行。

---

## 5. `/case` 会默认运行 webpivot 吗？

**会 —— 针对域名 / URL 目标。** `/case example.com` 会在其 **Acquire（采集）** 阶段运行 `/webpivot`：

- **默认无密钥**（crt.sh + 被动 DNS + 匿名 urlscan）。
- 当你通过 `/apikeys` 设置付费密钥后**自动增强**。
- 对 `username` / `phone` / 人物类目标**不会**运行。
- 由于 `/webpivot` 可能直接访问目标，对**恶意基础设施**会优先采用被动采集（urlscan / Wayback）——
  参见 [`techniques/web-pivot.md`](techniques/web-pivot.md)。

你也可以单独运行：`/webpivot https://target.top`。

---

## 6. 工作流示意图

**`/webpivot` + 付费 API 密钥流程** —— 密钥如何接入枢纽分析：

![cti-expert /webpivot + premium API key workflow](assets/workflow-apikeys.png)

**`/case` 完整流程（AEAD）** —— `/webpivot` 与密钥在一次完整案件中的位置：

![cti-expert /case pipeline](assets/workflow-case.png)

---

## 7. 安全

- **绝不要提交 `.env`** —— 已加入 gitignore（`.env` + `scripts/**/.env`）。
- 在共享主机 / CI 上，优先使用**环境变量**（覆盖文件且不在磁盘留下额外内容）。
- `set <服务> <KEY>` 会把密钥写入 shell 历史 —— 请用 **stdin 形式**
  （`printf %s "$KEY" | uv run "$AK" set censys`）来避免。
- `/apikeys` 的输出**始终对密钥值做掩码**（只显示长度 + 末 2 位）。

---

## 8. 验证

```bash
AK=~/.claude/skills/cti-expert/scripts/apikeys/apikeys.py
uv run "$AK" status         # 已设置哪些密钥 + 解锁了什么
uv run "$AK" test censys    # 实时探测：🟢 有效 / 🔴 无效 / 🟠 错误 / ⚪ 无探测
uv run "$AK" path           # .env 文件位置 + 权限
```

---

## 致谢

- **WebPivot** —— `scripts/webpivot/` 中的 `/webpivot` 工具（favicon/追踪码/钱包提取、Wayback-GA、反向 WHOIS、图聚类）—— 作者 **[Zeroska](https://github.com/Zeroska)**，已集成到 cti-expert。
- **cti-expert** 作者：Hieu Ngo —— [chongluadao.vn](https://chongluadao.vn)。
