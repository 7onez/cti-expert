# :vietnam: CTI Expert — Tình Báo Mối Đe Dọa Mạng & OSINT

🇬🇧 [English](README.md)&nbsp;&nbsp;·&nbsp;&nbsp;🇻🇳 **[Tiếng Việt](README.vi.md)**&nbsp;&nbsp;·&nbsp;&nbsp;🇨🇳 [中文](README.zh-CN.md)

---

### CTI Expert là gì?

Một kỹ năng của Claude Code biến Claude thành một nhà phân tích tình báo mối đe dọa mạng và tình báo nguồn mở chuyên nghiệp. Chạy thu thập tình báo có cấu trúc sử dụng **74+ lệnh** trên **40 kỹ thuật** — không cần API key cho chức năng cốt lõi. Để tận dụng tối đa, bạn có thể thêm API key **miễn phí *hoặc* trả phí** của riêng mình vào tệp `.env` — mỗi key được **tự động phát hiện** và mở khóa truy cập cấp cao hơn (VD: Wigle, VirusTotal, URLScan.io, Shodan, Censys, SecurityTrails, WhoisXML).

> [!TIP]
> **Miễn phí theo mặc định — mạnh hơn khi có key của bạn.** Mọi thứ chạy được với zero key. Để mở khóa toàn bộ sức mạnh, thêm bất kỳ API key **miễn phí hoặc trả phí** nào vào `.env` (hoặc chạy `/apikeys set <dịch-vụ> <KEY>`); chúng được **tự động phát hiện** và nâng cấp ngay `/webpivot` cùng các kỹ thuật khác với reverse favicon→host, passive DNS, tra cứu chứng chỉ, và pivot tên miền anh em. Key thiếu/sai chỉ hạ xuống ghi chú. Danh sách & hướng dẫn: [handbook/api-keys.md](handbook/api-keys.md).

> [!TIP]
> **Không trạng thái theo mặc định — có bộ nhớ bền vững nếu bạn muốn.** CTI Expert quên mọi thứ giữa các lần chạy, nhờ vậy nó chạy được trên Claude Code, Codex và ChatGPT. Trỏ `INTEL_HOME` tới engine tùy chọn `intel_engine` và mỗi pha có thêm một móc bộ nhớ: **Acquire** hỏi *"tôi đã thấy nhà vận hành này chưa?"* trên mọi case trước đó, **Enrich** tương quan trên *toàn bộ* cơ sở tri thức, **Deliver** ghi một case có phiên bản. Nó cũng mở khóa `/backend`, `/kb`, `/recall` và `/binary` (trích IOC từ APK/exe). Vắng engine → mọi móc là no-op im lặng và pipeline chạy đúng như tài liệu. Chạy `/backend` để xem tier của bạn. Hợp đồng đầy đủ: [connectors/intel-backend.md](connectors/intel-backend.md).

**Mới trong v2.6:** **Trinh sát Trung Quốc / Sinophone** (`/icp` + `/cn-corp`) — lớp quy thuộc mà các cơ quan đăng ký phương Tây không chạm tới được: **giấy phép ICP (工信部备案)** ánh xạ tên miền sang **pháp nhân đăng ký tại Trung Quốc**, và **số sê-ri giấy phép** pivot đảo ngược sang mọi website anh em thuộc cùng một hồ sơ — liên kết cùng-nhà-vận-hành mạnh tương đương một GA ID dùng chung. Sau đó là chuỗi đăng ký: **GSXT** (dữ liệu gốc) → TianYanCha/QCC/Aiqicha → danh sách đen **信用中国** → chủ sở hữu thụ hưởng (UBO), kèm xác thực USCC và cờ trạng thái bị thu hồi. Bổ sung **Quake (360)** và **ZoomEye** làm các chỉ mục không gian mạng độc lập, **tầng Baidu** cho `/dork-sweep` (tầng 1–4 gần như không index nội dung hosted tại Trung Quốc), và **sinh biến thể CJK** — pinyin, Giản thể↔Phồn thể, thân từ tên công ty — thành một trục mới của `/pivot-suggest`. **Đường thanh toán fiat** (`/iban`) — phần lớn nạn nhân không dùng crypto mà chuyển khoản ngân hàng: [`iban_analyze.py`](scripts/iban_analyze.py) kiểm tra **ISO 7064 mod-97** (chứng minh một "số tài khoản" trên trang thanh toán là giả *mà không cần liên hệ ai*), phân tách BBAN thành mã ngân hàng/chi nhánh/số tài khoản, và cảnh báo **lệch quốc gia thụ hưởng** — mẫu mule kinh điển; bao gồm cả các đường thanh toán ngoài IBAN của VN/ĐNÁ (VietQR/NAPAS BIN, BIN thẻ, ví điện tử, BIC). **Chuẩn phân tích** — mọi phán định mang **thuật ngữ khả năng có dải xác suất** (*gần như không thể* → *gần như chắc chắn*) báo cáo song song với độ tin cậy bằng chứng; `/coverage` thêm **lượt kiểm 5W1H** (ma trận kỹ thuật chỉ đo nỗ lực — một case có thể đạt 96% mà vẫn không trả lời được **Vì sao** hay **Bằng cách nào**); `/threat-model` yêu cầu **ma trận ACH** cho quy thuộc: các giả thuyết đối thủ được chấm theo *mức bất nhất*, nêu tên giả thuyết á quân và bằng chứng có thể đảo thứ hạng. **Định kiểu hash** (`/hash-id`) — 32 hex là MD5 **hoặc NTLM**, một cái là file hash, cái kia là dữ liệu đăng nhập; định tuyến đúng dịch vụ trước khi tra cứu. **`/case` chạy không cần giám sát** — vòng lặp pivot mặc định `autonomy=auto`, mở rộng đến khi cạn frontier **không hỏi phê duyệt** (cổng độ tin cậy, không phải lời nhắc con người, mới là thứ giữ cho việc mở rộng gọn gàng); `/icp`, `/cn-corp`, `/iban`, `/hash-id` tự chạy **không cần cờ** và nạp kết quả trở lại vòng lặp như mọi node khác. **Che PII có thể đảo ngược** (`/redact`) — placeholder có số thứ tự ổn định (`[EMAIL_1]`) + bản đồ JSON đảo ngược được, round-trip chính xác từng byte; **opt-in** qua `--redact`, bộ xuất mặc định vẫn không bị che.

**Mới trong v2.5:** **Pivot đệ quy — `/case` là "bản đồ mạng nhện"**: giờ đây `/case` chạy một cỗ máy pivot BFS đệ quy ([`pivot_orchestrator.py`](scripts/pivot_orchestrator.py) + [`engine/pivot-orchestration.md`](engine/pivot-orchestration.md)) — mọi định danh phát hiện được (email/tên miền/IP/username/ví…) trở thành một seed mới và đồ thị quan hệ mở rộng theo từng bước **cho đến khi cạn kiệt frontier**; có kiểm soát độ tin cậy (liên kết khớp-chính-xác tự động theo đuổi, liên kết yếu/PII được giữ lại), an toàn vòng lặp (khử trùng lặp + giới hạn độ sâu), và **checkpoint theo từng độ sâu** (mặc định: active · exhaustive · checkpoint-per-depth). **Thu hoạch IOC từ archive** (`/webpivot --harvest`, [`wayback_harvest.py`](scripts/webpivot/wayback_harvest.py)) — chạy bộ trích xuất đầy đủ trên **toàn bộ lịch sử Wayback** của tên miền, gộp **email, số điện thoại, ví crypto, ID tracking/verification, ID nhà vận hành SaaS và mạng xã hội** kèm first-seen/last-seen — khôi phục cả những selector bị xóa về sau; xuất `indicators[]` thẳng vào bộ IOC, tự chạy trong `/case`. `/webpivot` giờ cũng trích xuất **số điện thoại** (`tel:` + định dạng) làm lead pivot. **Truy cập archive** ([`wayback_fetch.py`](scripts/webpivot/wayback_fetch.py)) — WebFetch của Claude Code bị chặn khỏi `web.archive.org` (robots.txt); công cụ này đi vòng: CDX → chọn snapshot gần nhất → tải raw `id_`, có retry/backoff. Lệnh `asn` bản địa — tra cứu IP/ASN/tên miền không cần API key (ipwho.is + RDAP) trên Windows; nitefood/asn đầy đủ được tự động cài trên Linux/macOS/WSL. Tự động cài `whois` + `dig` + `asn` trên Windows (winget `Microsoft.Sysinternals.Whois` + `ISC.Bind`, trước đây phải cài thủ công); gia cố trình cài đặt cho **Windows PowerShell 5.1** (sửa lỗi native-stderr làm dừng script, lỗi dò `OSArchitecture`, và maigret qua `uv tool --force`); tự động thêm `~/.local/bin` (công cụ uv + `asn`) vào PATH — phiên hiện tại **và** vĩnh viễn. **Pivot hạ tầng web** (`/cti-expert /webpivot`) — **miễn phí/keyless theo mặc định** (crt.sh + passive DNS + urlscan ẩn danh luôn chạy) và **tự động phát hiện API key premium** (Shodan/Censys/FOFA/DNSLytics/SecurityTrails/urlscan-PRO/WhoisXML) để tự nâng cấp mà không cần cờ — trích xuất artifact (favicon/tracker/ví/token nhà vận hành) &rarr; truy vấn pivot xếp hạng, kèm bộ tương quan **cùng nhà vận hành**: `/cti-expert /rank-relations` (chấm điểm có trọng số + danh sách chặn nhiễu), `/cti-expert /cert-pivot` (pivot vân tay chứng chỉ TLS), `/cti-expert /pivot-suggest`, `/cti-expert /crypto-balance`, `/cti-expert /email-hygiene`, `/cti-expert /sensitive-paths`; phân tích **có kiểm soát bằng chứng** — mọi khẳng định phải trích dẫn một phát hiện tồn tại, dữ liệu thu thập không đáng tin được gắn thẻ và không bao giờ được thực thi. **Quét thiết bị biên** (`/cti-expert /appliance-scan`) — fingerprint thiết bị edge/VPN hướng Internet (Citrix/F5/Cisco/Ivanti/Forti/Palo Alto/Exchange) theo cách bị động trước (Shodan InternetDB/Censys) &rarr; ánh xạ sang **CVE trong danh mục CISA KEV**, cấp dữ liệu cho `/vuln-check` + `/threat-model`. **Bản đồ SaaS & danh tính** (`/cti-expert /saas-map`) — token xác thực tenancy qua DNS-TXT (Google/Atlassian/Zscaler/Salesforce/Workday…), fingerprint IdP ngoài Microsoft (Okta/Auth0/OneLogin/Ping/Keycloak/ADFS), và phát hiện API/GraphQL/OpenAPI-spec không cần xác thực. **Xác thực credential chỉ-đọc** — key phát hiện được kiểm tra còn sống qua endpoint định danh (AWS STS, phạm vi GitHub, Slack `auth.test`, `…/v1/models`), không bao giờ gọi endpoint ghi/xóa — nâng lên CRITICAL kèm bằng chứng tài khoản/phạm vi.

**Mới trong v2.4:** Phát hiện hệ điều hành đa nền tảng (Windows/macOS/Linux) với tự động cài đặt theo OS và tạo DOCX tự khắc phục (UTF-8 + pandoc); bộ công cụ ưu tiên **uv** (uv venv/pip/tool, script `uv run` PEP 723 không cần thiết lập); hỗ trợ **đa tác nhân** — chạy trên Claude Code **và** OpenAI Codex qua `AGENTS.md`; trình phân tích nhật ký stealer (`/cti-expert /stealer-log`) — định danh họ mã độc, phân tích nạn nhân-vs-kẻ vận hành, tương quan đa nhật ký, trích xuất IOC + dữ liệu thô; phát hiện trang quản trị & điểm cuối nhạy cảm (admin/adm/kef/ador/panel…); tích hợp **agent-browser** (vercel-labs) làm trình thu thập trình duyệt tương tác chính; gia cố cài đặt trên máy/VPS sạch + CI.

**Mới trong v2.3:** WHOIS toàn cầu cho mọi TLD (whoisdomain + CLI + Whoxy API; .vn, .th, .sg, .kr…), WHOIS đảo ngược & lịch sử; thu thập web Scrapling thích ứng (tĩnh → chống bot → kết xuất JS); trình duyệt headless tự động mở; làm giàu song song AgentFlow (DAG); phân tích HTML ~2ms; yêu cầu tối thiểu Python 3.10+.

**Mới trong v2.2:** Pháp y hình ảnh & tìm kiếm khuôn mặt (FaceCheck.id, TinEye, FotoForensics, picarta.ai AI geolocation), điều tra blockchain (Blockchair, Etherscan, WalletExplorer, Chainabuse), theo dõi vận tải (ADS-B Exchange theo dõi máy bay, Marine Traffic theo dõi tàu, VIN decoder), điều tra darknet (Ahmia.fi tìm kiếm Tor, ransomwatch), mạng xã hội mở rộng (Reddit, Instagram, TikTok, Telegram), tra cứu người (TruePeopleSearch, IDCrawl), 11 mẫu Google mega-dork bao phủ 73 domain.

**Mới trong v2.1:** Trực quan hóa đường tấn công (`/cti-expert /render threat-path`), bề mặt tấn công (`/cti-expert /render attack-surface`), xuất IOC STIX 2.1 (`/cti-expert /report ioc`), theo dõi rủi ro theo thời gian (`/cti-expert /drift`), ảnh chụp Wayback (`/cti-expert /snapshots`, `/cti-expert /diff`), hướng dẫn người mới (`/cti-expert /onboard`), giải thích phát hiện (`/cti-expert /clarify`), phân tích khoảng trống (`/cti-expert /blind-spots`), kiểm tra nguồn (`/cti-expert /source-check`), so sánh phiên (`/cti-expert /workspace diff`), điểm chất lượng (`/cti-expert /quality`), thang độ tin cậy nguồn A-F, 4 loại thực thể mới.

**Khả năng cốt lõi:** Trinh sát đa vector trên mọi loại mục tiêu (cá nhân, tên miền, tổ chức, tên người dùng, email, IP, WiFi) với xác thực phát hiện tự động, chấm điểm rủi ro phơi bày, và báo cáo tình báo có cấu trúc ở nhiều định dạng.

**Quy trình:** Vòng đời AEAD — Thu thập dữ liệu thô &rarr; Làm giàu bằng mở rộng pivot &rarr; Đánh giá phát hiện &rarr; Phân phối báo cáo có cấu trúc (HTML tương tác + Markdown + JSON/CSV + gói IOC; Word khi cần).

---

### Cài đặt

> **Khuyến nghị:** Dùng **Claude Code CLI** — cho phép sử dụng đầy đủ workflow terminal, phiên làm việc liên tục và gọi skill trực tiếp. [Tải tại đây](https://docs.anthropic.com/en/docs/claude-code/overview) hoặc chạy `npm install -g @anthropic-ai/claude-code`.

#### Tại sao nên dùng Claude Code CLI?

Toàn bộ workflow CTI Expert được tối ưu cho Claude Code CLI:
- **Phiên làm việc liên tục** — điều tra được lưu qua `/cti-expert /workspace save`
- **Truy cập đầy đủ công cụ** — ghi file, chạy Python, tạo DOCX, tất cả chạy tự nhiên
- **Gọi skill trực tiếp** — gõ `/cti-expert` ngay trong terminal
- **Agent song song** — AgentFlow hoạt động tốt nhất với CLI

#### 🖥️ Nên chạy ở đâu — CLI là tốt nhất cho skill này

> [!IMPORTANT]
> CTI Expert **chạy nhiều tác vụ thực thi**: chạy `uv`/Python, cài công cụ OSINT, ghi báo cáo `.md`/`.html`/`.json`/`.csv` + gói IOC, truy cập nhiều trang web bên ngoài, và lưu workspace vụ việc. Điều quan trọng là **shell cục bộ thật + file lưu bền + mạng không bị chặn** — **CLI hoặc app desktop cục bộ** cho bạn điều đó; còn **sandbox đám mây tạm thời thì không**. Điều này áp dụng cho cả **Claude** lẫn **Codex**.

| Môi trường | Chạy điều tra | Lý do |
|---|---|---|
| **Claude Code CLI** · **Codex CLI** | ✅ **Tốt nhất** | Shell thật, lưu bền, tác vụ nền, mạng mở — đúng thứ skill cần |
| **Claude Code Desktop** · **Tiện ích IDE Codex** | ✅ Rất tốt | Cùng khả năng thực thi cục bộ; đọc báo cáo, biểu đồ, sơ đồ thoải mái nhất |
| **claude.ai/code (web)** · **Codex cloud / ChatGPT web** | ⚠️ Hạn chế | Suy luận phân tích & tạo truy vấn vẫn chạy, nhưng file không lưu vào ổ đĩa của bạn và mạng ra ngoài thường bị giới hạn |

> [!TIP]
> **Chạy điều tra trong CLI** (Claude Code hoặc Codex); mở báo cáo `.html`/`.docx` trong cửa sổ Desktop/IDE nếu bạn thích đọc ở đó. Chỉ dùng môi trường web/đám mây cho phần suy luận phân tích, không dùng cho recon nặng về thực thi.

---

#### Bước 1 &mdash; Cài đặt Claude Code CLI

```bash
npm install -g @anthropic-ai/claude-code
```

> Yêu cầu Node.js 18+. Tài liệu đầy đủ: [docs.anthropic.com/en/docs/claude-code/overview](https://docs.anthropic.com/en/docs/claude-code/overview)

---

#### Bước 2 &mdash; Clone + Cài đặt all-in-one

Script `scripts/install.sh` xử lý tất cả: Python venv, công cụ hệ thống (`whois`, `dig`, `jq`, `exiftool`), công cụ OSINT (`maigret`, `sherlock`, `holehe`, `h8mail`, ...), và tùy chọn headless browser + Go tools.

<table>
<tr>
<th>Hệ điều hành</th>
<th>Lệnh</th>
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
<td><b>Windows (Git Bash hoặc WSL)</b></td>
<td>

```bash
git clone https://github.com/7onez/cti-expert.git ~/.claude/skills/cti-expert
bash ~/.claude/skills/cti-expert/scripts/install.sh
```

</td>
</tr>
<tr>
<td><b>Windows (PowerShell — thủ công)</b></td>
<td>

```powershell
git clone https://github.com/7onez/cti-expert.git "$env:USERPROFILE\.claude\skills\cti-expert"
pip3 install -r "$env:USERPROFILE\.claude\skills\cti-expert\scripts\requirements.txt"
```

</td>
</tr>
</table>

> **Người dùng Windows:** Script chạy trong **Git Bash** (đi kèm [Git for Windows](https://git-scm.com/download/win)) hoặc **WSL**. PowerShell là phương án dự phòng chỉ cài Python dependencies.

---

#### Tùy chọn installer

```bash
bash scripts/install.sh               # Cơ bản: Python + công cụ hệ thống + OSINT tools
bash scripts/install.sh --headless    # + Scrapling headless browser (~200MB Chromium)
bash scripts/install.sh --go          # + Go tools (subfinder, amass, gau, gitleaks, httpx)
bash scripts/install.sh --all         # + Tất cả
```

| Flag | Cài gì | Kích thước |
|------|--------|-----------|
| *(không có)* | Python packages, whois, dig, jq, exiftool, maigret, sherlock, holehe, h8mail, theHarvester, waymore, xeuledoc, agentflow | ~50 MB |
| `--headless` | Scrapling StealthyFetcher + DynamicFetcher + Chromium | +200 MB |
| `--go` | subfinder, amass, gau, gitleaks, httpx, trufflehog, phoneinfoga | +150 MB |
| `--all` | Tất cả | ~400 MB |

---

#### Kiểm tra cài đặt

```bash
claude   # mở Claude Code CLI
# sau đó gõ:
/cti-expert
```

---

#### Tùy chọn khác &mdash; Claude Code Desktop (macOS / Windows)

> Tải về: [claude.ai/download](https://claude.ai/download) &mdash; hỗ trợ **macOS** và **Windows**

1. **Cài đặt Claude Code Desktop** &mdash; Tải từ [claude.ai/download](https://claude.ai/download) và cài đặt ứng dụng
2. **Tải CTI Expert** &mdash; Vào [kho GitHub](https://github.com/7onez/cti-expert), nhấn nút **"Code"** màu xanh, sau đó chọn **"Download ZIP"**
3. **Giải nén vào thư mục skills** &mdash; Giải nén file đã tải, di chuyển thư mục vào thư mục skills và đổi tên thành `cti-expert`:

   | Hệ điều hành | Cách điều hướng |
   |-------------|----------------|
   | **macOS** | Mở **Finder** &rarr; Nhấn **Shift + Cmd + G** &rarr; Nhập `~/.claude/skills/` &rarr; Nhấn **Go** |
   | **Windows** | Mở **File Explorer** &rarr; Nhập `%USERPROFILE%\.claude\skills\` vào thanh địa chỉ &rarr; Nhấn **Enter** |

4. **Chạy installer** &mdash; Mở terminal trong Claude Code Desktop:

   ```bash
   bash ~/.claude/skills/cti-expert/scripts/install.sh
   ```

   Hoặc trên Windows PowerShell (chỉ Python):

   ```powershell
   pip3 install -r "$env:USERPROFILE\.claude\skills\cti-expert\scripts\requirements.txt"
   ```

5. **Khởi động lại Claude Code Desktop** &mdash; Đóng và mở lại ứng dụng
6. **Xác nhận** &mdash; Gõ `/cti-expert` trong chat để xác nhận skill đã được tải

<details>
<summary><b>Yêu cầu hệ thống</b></summary>
<br>

| Yêu cầu | Phiên bản | Mục đích |
|----------|-----------|----------|
| [Claude Code CLI](https://docs.anthropic.com/en/docs/claude-code/overview) | Mới nhất | **Khuyến nghị** — runtime terminal |
| [Claude Code Desktop](https://claude.ai/download) | Mới nhất | Runtime giao diện (macOS/Windows) |
| Node.js | 18+ | Yêu cầu bởi Claude Code CLI |
| Python | 3.10+ | Tạo báo cáo DOCX, Scrapling, AgentFlow |
| pip packages | Xem `requirements.txt` | Biểu đồ, sơ đồ, định dạng |
| git | Bất kỳ | Clone repository |

</details>

---

### Bắt đầu nhanh

```bash
/cti-expert /case example.com                   # Chạy case tự động hoàn toàn
/cti-expert /flow person                        # Quy trình điều tra cá nhân
/cti-expert /flow domain                        # Quy trình trinh sát tên miền
/cti-expert /sweep @username                    # Trinh sát đa vector trên handle
/cti-expert /query example.com                  # 12-15 truy vấn tìm kiếm nâng cao
/cti-expert /username johndoe                   # Liệt kê nền tảng (3000+)
/cti-expert /email-deep user@domain.com         # Điều tra email chuyên sâu
/cti-expert /github-osint github.com/org/repo   # Hồ sơ GitHub, repo, code, commit, fork
/cti-expert /webpivot https://scam-site.top     # Pivot hạ tầng web → truy vấn pivot xếp hạng
/cti-expert /rank-relations                      # Xếp hạng quan hệ cùng nhà vận hành (lọc nhiễu)
/cti-expert /cert-pivot scam-site.top           # Pivot vân tay chứng chỉ TLS + tên miền SAN
/cti-expert /icp scam-site.top                  # Giấy phép ICP → pháp nhân TQ + tên miền anh em
/cti-expert /cn-corp 深圳市某某科技有限公司        # Chuỗi đăng ký doanh nghiệp TQ (GSXT → UBO)
/cti-expert /iban GB29NWBK60161331926819        # Xác thực + phân tách số tài khoản ngân hàng
/cti-expert /hash-id <hash>                     # Định kiểu hash trước khi tra cứu
/cti-expert /redact REPORT.md                   # Bản báo cáo che PII để chia sẻ (opt-in)
/cti-expert /backend                            # Phát hiện backend tùy chọn + báo tier (cần intel_engine)
/cti-expert /kb --entity example.com            # Tra cứu cơ sở tri thức chia sẻ (thực thể/cụm/chỉ báo chung)
/cti-expert /recall scam-site.top               # "Tôi đã thấy chưa?" — đối chiếu seed với mọi case trước
/cti-expert /risk CASE-0001                      # Chấm điểm NRD / hosting chống đạn / đường tiền
/cti-expert /cert-overlap a.com b.com           # Phán định cùng-nhà-vận-hành qua chứng chỉ TLS/SAN
/cti-expert /reference check favicon:123        # Sổ kiểm soát dương-tính-giả (BENIGN vs SIGNAL)
/cti-expert /harness status CASE-0001           # Điều phối toàn case — bền vững, có phiên bản, hội tụ
/cti-expert /report pdf assessment.md out       # Kết xuất PDF/DOCX chuẩn báo cáo (IntelReport)
/cti-expert /binary ./trader.apk                # Trích IOC từ APK/exe lừa đảo → gộp với hạ tầng web
/cti-expert /exposure domain.com                # Điểm rủi ro tổng hợp (0-100)
/cti-expert /report                             # Báo cáo kỹ thuật INTSUM
/cti-expert /workspace save                     # Lưu trạng thái workspace để tiếp tục sau
```

---

### Tính năng theo lĩnh vực

| Lĩnh vực | Khả năng |
|-----------|----------|
| **Danh tính & Con người** | Tra cứu cá nhân (50+ điểm dữ liệu), điều tra số điện thoại, email chuyên sâu, liệt kê tên người dùng (3000+ nền tảng), dấu vết nhà phát triển GitHub |
| **Tên miền & Hạ tầng** | Liệt kê subdomain, fingerprint kỹ thuật, pháp y DNS, phân tích lưu lượng, giấy phép ICP &rarr; pháp nhân TQ |
| **Trung Quốc & KYC doanh nghiệp** | Hồ sơ ICP + pivot số sê-ri, chuỗi đăng ký GSXT/信用中国/TianYanCha/QCC/Aiqicha, xác thực USCC, Quake/ZoomEye/FOFA, dork Baidu, biến thể pinyin & Phồn thể |
| **Dòng tiền** | Số dư ví on-chain; xác thực IBAN mod-97 + phân tách BBAN, BIC, VietQR/NAPAS BIN, BIN thẻ, pivot tái sử dụng tài khoản |
| **Phân tích & Xác minh** | Xác minh hình ảnh, pháp y metadata, pháp y web, cơ sở dữ liệu rò rỉ, định kiểu hash, thuật ngữ khả năng có dải xác suất + lượt kiểm 5W1H + ma trận ACH |
| **WiFi & Định vị** | Định vị WiFi qua Wigle.net, định vị nâng cao (W3W, Plus Codes, MGRS) |
| **Kiểm tra bảo mật** | Kiểm tra đám mây (AWS/GCP/Azure), kiểm tra OWASP, kiểm tra dependency, kiểm tra prompt injection |
| **Pivot hạ tầng & Tương quan** | Pivot hạ tầng web (favicon/tracker/ví &rarr; truy vấn pivot), xếp hạng quan hệ cùng nhà vận hành (lọc nhiễu, phân cụm), pivot vân tay chứng chỉ TLS, gợi ý pivot, số dư ví on-chain, chấm điểm hygiene email, phân loại đường dẫn nhạy cảm |
| **Báo cáo & Xuất** | Báo cáo HTML tương tác (đồ thị thực thể 2D, biểu đồ, dòng thời gian), Markdown, JSON/CSV, gói IOC (STIX 2.1), DOCX khi cần, che PII đảo ngược được để chia sẻ (opt-in) |

---

### Sơ đồ quy trình

**Pipeline `/case` đầy đủ (AEAD)** — vị trí của `/webpivot`, tương quan và key trả phí:

![Pipeline /case của cti-expert](assets/workflow-case.png)

**Luồng `/webpivot` + tương quan + API key trả phí:**

![Luồng /webpivot + API key của cti-expert](assets/workflow-apikeys.png)

<sub>Nguồn: <a href="workflow-case.puml"><code>workflow-case.puml</code></a> · <a href="workflow-apikeys.puml"><code>workflow-apikeys.puml</code></a> — xem <a href="handbook/api-keys.md">hướng dẫn API key & webpivot</a>.</sub>

---

### Đạo đức & Sử dụng có trách nhiệm

**Kỹ năng này chỉ dành cho nghiên cứu hợp pháp và điều tra bảo mật chuyên nghiệp.**

**Được phép:** Xác minh nguồn báo chí, sàng lọc nhân sự (có sự đồng ý), nghiên cứu bảo mật doanh nghiệp, kiểm tra xâm nhập được ủy quyền, điều tra pháp lý/tuân thủ, giám sát danh tiếng cá nhân.

**Cấm:** Doxxing, quấy rối, theo dõi, giám sát trái phép, kỹ thuật xã hội, gian lận, vi phạm quyền riêng tư, hoạt động tội phạm.

---

## 🙏 Lời cảm ơn & Ghi nhận

CTI Expert được xây dựng trên thành quả của cộng đồng mã nguồn mở và các nhà cung cấp dữ liệu miễn phí vì lợi ích cộng đồng. Xin gửi lời cảm ơn chân thành đến mọi dự án, nhà cung cấp và API miễn phí dưới đây — kỹ năng này sẽ không thể tồn tại nếu thiếu công sức của các bạn. *(Việc liệt kê không đồng nghĩa với liên kết hay chứng thực; hãy luôn tôn trọng điều khoản dịch vụ của từng nhà cung cấp.)*

| Hạng mục | Dự án & dịch vụ miễn phí chúng tôi tri ân |
|----------|--------------------------------------------|
| **Tác nhân & runtime** | [Anthropic — Claude Code](https://claude.com/claude-code) · [OpenAI — Codex](https://developers.openai.com/codex) · [Astral — uv](https://docs.astral.sh/uv/) · [Python](https://www.python.org) · [Node.js](https://nodejs.org) · [Rust](https://www.rust-lang.org) |
| **Trình duyệt & thu thập web** | [agent-browser — Vercel Labs](https://github.com/vercel-labs/agent-browser) · [Scrapling](https://github.com/D4Vinci/Scrapling) · [Chromium](https://www.chromium.org) |
| **Tên người dùng, cá nhân & mạng xã hội** | [Maigret](https://github.com/soxoj/maigret) · [Sherlock](https://github.com/sherlock-project/sherlock) · [Blackbird](https://github.com/p1ngul1n0/blackbird) · [instaloader](https://github.com/instaloader/instaloader) · [Osintgram](https://github.com/Datalux/Osintgram) · [toutatis](https://github.com/megadose/toutatis) · [ShareTrace](https://github.com/7onez/sharetrace) |
| **Email & dữ liệu rò rỉ** | [Holehe](https://github.com/megadose/holehe) · [h8mail](https://github.com/khast3x/h8mail) · [theHarvester](https://github.com/laramies/theHarvester) · [Have I Been Pwned](https://haveibeenpwned.com) · [Hudson Rock](https://www.hudsonrock.com) · [LeakCheck](https://leakcheck.io) |
| **Tên miền, DNS & hạ tầng** | [Subfinder](https://github.com/projectdiscovery/subfinder) · [Amass](https://github.com/owasp-amass/amass) · [httpx](https://github.com/projectdiscovery/httpx) · [GAU](https://github.com/lc/gau) · [crt.sh](https://crt.sh) · [Whoxy](https://www.whoxy.com) · [ViewDNS](https://viewdns.info) · [whoisdomain](https://github.com/mboot-github/WhoisDomain) · [Shodan InternetDB](https://internetdb.shodan.io) · [ipwho.is](https://ipwho.is) |
| **Tình báo mối đe dọa** | [VirusTotal](https://www.virustotal.com) · [URLScan.io](https://urlscan.io) · [GreyNoise](https://www.greynoise.io) · [AbuseIPDB](https://www.abuseipdb.com) · [AlienVault OTX](https://otx.alienvault.com) · [abuse.ch](https://abuse.ch) (URLhaus · ThreatFox · MalwareBazaar) · [CIRCL](https://www.circl.lu) · [NVD](https://nvd.nist.gov) · [ransomware.live](https://www.ransomware.live) |
| **Bí mật & mã nguồn** | [TruffleHog](https://github.com/trufflesecurity/trufflehog) · [Gitleaks](https://github.com/gitleaks/gitleaks) · [GitHub CLI](https://cli.github.com) |
| **Điện thoại** | [PhoneInfoga](https://github.com/sundowndev/phoneinfoga) · FreeCNAM · WhoCalld |
| **Định vị & WiFi** | [OpenStreetMap](https://www.openstreetmap.org) · [what3words](https://what3words.com) · [Overpass Turbo](https://overpass-turbo.eu) · [WiGLE](https://wigle.net) |
| **Pháp y hình ảnh** | [ExifTool](https://exiftool.org) · [TinEye](https://tineye.com) · [FaceCheck.id](https://facecheck.id) · [FotoForensics](https://fotoforensics.com) · [picarta.ai](https://picarta.ai) |
| **Blockchain** | [Blockchair](https://blockchair.com) · [Etherscan](https://etherscan.io) · [WalletExplorer](https://www.walletexplorer.com) · [Chainabuse](https://www.chainabuse.com) |
| **Trinh sát Trung Quốc / Sinophone** | [ENScan_GO](https://github.com/wgpsec/ENScan_GO) · [Kunyu](https://github.com/knownsec/Kunyu) · [fofax](https://github.com/xiecat/fofax) · [PyDork](https://github.com/blacknon/pydork) · [MediaCrawler](https://github.com/NanmiCoder/MediaCrawler) · [pypinyin](https://github.com/mozillazg/python-pinyin) · [OpenCC](https://github.com/BYVoid/OpenCC) · [jieba](https://github.com/fxsjy/jieba) · [FOFA](https://fofa.info) · [Quake (360)](https://quake.360.net) · [ZoomEye](https://www.zoomeye.ai) · [GSXT](https://www.gsxt.gov.cn) · [信用中国](https://www.creditchina.gov.cn) · [Cninfo](http://www.cninfo.com.cn) |
| **Đường thanh toán & hash** | [ISO 13616 / ISO 7064](https://www.iso.org) (chuẩn IBAN + mod-97) · [NAPAS / VietQR](https://vietqr.vn) · [name-that-hash](https://github.com/HashPals/Name-That-Hash) |
| **Nghiệp vụ & phương pháp luận** | [SOsintOps — Speculator Project](https://github.com/SOsintOps/Speculator-Project) · [Wukong](https://github.com/SOsintOps/Wukong) (khảo sát công cụ lớp Trung Quốc & ma trận thực tế truy cập) · [Exploratores](https://github.com/SOsintOps/Exploratores) (*kỹ thuật* che PII đảo ngược và phân tích IBAN — tự triển khai lại từ tài liệu công bố; dự án đó theo AGPL-3.0 và **không có dòng mã nào được sao chép**) |
| **Theo dõi vận tải** | [ADS-B Exchange](https://www.adsbexchange.com) · [Flightradar24](https://www.flightradar24.com) · [MarineTraffic](https://www.marinetraffic.com) · [VesselFinder](https://www.vesselfinder.com) |
| **Darknet** | [Ahmia](https://ahmia.fi) · [OnionSearch](https://github.com/megadose/OnionSearch) · [ransomwatch](https://github.com/joshhighet/ransomwatch) |
| **Đám mây & tài liệu** | [MSFTRecon](https://github.com/Arcanum-Sec/msftrecon) · [Xeuledoc](https://github.com/Malfrats/xeuledoc) · [oletools](https://github.com/decalage2/oletools) · [poppler](https://poppler.freedesktop.org) · [qpdf](https://github.com/qpdf/qpdf) · [mat2](https://0xacab.org/jvoisin/mat2) · [The Sleuth Kit](https://www.sleuthkit.org) |
| **Lưu trữ web** | [Internet Archive — Wayback](https://web.archive.org) · [Waymore](https://github.com/xnl-h4ck3r/waymore) |
| **Báo cáo & tiện ích** | [pandoc](https://pandoc.org) · [python-docx](https://github.com/python-openxml/python-docx) · [Matplotlib](https://matplotlib.org) · [NetworkX](https://networkx.org) · [jq](https://jqlang.github.io/jq/) · [ASN](https://github.com/nitefood/asn) |
| **Tiêu chuẩn & khuôn khổ** | [OWASP](https://owasp.org) · [MITRE ATT&CK](https://attack.mitre.org) · [STIX 2.1 (OASIS)](https://oasis-open.github.io/cti-documentation/) · [NIST SP 800-61](https://csrc.nist.gov/pubs/sp/800/61/r2/final) · [CWE](https://cwe.mitre.org) |

> Chúng tôi nên ghi nhận thêm dự án nào, hoặc bạn muốn thay đổi/gỡ tên dự án của mình? Hãy mở issue hoặc PR — chúng tôi sẽ sửa ngay. 💙

---

**Tác giả:** [Hieu Ngo](https://chongluadao.vn) &bull; [hieu.ngo@chongluadao.vn](mailto:hieu.ngo@chongluadao.vn) &bull; **Phiên bản:** 2.6 &bull; **Giấy phép:** MIT
