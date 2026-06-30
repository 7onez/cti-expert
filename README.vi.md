# :vietnam: CTI Expert — Tình Báo Mối Đe Dọa Mạng & OSINT

**Ngôn ngữ:** [English](README.md) · [Tiếng Việt](README.vi.md) · [中文](README.zh.md)

---

### CTI Expert là gì?

Một kỹ năng của Claude Code biến Claude thành một nhà phân tích tình báo mối đe dọa mạng và tình báo nguồn mở chuyên nghiệp. Chạy thu thập tình báo có cấu trúc sử dụng **67+ lệnh** trên **36 kỹ thuật** — không cần API key cho chức năng cốt lõi. Một số kỹ thuật hỗ trợ API key miễn phí tùy chọn để truy cập nâng cao (VD: Wigle, VirusTotal, URLScan.io).

**Mới trong v2.4:** Phát hiện hệ điều hành đa nền tảng (Windows/macOS/Linux) với tự động cài đặt theo OS và tạo DOCX tự khắc phục (UTF-8 + pandoc); bộ công cụ ưu tiên **uv** (uv venv/pip/tool, script `uv run` PEP 723 không cần thiết lập); hỗ trợ **đa tác nhân** — chạy trên Claude Code **và** OpenAI Codex qua `AGENTS.md`; trình phân tích nhật ký stealer (`/cti-expert /stealer-log`) — định danh họ mã độc, phân tích nạn nhân-vs-kẻ vận hành, tương quan đa nhật ký, trích xuất IOC + dữ liệu thô; phát hiện trang quản trị & điểm cuối nhạy cảm (admin/adm/kef/ador/panel…); tích hợp **agent-browser** (vercel-labs) làm trình thu thập trình duyệt tương tác chính; gia cố cài đặt trên máy/VPS sạch + CI.

**Mới trong v2.3:** WHOIS toàn cầu cho mọi TLD (whoisdomain + CLI + Whoxy API; .vn, .th, .sg, .kr…), WHOIS đảo ngược & lịch sử; thu thập web Scrapling thích ứng (tĩnh → chống bot → kết xuất JS); trình duyệt headless tự động mở; làm giàu song song AgentFlow (DAG); phân tích HTML ~2ms; yêu cầu tối thiểu Python 3.10+.

**Mới trong v2.2:** Pháp y hình ảnh & tìm kiếm khuôn mặt (FaceCheck.id, TinEye, FotoForensics, picarta.ai AI geolocation), điều tra blockchain (Blockchair, Etherscan, WalletExplorer, Chainabuse), theo dõi vận tải (ADS-B Exchange theo dõi máy bay, Marine Traffic theo dõi tàu, VIN decoder), điều tra darknet (Ahmia.fi tìm kiếm Tor, ransomwatch), mạng xã hội mở rộng (Reddit, Instagram, TikTok, Telegram), tra cứu người (TruePeopleSearch, IDCrawl), 11 mẫu Google mega-dork bao phủ 73 domain.

**Mới trong v2.1:** Trực quan hóa đường tấn công (`/cti-expert /render threat-path`), bề mặt tấn công (`/cti-expert /render attack-surface`), xuất IOC STIX 2.1 (`/cti-expert /report ioc`), theo dõi rủi ro theo thời gian (`/cti-expert /drift`), ảnh chụp Wayback (`/cti-expert /snapshots`, `/cti-expert /diff`), hướng dẫn người mới (`/cti-expert /onboard`), giải thích phát hiện (`/cti-expert /clarify`), phân tích khoảng trống (`/cti-expert /blind-spots`), kiểm tra nguồn (`/cti-expert /source-check`), so sánh phiên (`/cti-expert /workspace diff`), điểm chất lượng (`/cti-expert /quality`), thang độ tin cậy nguồn A-F, 4 loại thực thể mới.

**Khả năng cốt lõi:** Trinh sát đa vector trên mọi loại mục tiêu (cá nhân, tên miền, tổ chức, tên người dùng, email, IP, WiFi) với xác thực phát hiện tự động, chấm điểm rủi ro phơi bày, và báo cáo tình báo có cấu trúc ở nhiều định dạng.

**Quy trình:** Vòng đời AEAD — Thu thập dữ liệu thô &rarr; Làm giàu bằng mở rộng pivot &rarr; Đánh giá phát hiện &rarr; Phân phối báo cáo có cấu trúc (Markdown + Word với biểu đồ, sơ đồ, định dạng chuyên nghiệp).

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
> CTI Expert **chạy nhiều tác vụ thực thi**: chạy `uv`/Python, cài công cụ OSINT, ghi báo cáo `.md`/`.docx`/`.json`, truy cập nhiều trang web bên ngoài, và lưu workspace vụ việc. Điều quan trọng là **shell cục bộ thật + file lưu bền + mạng không bị chặn** — **CLI hoặc app desktop cục bộ** cho bạn điều đó; còn **sandbox đám mây tạm thời thì không**. Điều này áp dụng cho cả **Claude** lẫn **Codex**.

| Môi trường | Chạy điều tra | Lý do |
|---|---|---|
| **Claude Code CLI** · **Codex CLI** | ✅ **Tốt nhất** | Shell thật, lưu bền, tác vụ nền, mạng mở — đúng thứ skill cần |
| **Claude Code Desktop** · **Tiện ích IDE Codex** | ✅ Rất tốt | Cùng khả năng thực thi cục bộ; đọc báo cáo, biểu đồ, sơ đồ thoải mái nhất |
| **claude.ai/code (web)** · **Codex cloud / ChatGPT web** | ⚠️ Hạn chế | Suy luận phân tích & tạo truy vấn vẫn chạy, nhưng file không lưu vào ổ đĩa của bạn và mạng ra ngoài thường bị giới hạn |

> [!TIP]
> **Chạy điều tra trong CLI** (Claude Code hoặc Codex); mở file `.docx`/báo cáo trong cửa sổ Desktop/IDE nếu bạn thích đọc ở đó. Chỉ dùng môi trường web/đám mây cho phần suy luận phân tích, không dùng cho recon nặng về thực thi.

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
| *(không có)* | Python packages, whois, dig, jq, exiftool, maigret, sherlock, holehe, h8mail, theHarvester, trufflehog, waymore, xeuledoc, agentflow | ~50 MB |
| `--headless` | Scrapling StealthyFetcher + DynamicFetcher + Chromium | +200 MB |
| `--go` | subfinder, amass, gau, gitleaks, httpx, phoneinfoga | +150 MB |
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
   | **macOS** | Mở **Finder** &rarr; Nhấn **Cmd + Shift + G** &rarr; Nhập `~/.claude/skills/` &rarr; Nhấn **Go** |
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
/cti-expert /exposure domain.com                # Điểm rủi ro tổng hợp (0-100)
/cti-expert /report                             # Báo cáo kỹ thuật INTSUM
/cti-expert /workspace save                     # Lưu workspace + tự động tạo .docx
```

---

### Tính năng theo lĩnh vực

| Lĩnh vực | Khả năng |
|-----------|----------|
| **Danh tính & Con người** | Tra cứu cá nhân (50+ điểm dữ liệu), điều tra số điện thoại, email chuyên sâu, liệt kê tên người dùng (3000+ nền tảng), dấu vết nhà phát triển GitHub |
| **Tên miền & Hạ tầng** | Liệt kê subdomain, fingerprint kỹ thuật, pháp y DNS, phân tích lưu lượng |
| **Phân tích & Xác minh** | Xác minh hình ảnh, pháp y metadata, pháp y web, cơ sở dữ liệu rò rỉ |
| **WiFi & Định vị** | Định vị WiFi qua Wigle.net, định vị nâng cao (W3W, Plus Codes, MGRS) |
| **Kiểm tra bảo mật** | Kiểm tra đám mây (AWS/GCP/Azure), kiểm tra OWASP, kiểm tra dependency, kiểm tra prompt injection |
| **Báo cáo & Xuất** | Báo cáo Markdown, DOCX với biểu đồ, workspace case, định dạng chuyên nghiệp |

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
| **Theo dõi vận tải** | [ADS-B Exchange](https://www.adsbexchange.com) · [Flightradar24](https://www.flightradar24.com) · [MarineTraffic](https://www.marinetraffic.com) · [VesselFinder](https://www.vesselfinder.com) |
| **Darknet** | [Ahmia](https://ahmia.fi) · [OnionSearch](https://github.com/megadose/OnionSearch) · [ransomwatch](https://github.com/joshhighet/ransomwatch) |
| **Đám mây & tài liệu** | [MSFTRecon](https://github.com/Arcanum-Sec/msftrecon) · [Xeuledoc](https://github.com/Malfrats/xeuledoc) · [oletools](https://github.com/decalage2/oletools) · [poppler](https://poppler.freedesktop.org) · [qpdf](https://github.com/qpdf/qpdf) · [mat2](https://0xacab.org/jvoisin/mat2) · [The Sleuth Kit](https://www.sleuthkit.org) |
| **Lưu trữ web** | [Internet Archive — Wayback](https://web.archive.org) · [Waymore](https://github.com/xnl-h4ck3r/waymore) |
| **Báo cáo & tiện ích** | [pandoc](https://pandoc.org) · [python-docx](https://github.com/python-openxml/python-docx) · [Matplotlib](https://matplotlib.org) · [NetworkX](https://networkx.org) · [jq](https://jqlang.github.io/jq/) · [ASN](https://github.com/nitefood/asn) |
| **Tiêu chuẩn & khuôn khổ** | [OWASP](https://owasp.org) · [MITRE ATT&CK](https://attack.mitre.org) · [STIX 2.1 (OASIS)](https://oasis-open.github.io/cti-documentation/) · [NIST SP 800-61](https://csrc.nist.gov/pubs/sp/800/61/r2/final) · [CWE](https://cwe.mitre.org) |

> Chúng tôi nên ghi nhận thêm dự án nào, hoặc bạn muốn thay đổi/gỡ tên dự án của mình? Hãy mở issue hoặc PR — chúng tôi sẽ sửa ngay. 💙

---

**Tác giả:** [Hieu Ngo](https://chongluadao.vn) &bull; [hieu.ngo@chongluadao.vn](mailto:hieu.ngo@chongluadao.vn) &bull; **Phiên bản:** 2.4 &bull; **Giấy phép:** MIT
