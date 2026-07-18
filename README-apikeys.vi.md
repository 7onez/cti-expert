# cti-expert — Web Pivot & API Key trả phí

**Ngôn ngữ:** [English](README-apikeys.md) · Tiếng Việt · [中文](README-apikeys.zh-CN.md)

Hướng dẫn dùng **`/webpivot`** (pivot hạ tầng web) và **`/apikeys`** (quản lý API key trả phí).
cti-expert **mặc định chạy hoàn toàn không cần key / miễn phí** — API key trả phí chỉ để *nâng cấp
thêm*, và không có key thì mọi thứ vẫn chạy bình thường.

---

## Tóm tắt nhanh

```bash
AK=~/.claude/skills/cti-expert/scripts/apikeys/apikeys.py

uv run "$AK"                              # status — đang cấu hình những key nào (không cần key để bắt đầu)
uv run "$AK" set censys censys_pat_XXXX  # thêm một key trả phí (ví dụ Censys)
uv run "$AK" test censys                 # 🟢 hợp lệ / 🔴 sai / 🟠 lỗi
uv run "$AK" unlocks                      # key vừa thêm mở khoá được gì

/webpivot https://trang-nghi-ngo.top     # dùng — key được áp dụng tự động
```

---

## 1. Key được lưu ở đâu? (chỉ MỘT file duy nhất)

cti-expert chỉ có **đúng một** file chứa key:

```
~/.claude/skills/cti-expert/.env          ( = $SKILL_DIR/.env )
```

- File này **được tạo tự động** ngay lần đầu bạn chạy `/apikeys set …` — **trước đó nó chưa tồn tại**
  (nên nếu chưa thấy file thì đó là bình thường).
- `chmod 600` + **đã gitignore** — không bao giờ bị commit lên git.

**Các file `.env` khác mà bạn thấy KHÔNG phải là nơi lưu key của cti-expert** — bỏ qua chúng. Đó chỉ
là file mẫu đi kèm trong các package *nguồn*:

| File bạn thấy | Thực chất là gì |
|---|---|
| `WebPivot/.env.example`, `quarry/.env.example` | File mẫu trong **repo gốc** (chỉ để tham khảo) |
| `quarry/.env.docker.example` | File mẫu cho Docker của quarry |
| `scripts/webpivot/.env` (nếu bạn có tạo) | Đường dẫn cũ để tương thích ngược; **`.env` ở gốc skill mới là chuẩn** |

**Thứ tự ưu tiên đọc key ở mọi nơi:** **biến môi trường → file `.env` của skill → chế độ không key.**
Biến môi trường luôn được ưu tiên hơn file (tiện cho máy dùng chung / CI).

---

## 2. Hai cách thêm hoặc sửa key

### A) Dùng lệnh `/apikeys` (khuyến nghị)

```bash
AK=~/.claude/skills/cti-expert/scripts/apikeys/apikeys.py

# Censys cần Personal Access Token, kèm Org ID (không bắt buộc):
uv run "$AK" set censys censys_pat_XXXXXXXXXXXX     # nhận id dịch vụ ("censys")…
uv run "$AK" set CENSYS_ORG_ID 1234-5678-org        # …hoặc đúng tên ENV_VAR
uv run "$AK" set CENSYS_API_SECRET censys_pat_XXXX  # (tên thay thế cũng chấp nhận)

# Để key không lộ trong lịch sử shell — truyền qua stdin:
printf %s "$MYKEY" | uv run "$AK" set censys

uv run "$AK" unset censys                            # xoá một key
```

### B) Sửa trực tiếp file `.env`

Skill có sẵn file **[`.env.example`](.env.example)** liệt kê mọi key được hỗ trợ (đang để trống), mỗi
key kèm chú thích nó mở khoá gì và lấy ở đâu. Copy nó rồi điền các key bạn có:

```bash
cp .env.example .env       # chạy tại thư mục gốc của skill (~/.claude/skills/cti-expert)
```

Hoặc mở `~/.claude/skills/cti-expert/.env` bằng trình soạn thảo bất kỳ và thêm các dòng `KEY=VALUE`:

```dotenv
# cti-expert API keys — chmod 600, gitignored. Never commit.
CENSYS_API_KEY=censys_pat_XXXXXXXXXXXX
CENSYS_ORG_ID=1234-5678-org
SHODAN_API_KEY=key_shodan_cua_ban
```

Cả hai cách đều ghi vào **cùng một** file. Chạy `uv run "$AK" status` để kiểm tra key đã được nhận.

---

## 3. Mỗi key mở khoá được gì?

Chạy `uv run "$AK" status --all` để xem toàn bộ danh mục (17 dịch vụ) hoặc xem
[`handbook/api-keys.md`](handbook/api-keys.md). Bản miễn phí/không key đã bao phủ phần lớn — key chỉ
mở thêm mức cao hơn hoặc tra ngược:

| Dịch vụ | Biến môi trường | Mở khoá |
|---|---|---|
| Shodan | `SHODAN_API_KEY` | `/webpivot`: tra ngược favicon **mmh3** → host; `/cert-pivot`: tra ngược **vân tay chứng chỉ TLS** → host |
| Censys | `CENSYS_API_KEY` (hoặc `CENSYS_API_ID`+`CENSYS_API_SECRET`) | `/webpivot`: tra ngược favicon **MD5**; `/cert-pivot`: **fingerprint_sha256** của chứng chỉ → host |
| FOFA | `FOFA_KEY` (+`FOFA_EMAIL`) | `/webpivot`: tra ngược `icon_hash` + body tracker |
| DNSLytics | `DNSLYTICS_API_KEY` | `/webpivot`: ID AdSense/GA → **các domain anh em** |
| SecurityTrails | `SECURITYTRAILS_API_KEY` | passive DNS, subdomain, lịch sử DNS/WHOIS |
| urlscan.io PRO | `URLSCAN_API_KEY` | tìm nội dung DOM đã xác thực |
| WhoisXML | `WHOISXML_API_KEY` | WHOIS hiện tại + lịch sử + **reverse WHOIS** |
| Blockchair | `BLOCKCHAIR_API_KEY` | `/crypto-balance`: **dòng tiền vào/ra trọn đời** trên nhiều chain (không key vẫn có số dư + số tx) |
| Subscan | `SUBSCAN_API_KEY` | `/crypto-balance`: tra cứu **Polkadot (DOT)** với hạn mức cao hơn |
| Hudson Rock / IntelX / ChongLuaDao | `HUDSONROCK_API_KEY` / `INTELX_API_KEY` / `CHONGLUADAO_API_KEY` | dữ liệu breach / leak / darknet; ChongLuaDao còn phục vụ phát hiện email dùng-một-lần cho `/email-hygiene` |
| GitHub · SerpAPI · BrightData · CertSpotter · ZoneCruncher | … | tra code · tự động dork · CT · liveDNS |

---

## 4. Workflow nào dùng các key này? (và cơ chế dự phòng không key)

Key được gắn vào bước **`enrich_live()`** trong `pivot_extract.py`, dùng bởi **`/webpivot`** (và bởi
**`/case`** khi mục tiêu là domain/URL):

1. **Trích xuất** artifact từ trang — hash favicon, ID GA/GTM/AdSense, ví crypto, token SaaS, email,
   vân tay DOM.
2. **Nền tảng không key — LUÔN chạy:** crt.sh (certificate transparency), passive DNS qua
   HackerTarget, urlscan ẩn danh.
3. **Trả phí — chỉ với key bạn đã đặt:** Shodan (favicon mmh3 + vân tay chứng chỉ → host), Censys
   (favicon MD5 + cert SHA-256), FOFA, DNSLytics (GA/AdSense → domain anh em), SecurityTrails
   (passive DNS), urlscan-PRO, WhoisXML, Blockchair/Subscan (dòng tiền ví cho `/crypto-balance`). Mỗi
   kết quả được gắn vào pivot dưới dạng `live_results` và hiển thị khi chạy `--leads`.

> **Công cụ tương quan mới không cần key:** `/rank-relations` (chấm điểm quan hệ cùng nhà vận hành +
> danh sách chặn nhiễu), `/cert-pivot` (tên miền SAN của chứng chỉ), `/pivot-suggest`,
> `/crypto-balance`, `/email-hygiene`, `/sensitive-paths`. Các key ở trên chỉ *tăng cường* thêm.

> **Nếu không đặt key nào, mọi thứ vẫn chạy y như trước — không key / miễn phí.** Mỗi bước trả phí bị
> bỏ qua khi thiếu key, và mọi lỗi (sai key, hết quota) chỉ hiện một dòng ghi chú — không bao giờ làm
> hỏng lần chạy.

---

## 5. `/case` có tự động chạy webpivot không?

**Có — với mục tiêu là domain / URL.** `/case example.com` sẽ chạy `/webpivot` trong pha **Acquire**:

- **Mặc định không key** (crt.sh + passive DNS + urlscan ẩn danh).
- **Tự động nâng cấp** khi bạn đã đặt key trả phí qua `/apikeys`.
- **Không** chạy với mục tiêu `username` / `phone` / con người.
- Vì `/webpivot` có thể truy cập trực tiếp mục tiêu, nên với **hạ tầng của kẻ xấu**, nó ưu tiên thu
  thập thụ động (urlscan / Wayback) — xem [`techniques/web-pivot.md`](techniques/web-pivot.md).

Bạn cũng có thể chạy riêng: `/webpivot https://muc-tieu.top`.

---

## 6. Sơ đồ workflow

**Luồng `/webpivot` + API key trả phí** — key được gắn vào pivot như thế nào:

![Luồng /webpivot + API key tra phi cua cti-expert](assets/workflow-apikeys.png)

**Toàn bộ pipeline `/case` (AEAD)** — `/webpivot` và các key nằm ở đâu trong một vụ việc đầy đủ:

![Pipeline /case cua cti-expert](assets/workflow-case.png)

---

## 7. Bảo mật

- **Không bao giờ commit `.env`** — đã được gitignore (`.env` + `scripts/**/.env`).
- Trên máy dùng chung / CI, hãy ưu tiên **biến môi trường** (ghi đè file và không để lại gì trên đĩa).
- `set <dịch_vụ> <KEY>` sẽ lưu key vào lịch sử shell — hãy dùng dạng **stdin**
  (`printf %s "$KEY" | uv run "$AK" set censys`) để tránh.
- Kết quả của `/apikeys` **luôn che** giá trị key (chỉ hiện độ dài + 2 ký tự cuối).

---

## 8. Kiểm tra

```bash
AK=~/.claude/skills/cti-expert/scripts/apikeys/apikeys.py
uv run "$AK" status         # đang đặt những key nào + mở khoá được gì
uv run "$AK" test censys    # kiểm tra trực tiếp: 🟢 hợp lệ / 🔴 sai / 🟠 lỗi / ⚪ không có bài test
uv run "$AK" path           # vị trí file .env + quyền
```

---

## Ghi công

- **WebPivot** — bộ công cụ `/webpivot` trong `scripts/webpivot/` (trích favicon/tracker/ví, Wayback-GA, reverse-WHOIS, gom cụm đồ thị) — của **[Zeroska](https://github.com/Zeroska)**, được tích hợp vào cti-expert.
- **cti-expert** bởi Hieu Ngo — [chongluadao.vn](https://chongluadao.vn).
