# Media Evidence Analysis — Vision & Video

Analyze the **content** of image, document, and audio/video evidence — not just its
file metadata. A screenshot, a photo of a storefront, a leaked PDF, or a Telegram
voice note is a **pivot node**: the text, faces, logos, landmarks, GPS cues, and
spoken names inside it become new seeds that re-enter the Enrich pivot loop.

**Native & standalone — no AgentKit / sibling-skill dependency.** A bare clone of
`cti-expert` on a fresh VPS works: the vision layer is the standalone
[`multix`](https://github.com/mrgoonie/multix-cli) CLI (run via `npx`, nothing to
install globally); the media layer is `ffmpeg` / `imagemagick` / `rmbg`, provisioned
by the skill's own Tool Auto-Install Policy.

> **Doctrine (same as every collector):** present → use; absent → log a collection
> gap and fall back to metadata-only (`exiftool`/EXIF). A missing key or binary is
> **never** a case blocker.

---

## 1. Prerequisites

| Layer | Tool | Requirement | Install |
|-------|------|-------------|---------|
| Vision / transcription | `multix` (Gemini) | Node.js 20+ · `GEMINI_API_KEY` | none — `npx` (see below) |
| Video/audio preprocess | `ffmpeg` | system binary | Auto-Install Policy |
| Image preprocess | `imagemagick` (`magick` on IM7; `convert` on IM6/apt) | system binary | Auto-Install Policy |
| Background removal | `rmbg` | Node CLI | `npm i -g rmbg-cli` |
| Vision fallback (no key) | host agent (Claude/Codex) + `tesseract` | multimodal image read + local OCR | none / Auto-Install Policy |
| Transcription fallback (no key) | local Whisper (`whisper-ctranslate2`) | offline ASR | `uv tool install whisper-ctranslate2` (optional) |

**Key resolution** — get a key at <https://aistudio.google.com/apikey>. The skill's
canonical store is `$SKILL_DIR/.env` (chmod-600, gitignored), managed by `/apikeys`
and registered as service `gemini`:

```bash
/apikeys set gemini <KEY>          # writes GEMINI_API_KEY to $SKILL_DIR/.env
/apikeys status                    # confirm it is set (masked)
```

`multix` reads `GEMINI_API_KEY` from the **process env** (or `~/.multix/.env`), *not*
from `$SKILL_DIR/.env` — so export the skill store into the env before invoking it:

```bash
set -a; [ -f "$SKILL_DIR/.env" ] && . "$SKILL_DIR/.env"; set +a   # $SKILL_DIR/.env -> env
export GEMINI_API_KEY="…"                                        # or set directly (shell / CI)
```

**Pre-warm offline** — `npx --prefer-online` checks the npm registry each run. In a
network-restricted session, warm the cache while network is available:

```bash
npx --yes --prefer-online --package=@mrgoonie/multix@latest -- multix --version
```

The `npx --yes --prefer-online --package=@mrgoonie/multix@latest -- multix` prefix is
written in full below; alias it locally if you like (`MX="npx --yes … -- multix"`).

---

## 2. Images / screenshots / documents → vision

### OCR + scene read (geolocation, correlation)

```bash
npx --yes --prefer-online --package=@mrgoonie/multix@latest -- multix gemini analyze \
  --files EVIDENCE.png \
  --prompt "OCR every piece of text verbatim. Then describe: visible signage, shop/brand names, street names, license plates, landmarks, language/script, and any faces. List location cues for geolocation." \
  --format markdown --output vision.md
```

> **No Gemini key? Keyless fallback.** Have the **host agent read the image directly** — Claude Code / Codex are multimodal: open `EVIDENCE.png` with the Read tool and do the OCR + sign/landmark/logo/face description in-session (no key, no upload). For dense/bulk OCR add `tesseract EVIDENCE.png out -l vie+chi_sim+eng && cat out.txt` (VN + simplified-Chinese + English — cti-expert's usual targets). Both feed the same `indicators[]`; a `GEMINI_API_KEY` only upgrades scene-reading quality and batch throughput. Tag these `[vision-local]`.

Use for: reading a sign/menu/plate in a photo (feeds `fx-geolocation.md` /
`advanced-geolocation-techniques.md`), OCR of a screenshot a naive parser can't reach
(a Telegram bio, a chat screenshot), describing a logo/face for correlation
(complements `image-forensics-and-face-search.md`, `fx-image-verification.md`).

### Structured extraction (selectors as JSON)

```bash
npx --yes --prefer-online --package=@mrgoonie/multix@latest -- multix gemini extract \
  --files EVIDENCE.png \
  --prompt "Extract as JSON arrays: social_handles, emails, phones, crypto_wallets, ibans, org_names, urls visible in the image." \
  --format json --output vision.json
```

The JSON keys map straight to case-schema `indicators[]` — merge them like any other
harvested selector.

### Document → Markdown (leaked PDFs / office docs)

```bash
npx --yes --prefer-online --package=@mrgoonie/multix@latest -- multix doc convert \
  --input leaked.pdf --output leaked.md
```

Complements `fx-document-forensics.md` (which handles metadata/authorship): `doc
convert` gets the **body text** into a greppable form for selector extraction.

---

## 3. Video / audio → preprocess with FFmpeg, then vision

Gemini takes images and short A/V, but the reliable OSINT pattern is **decompose
first**: pull keyframes for scene/OCR analysis and the audio track for transcription.

### Keyframes → scene/OCR analysis

```bash
# 1 frame every 5 seconds
ffmpeg -i clip.mp4 -vf "fps=1/5" frame_%03d.png
# scene-change frames only (dedupes static footage)
ffmpeg -i clip.mp4 -vf "select='gt(scene,0.4)'" -vsync vfr scene_%03d.png
```

Then run each frame through §2 `analyze`/`extract`.

### Audio → timestamped transcript

```bash
ffmpeg -i clip.mp4 -vn -c:a copy audio.m4a
npx --yes --prefer-online --package=@mrgoonie/multix@latest -- multix gemini transcribe \
  --files audio.m4a \
  --prompt "Transcript with timestamps; note language and any named people, orgs, places, handles." \
  --format markdown --output transcript.md
```

**No Gemini key? Local Whisper.** Transcribe offline after the same `ffmpeg` audio extraction — keyless, fully local:

```bash
whisper-ctranslate2 audio.m4a --model base --output_format srt --output_dir .   # offline; no key
```

Transcript lines use the standard form:

```text
[HH:MM:SS -> HH:MM:SS] transcript content
```

### Oversized media → split, process, combine

Provider input/duration limits apply. When a file exceeds the limit, segment with
FFmpeg, process each segment, then concatenate the outputs:

```bash
ffmpeg -i long.mp4 -c copy -map 0 -segment_time 600 -f segment part_%03d.mp4
```

### Image preprocessing (ImageMagick / RMBG)

```bash
IM="$(command -v magick || command -v convert)"            # IM7 -> magick; IM6 (apt) -> convert
"$IM" EVIDENCE.png -resize 2000x -quality 90 prepped.jpg   # normalize before upload
rmbg subject.jpg -m briaai -o cutout.png                     # isolate a face/subject
```

---

## 4. Feedback into the pivot loop

Everything recovered here is a **seed**, not a terminal finding:

- OCR'd / extracted **handles, emails, phones, wallets, IBANs, org names** → merge as
  `indicators[]` and pivot (`/username`, `/email-deep`, `/breach-deep`, `/iban`, …).
- **GPS / landmarks / signage** → `fx-geolocation.md` chain.
- **Transcribed names / places / orgs** → subject/entity nodes.
- **Faces / logos** → correlation candidates, **held pending corroboration** (a face
  or commodity logo match is moderate-strength at best — never auto-merge an operator
  link on it alone; see SKILL.md §Pivot priority ladder).

Tag each finding with its collection method: **`[vision]`** (multix/Gemini), **`[vision-local]`** (host-agent vision / `tesseract` / local Whisper — the keyless fallback), or **`[media]`** (ffmpeg/imagemagick preprocessing).

---

## 5. Model & provider discipline

`multix` owns the command syntax; the Gemini provider owns model IDs, limits, and
pricing. Do **not** hard-code a model as "latest/default" from this doc — when a
specific model is needed, resolve it live (`multix gemini --help`; provider docs) and
record it in the case notes for reproducibility. Core `analyze`/`extract`/`transcribe`
run on the CLI's current default model with no `--model` flag.

---

## 6. Failure UX

| Symptom | Handling |
|---------|----------|
| `GEMINI_API_KEY` missing | **Not a blocker** — fall back keyless: host-agent vision (Read the image in-session) for OCR + sign/landmark/logo/face read, `tesseract` for dense OCR, and local Whisper (`whisper-ctranslate2`) for A/V; only then `exiftool`/EXIF metadata. Tag `[vision-local]`. |
| Node < 20 / npx absent | Install Node 20+ (Auto-Install Policy) or log a gap and continue. |
| Offline / npm blocked | Pre-warm the cache first (§1); otherwise log a gap. |
| `ffmpeg` absent | Provision via Auto-Install Policy; else skip A/V decomposition and analyze the raw file if small enough. |
| Provider API error | Keep the full error (redact the key), fix auth/quota/params, retry once; else log a gap. |

Never claim a media tool ran when it didn't — record what was attempted and which rung of the chain (Gemini → host-agent vision → `tesseract`/Whisper → metadata) actually produced the result.
