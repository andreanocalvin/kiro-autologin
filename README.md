# Kiro Auto-Login for 9router

Tool otomatis untuk login Kiro via Google SSO, capture token, dan simpan ke 9router SQLite DB.
Reverse-engineered dari 9router v0.4.71 + Kiro auth flow.

## ✨ Features

- **Google SSO** auto-login (email → password → consent, multi-language)
- **Batch mode** — login banyak akun sekaligus dari file
- **Concurrent processing** — beberapa browser jalan bareng (1-5)
- **Headless mode** — browser invisible untuk automation cepat
- **Skip existing** — auto-skip akun yang sudah ada di 9router DB
- **Consent handler** — otomatis handle semua consent screens:
  - Kiro "Sign in to Kiro" → Continue
  - Google "I understand" / "Saya mengerti"
  - "Continue" / "Lanjutkan" / "Allow"
  - OAuth scope consent
- **kiro:// protocol interception** — triple fallback (JS injection + response listener + URL polling)
- **Private network blocking** — block akses ke local network (10.x, 192.168.x, dll)
- **Interactive mode** — preview akun + toggle headless + confirm sebelum jalan
- **Test mode** — simulate tanpa save ke DB, print JSON payload
- **PKCE + nonce** — secure auth flow (RFC 7636)

## 📋 Requirements

| Requirement | Minimum |
|-------------|---------|
| **Windows** | 10 / 11 |
| **Python** | 3.10+ |
| **9router** | v0.4.71+ (for DB save) |

## 🚀 Quick Start

### 1. Install

```bash
# Clone atau download repo ini, lalu:
cd kiro-autologin

# Auto-install dependencies
setup.bat
```

Atau manual:
```bash
pip install -r requirements.txt
playwright install chromium
```

### 2. Pakai

**Single account:**
```bash
python kiro_autologin.py email@gmail.com:password123
```

**Batch dari file:**
```bash
python kiro_autologin.py --batch accounts.txt --headless
```

**Interactive (double-click `run-batch.bat`):**

```
  ===================================================
     Kiro Auto-Login for 9router - Batch Mode
  ===================================================

  [i] Found 5 account(s) in accounts.txt

  ---------------------------------------------------
    email1@gmail.com
    email2@gmail.com
    ...
  ---------------------------------------------------

  Headless mode? (browser invisible) [y/N]: y
  Concurrent browsers (1-5) [1]: 2

  +--------------------------------------+
  |  Accounts:   5
  |  Browser:    Headless
  |  Concurrent: 2
  |  Save to:    9router DB
  +--------------------------------------+

  Start login? [Y/n]:
```

## 📁 File Structure

```
kiro-autologin/
├── kiro_autologin.py       ← Script utama
├── setup.bat               ← Auto-installer (Python + Playwright)
├── run-batch.bat           ← Interactive batch launcher (double-click)
├── accounts.txt            ← Akun kamu (jangan di-commit!)
├── accounts.txt.example    ← Template (safe to commit)
├── requirements.txt        ← Python dependencies
├── .gitignore
└── README.md
```

## 📝 Format accounts.txt

```
# Komentar diawali # (di-skip)
# Baris kosong juga di-skip

email1@gmail.com:password1
email2@gmail.com:password2
email3@workspace.com:password3
```

## 🔧 CLI Options

```
usage: kiro_autologin.py [-h] [--batch FILE] [--headless]
                          [--concurrent N] [--test] [--debug]
                          [--interactive] [--no-skip-existing]
                          [accounts ...]

positional arguments:
  accounts              email:password pairs

options:
  -b, --batch FILE      Read accounts from file
  --headless            Run browser in headless mode
  -c, --concurrent N    Concurrent browser sessions (1-5, default: 1)
  -t, --test            Test mode (don't save to DB, print JSON)
  -d, --debug           Debug output
  -i, --interactive     Interactive prompts before running
  --no-skip-existing    Re-login even if account exists in 9router
```

## 🛡️ Safety Features

### Skip Existing Accounts
By default, akun yang sudah ada di 9router DB **di-skip otomatis**.
Gunakan `--no-skip-existing` untuk force re-login (misal token expired).

### Test Mode
`--test` flag: jalankan login tanpa save ke DB. Print JSON payload yang akan disimpan.
Berguna untuk testing akun baru atau verifikasi format data.

### Private Network Blocking
Block semua request ke local/private network IPs (10.x, 172.16-31.x, 192.168.x, localhost).
Mencegah browser "local network access" prompts yang block automation.

## 🔄 How It Works

```
1. PKCE         → Generate code_verifier + code_challenge
2. Navigate     → Kiro social login URL (Google SSO)
3. Google SSO   → Auto-fill email + password + handle consent
4. Redirect     → Intercept kiro:// redirect (triple fallback)
5. Token        → Exchange auth code → accessToken + refreshToken
6. Save         → Upsert ke 9router SQLite DB
```

### Kiro Auth Endpoints

| Endpoint | URL |
|----------|-----|
| **Login** | `https://prod.us-east-1.auth.desktop.kiro.dev/login` |
| **Token Exchange** | `POST .../oauth/token` |
| **Token Refresh** | `POST .../refreshToken` |
| **Redirect** | `kiro://kiro.kiroAgent/authenticate-success` |

### 9router DB Schema

Saved to `providerConnections` table:
- `provider`: `kiro`
- `authType`: `oauth`
- `data` (JSON): accessToken, refreshToken, expiresAt, expiresIn, profileArn, authMethod

## ⚡ Performance

| Mode | Per Account | 10 Accounts |
|------|------------|-------------|
| Visible, concurrent=1 | ~18s | ~3 min |
| Headless, concurrent=1 | ~18s | ~3 min |
| Visible, concurrent=2 | ~20s each | ~1.5 min |
| Headless, concurrent=2 | ~20s each | ~1.5 min |

> ⚠️ Concurrent > 2 bisa trigger Google rate-limiting. Recommended: **concurrent 1-2**.

## 🐛 Troubleshooting

**Browser stuck / timeout:**
- Coba `--concurrent 1` (hindari rate-limit)
- Pastikan koneksi internet stabil

**Google CAPTCHA / 2FA:**
- Pakai browser visible (tanpa `--headless`) biar bisa handle manual
- Atau disable 2FA sementara di akun Google

**Consent screen stuck:**
- Script auto-handle kebanyakan consent screen
- Kalau ada yang baru, submit issue dengan screenshot (`--debug` flag)

**Token tidak datang:**
- Pastikan 9router sedang jalan (untuk DB save)
- Cek `--test` mode untuk verifikasi token capture
- Pastikan 9router versi >= 0.4.71

**kiro:// protocol dialog:**
- Sudah di-handle otomatis via JS injection + Chrome flags
- Kalau masih muncul, pastikan Chrome/Chromium up-to-date

## 📄 License

MIT — pakai sesuka hati.

## ⚠️ Disclaimer

Tool ini untuk penggunaan personal. Gunakan responsibly.
Penulis tidak bertanggung jawab atas penyalahgunaan tool ini.
