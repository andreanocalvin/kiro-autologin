# Kiro Auto-Login for 9router

Automates Kiro login via Google SSO, captures tokens, and saves to 9router SQLite DB.

## Flow

```
Google SSO → Kiro Auth → kiro:// redirect → Token Exchange → 9router DB
```

1. Generate PKCE pair (code_verifier + code_challenge)
2. Navigate Playwright to Kiro social login URL (Google SSO)
3. Auto-fill Google credentials + handle consent screens
4. Intercept `kiro://` redirect → extract auth code
5. Exchange code → tokens (accessToken, refreshToken, profileArn)
6. Save to 9router SQLite DB (`providerConnections` table)

## Prerequisites

```bash
pip install playwright aiohttp
playwright install chromium
```

## Usage

```bash
# Single account
python kiro_autologin.py user@gmail.com:password

# Test mode (no DB save)
python kiro_autologin.py --test user@gmail.com:password

# Batch from file
python kiro_autologin.py --batch accounts.txt

# Batch + headless + concurrent
python kiro_autologin.py --batch accounts.txt --headless --concurrent 3

# Debug mode
DEBUG=true python kiro_autologin.py --test user@gmail.com:password
```

## Accounts File Format

```
# accounts.txt
user1@gmail.com:password1
user2@gmail.com:password2
# This is a comment
user3@gmail.com:password3
```

## CLI Options

| Argument | Short | Description |
|----------|-------|-------------|
| `accounts` | (positional) | `email:password` pairs |
| `--batch FILE` | `-b` | Read accounts from file |
| `--test` | `-t` | Test mode: don't save to DB |
| `--headless` | | Run browser in headless mode |
| `--concurrent N` | `-c` | Concurrent browser sessions (default: 1) |
| `--debug` | `-d` | Enable debug output |
| `--no-skip-existing` | | Re-login accounts already in DB |

## How It Works

### Kiro Auth (reverse-engineered from 9router)

- **Login URL**: `https://prod.us-east-1.auth.desktop.kiro.dev/login`
- **Token Exchange**: `POST https://prod.us-east-1.auth.desktop.kiro.dev/oauth/token`
- **Token Refresh**: `POST https://prod.us-east-1.auth.desktop.kiro.dev/refreshToken`
- **Redirect URI**: `kiro://kiro.kiroAgent/authenticate-success`

### 9router DB Schema

Saved to `providerConnections` table with:
- `provider`: `kiro`
- `authType`: `oauth`
- `data` (JSON): accessToken, refreshToken, expiresAt, profileArn, authMethod

## License

MIT
