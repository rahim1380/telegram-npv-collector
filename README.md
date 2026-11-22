# Telegram → NapsternetV subscription collector

This starter project collects configuration URI strings posted in the **last 24 hours**
by the seven public Telegram channels specified by the user, appends new unique URIs
to a persistent archive, and writes a Base64 subscription file.

## Included sources
- @MARAMBASHI
- @v2ray_Mammad
- @Gp_config
- @levconnect
- @iranping24
- @Configvibes
- @JOFAVPN

## Important behavior
- Manual execution only (GitHub Actions `workflow_dispatch`).
- No ping test and no VPN connection test.
- Historical configs are retained; newly found exact duplicate strings are skipped.
- The script only collects visible `vless://`, `vmess://`, `trojan://`, and `ss://` URIs.
- It does not decode arbitrary obfuscated text, images, QR codes, or external subscription URLs.
- Public Telegram preview pages can change or limit how many posts are visible. Review the run log if a channel fails.

## Setup (one-time)
1. Create a **private or public** GitHub repository.
2. Upload all files in this folder to the repository's main branch, preserving `.github/workflows/update.yml`.
3. Open the repository's **Actions** tab and enable workflows if GitHub asks.
4. Choose **Manual Telegram config update** → **Run workflow**.
5. After a successful run, `subscription.txt` will be updated in the repository.

## Stable subscription URL
If the repository is public, the raw URL is:

`https://raw.githubusercontent.com/USERNAME/REPOSITORY/main/subscription.txt`

Replace `USERNAME` and `REPOSITORY` with the actual GitHub account and repository names.
For a private repository, this raw URL generally cannot be used as a public subscription URL;
use a private hosting solution that supports authenticated access instead.

Add the raw URL to NapsternetV's subscription/import-by-URL section, if the app accepts
Base64 subscriptions in that format. Client compatibility can vary by version.

## Local run (optional)
```bash
pip install -r requirements.txt
python collector.py
```

Use only public channels you are allowed to access. Treat imported proxy configurations
as untrusted: they route network traffic through third-party servers.
