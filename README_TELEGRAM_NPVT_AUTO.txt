# Automatic Telegram NPVT downloader

This patch adds automatic `.npvt` attachment downloading from the configured public Telegram channels.

## GitHub Actions secrets

The repository must contain these Actions secrets:

- `TELEGRAM_API_ID`
- `TELEGRAM_API_HASH`
- `TELEGRAM_SESSION`

The session value is the complete StringSession text from the local file
`%USERPROFILE%\.npvt-telegram\session_string.txt`. Never commit that file or print its contents.

## Behavior

- First run scans the latest 1,000 posts in each configured channel.
- Later runs scan only messages newer than the saved per-channel message ID.
- Only files whose Telegram document filename ends in `.npvt` are downloaded.
- Files are stored permanently in `npvt_inputs/` and then processed by the existing importer.
- SHA-256 hashes are stored permanently in `data/npvt_download_hashes.json` to prevent duplicate downloads.
- Recent download receipts are retained for 24 hours in `data/npvt_telegram_state.json`.
- The existing Telegram collector, NPVT decoder, archive, and Base64 subscription logic are retained.

## Apply

Copy `npvt_telegram_downloader.py`, replace `.github/workflows/update.yml` and
`requirements.txt` with the versions in this patch, then commit and push.
