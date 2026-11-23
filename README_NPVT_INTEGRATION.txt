# NPVT + Telegram subscription integration

This update keeps the existing Telegram collector and adds NPVT file importing.

## Add an NPVT file
1. Open the repository on GitHub.
2. Open the `npvt_inputs` folder.
3. Upload one or more `.npvt` files.
4. Commit the upload. The workflow starts automatically because the commit changed `npvt_inputs/**`.

You can also run **Automatic Telegram Config Update** manually from the Actions tab.

## Result
- Telegram collector keeps its existing behavior: only configs seen in the last 24 hours are included.
- Decoded NPVT links are stored persistently in `data/npvt_configs.json`.
- Both sources are deduplicated and merged into the existing Base64 `subscription.txt`.
- Entries in `data/blacklist.txt` are excluded from both sources.
- No ping or VPN connection test is performed.

NPVT files are decoded with the included `npvt_decoder.py`. The public reference tables are downloaded automatically by the workflow.
