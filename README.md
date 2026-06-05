# EVEZ OpenClaw Mesh

Decentralized nonlocal + local OpenClaw network with EVEZ-OS spine.
Test status: **13/13 PASS** | Groq llama-3.3-70b active | Gossip sync verified

## Quick Start
```bash
# Start mesh
GROQ_API_KEY=gsk_... BRAIN_ID=alpha BRAIN_PORT=8893 python3 mesh/brain.py &
GROQ_API_KEY=gsk_... BRAIN_ID=beta  BRAIN_PORT=8895 python3 mesh/brain.py &

# Start Telegram bot  
TELEGRAM_BOT_TOKEN=xxx python3 telegram_bot.py &

# Run tests
python3 tests/final_e2e_test.py
```

## Telegram Bot
**@YVY1Bot** — https://t.me/YVY1Bot
Commands: /status /prompt /alpha /beta /gossip /haiku

## Deploy to Fly.io
1. `fly tokens create deploy --expiry 8760h -o evez`
2. Add `FLY_API_TOKEN` to GitHub Secrets
3. Push to main → GitHub Actions auto-deploys

*Tests: 13/13 ✅ · Jun 5, 2026*
