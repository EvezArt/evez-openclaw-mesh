# EVEZ OpenClaw Mesh

Decentralized nonlocal + local network of OpenClaw instances with EVEZ-OS spine.
Tests: 10/10 ✅ | Nodes: 3 | Gossip: active | Free models: 27+

## Quick start
```bash
./deploy.sh          # deploy all 3 nodes to Fly.io
python3 mesh_orchestrator.py test    # test all nodes
python3 mesh_orchestrator.py prompt "Hello mesh"
```

## Nodes
| ID | Fly App | URL |
|----|---------|-----|
| alpha | openclaws-qol4-a | https://openclaws-qol4-a.fly.dev |
| beta | openclaw-pfncdg | https://openclaw-pfncdg.fly.dev |
| brain | evez666 | https://evez666.fly.dev |

## Required GitHub Secrets for auto-deploy
```
FLY_API_TOKEN, GROQ_API_KEY, OPENROUTER_API_KEY, ANTHROPIC_API_KEY, GEMINI_API_KEY,
TELEGRAM_BOT_TOKEN, DISCORD_BOT_TOKEN, SLACK_BOT_TOKEN, CLAUDE_AI_SESSION_KEY
```
See `.env.template` for full list of supported keys (37 providers).
