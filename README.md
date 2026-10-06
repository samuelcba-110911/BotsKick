# BotsKick

Bots de Telegram en Python (`python-telegram-bot`), desplegados en Railway.

## Local
```
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export TELEGRAM_BOT_TOKEN=...   # token de @BotFather
python bot.py
```

## Railway
1. Crear proyecto en Railway y conectar este repo.
2. Añadir la variable `TELEGRAM_BOT_TOKEN`.
3. Deploy: corre como worker con `python bot.py` (polling, no necesita puerto ni dominio).
