# fsociety bot

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

## Comandos
Análisis: `/whois /dns /subdominios /ip /headers /ssl /tech` · Seguridad: `/password /filtrado /link` + metadatos/limpieza de imágenes · CTF: `/b64 /hex /url /rot13 /hash /hashid /jwt /pass /quote`.

Variables opcionales: `HIBP_API_KEY` (para `/filtrado`), `VT_API_KEY` (para `/link`).
