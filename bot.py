import logging
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from exif import extract, format_report
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters

logging.basicConfig(
    format="%(asctime)s %(name)s %(levelname)s %(message)s", level=logging.INFO
)
log = logging.getLogger("fsociety")
MAX_BYTES = 20 * 1024 * 1024


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text("Hello, friend. Somos fsociety.\nUsa /help para ver comandos.")


async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text("/start - saludo\n/help - esta ayuda\n/ping - prueba\n\nEnvíame una foto COMO ARCHIVO (adjuntar > archivo) y te muestro sus metadatos EXIF.")


async def ping(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text("pong")


async def photo_warning(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "Telegram borra los metadatos de las fotos normales. "
        "Reenvíala como archivo: adjuntar (clip) > Archivo, sin comprimir."
    )


async def metadata(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    doc = update.message.document
    if doc.file_size and doc.file_size > MAX_BYTES:
        await update.message.reply_text("Archivo demasiado grande (máx. 20 MB).")
        return
    tg_file = await doc.get_file()
    data = bytes(await tg_file.download_as_bytearray())
    try:
        report = format_report(extract(data))
    except Exception:
        log.exception("No se pudo leer la imagen")
        await update.message.reply_text("No pude leer ese archivo como imagen.")
        return
    await update.message.reply_text(report)


async def echo(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(update.message.text)


class _Health(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args) -> None:
        pass


def start_health_server() -> None:
    """Render exige que los Web Services escuchen en $PORT; Railway no lo necesita."""
    port = os.environ.get("PORT")
    if port:
        server = HTTPServer(("0.0.0.0", int(port)), _Health)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        log.info("Health check en el puerto %s", port)


def main() -> None:
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    if not token:
        raise SystemExit("Falta la variable de entorno TELEGRAM_BOT_TOKEN")

    start_health_server()
    app = Application.builder().token(token).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(CommandHandler("ping", ping))
    app.add_handler(MessageHandler(filters.PHOTO, photo_warning))
    app.add_handler(MessageHandler(filters.Document.IMAGE, metadata))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, echo))

    log.info("Bot iniciado (polling)")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
