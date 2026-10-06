import io
import logging
import os
import random
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

import tools
from exif import extract, format_report, strip

logging.basicConfig(
    format="%(asctime)s %(name)s %(levelname)s %(message)s", level=logging.INFO
)
# httpx loguea la URL completa de la API de Telegram, que contiene el token
logging.getLogger("httpx").setLevel(logging.WARNING)
log = logging.getLogger("fsociety")
MAX_BYTES = 20 * 1024 * 1024

BANNER = r"""
 _____ ____   ___   ____ ___ _____ _______   __
|  ___/ ___| / _ \ / ___|_ _| ____|_   _\ \ / /
| |_  \___ \| | | | |    | ||  _|   | |  \ V /
|  _|  ___) | |_| | |___ | || |___  | |   | |
|_|   |____/ \___/ \____|___|_____| |_|   |_|
"""

SECTIONS = {
    "osint": (
        "ANÁLISIS (solo infraestructura pública)\n"
        "/whois dominio\n/dns dominio\n/subdominios dominio\n/ip 8.8.8.8\n"
        "/headers url\n/ssl dominio\n/tech url"
    ),
    "seg": (
        "SEGURIDAD PERSONAL\n"
        "/password clave  (se borra tu mensaje)\n/filtrado correo\n/link url\n"
        "Foto como ARCHIVO: te muestro sus metadatos.\n"
        "Foto como ARCHIVO con el texto 'limpiar': te la devuelvo sin metadatos."
    ),
    "ctf": (
        "CTF\n/b64 e|d texto\n/hex e|d texto\n/url e|d texto\n/rot13 texto\n"
        "/hash texto\n/hashid hash\n/jwt token\n/pass 16\n/quote"
    ),
}
MENU = InlineKeyboardMarkup(
    [[
        InlineKeyboardButton("Análisis", callback_data="osint"),
        InlineKeyboardButton("Seguridad", callback_data="seg"),
        InlineKeyboardButton("CTF", callback_data="ctf"),
    ]]
)


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        f"<pre>{BANNER}</pre>\nHello, friend. Somos fsociety.\nElige una sección:",
        parse_mode="HTML",
        reply_markup=MENU,
    )


async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text("\n\n".join(SECTIONS.values()))


async def menu_button(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    q = update.callback_query
    await q.answer()
    await q.edit_message_text(SECTIONS[q.data], reply_markup=MENU)


async def ping(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text("pong")


async def quote(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(random.choice(tools.QUOTES))


def _reply_text(text: str) -> str:
    return text if len(text) <= 4000 else text[:4000] + "\n…"


def command(usage: str, nargs_min: int = 1):
    """Decorador: valida argumentos, ejecuta la herramienta y traduce errores."""

    def deco(fn):
        async def handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
            if len(context.args) < nargs_min:
                await update.message.reply_text(f"Uso: {usage}")
                return
            try:
                result = fn(*context.args) if not _is_async(fn) else await fn(*context.args)
            except tools.ToolError as e:
                result = str(e)
            except httpx.HTTPError:
                log.exception("Fallo de red en %s", fn.__name__)
                result = "El servicio externo no respondió. Intenta de nuevo."
            except Exception:
                log.exception("Error en %s", fn.__name__)
                result = "Algo salió mal."
            await update.message.reply_text(_reply_text(result), disable_web_page_preview=True)

        return handler

    return deco


def _is_async(fn) -> bool:
    import inspect
    return inspect.iscoroutinefunction(fn)


whois_cmd = command("/whois dominio.com")(tools.whois)
dns_cmd = command("/dns dominio.com")(tools.dns)
subs_cmd = command("/subdominios dominio.com")(tools.subdomains)
ip_cmd = command("/ip 8.8.8.8")(tools.ip_info)
headers_cmd = command("/headers url")(tools.headers)
ssl_cmd = command("/ssl dominio.com")(tools.ssl_info)
tech_cmd = command("/tech url")(tools.tech)
hash_cmd = command("/hash texto")(lambda *a: tools.hashes(" ".join(a)))
hashid_cmd = command("/hashid hash")(lambda h: tools.hash_id(h))
jwt_cmd = command("/jwt token")(lambda t: tools.jwt_decode(t))
rot_cmd = command("/rot13 texto")(lambda *a: tools.rot13(" ".join(a)))
b64_cmd = command("/b64 e|d texto", 2)(lambda m, *a: tools.codec("b64", m, " ".join(a)))
hex_cmd = command("/hex e|d texto", 2)(lambda m, *a: tools.codec("hex", m, " ".join(a)))
url_cmd = command("/url e|d texto", 2)(lambda m, *a: tools.codec("url", m, " ".join(a)))
link_cmd = command("/link url")(lambda u: tools.check_link(u, os.environ.get("VT_API_KEY")))
leak_cmd = command("/filtrado correo")(lambda e: tools.pwned_email(e, os.environ.get("HIBP_API_KEY")))


async def pass_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    n = int(context.args[0]) if context.args and context.args[0].isdigit() else 16
    await update.message.reply_text(tools.gen_password(n))


async def password_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args:
        await update.message.reply_text("Uso: /password tuclave")
        return
    pw = " ".join(context.args)
    try:
        await update.message.delete()  # no dejar la clave en el chat
    except Exception:
        pass
    try:
        result = await tools.pwned_password(pw)
    except httpx.HTTPError:
        result = "El servicio no respondió. Intenta de nuevo."
    await context.bot.send_message(update.effective_chat.id, result)


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
        if "limpiar" in (update.message.caption or "").lower():
            clean, ext = strip(data)
            await update.message.reply_document(io.BytesIO(clean), filename=f"limpia.{ext}")
            return
        report = format_report(extract(data))
    except Exception:
        log.exception("No se pudo leer la imagen")
        await update.message.reply_text("No pude leer ese archivo como imagen.")
        return
    await update.message.reply_text(report)


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
    for name, fn in {
        "start": start, "help": help_cmd, "ping": ping, "quote": quote,
        "whois": whois_cmd, "dns": dns_cmd, "subdominios": subs_cmd, "ip": ip_cmd,
        "headers": headers_cmd, "ssl": ssl_cmd, "tech": tech_cmd,
        "password": password_cmd, "filtrado": leak_cmd, "link": link_cmd,
        "b64": b64_cmd, "hex": hex_cmd, "url": url_cmd, "rot13": rot_cmd,
        "hash": hash_cmd, "hashid": hashid_cmd, "jwt": jwt_cmd, "pass": pass_cmd,
    }.items():
        app.add_handler(CommandHandler(name, fn))
    app.add_handler(CallbackQueryHandler(menu_button, pattern="^(osint|seg|ctf)$"))
    app.add_handler(MessageHandler(filters.PHOTO, photo_warning))
    app.add_handler(MessageHandler(filters.Document.IMAGE, metadata))

    log.info("Bot iniciado (polling)")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
