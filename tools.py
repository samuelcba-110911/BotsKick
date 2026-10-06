"""Herramientas de análisis pasivo (OSINT sobre infraestructura pública) y utilidades CTF."""
import asyncio
import base64
import hashlib
import ipaddress
import json
import re
import secrets
import socket
import ssl
import string
from datetime import datetime, timezone
from urllib.parse import quote, urlparse

import httpx

TIMEOUT = httpx.Timeout(10.0)
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
UA = {"User-Agent": "fsociety-bot/1.0 (+osint educativo)"}


class ToolError(Exception):
    """Error mostrable al usuario."""


def clean_domain(raw: str) -> str:
    raw = raw.strip().lower()
    if "://" in raw:
        raw = urlparse(raw).hostname or ""
    raw = raw.split("/")[0].rstrip(".")
    if not DOMAIN_RE.match(raw):
        raise ToolError("Dominio no válido. Ejemplo: example.com")
    return raw


async def _resolve_public(host: str) -> list[str]:
    """Resuelve el host y rechaza cualquier IP no pública (evita SSRF hacia la red interna)."""
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise ToolError("No pude resolver ese host.")
    ips = sorted({i[4][0] for i in infos})
    if not ips or not all(ipaddress.ip_address(ip).is_global for ip in ips):
        raise ToolError("Ese host no es público; no lo consulto.")
    return ips


# ---------------------------------------------------------------- OSINT pasivo
async def whois(domain: str) -> str:
    domain = clean_domain(domain)
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True, headers=UA) as c:
        r = await c.get(f"https://rdap.org/domain/{quote(domain)}")
    if r.status_code == 404:
        raise ToolError("Dominio no registrado o sin datos RDAP.")
    r.raise_for_status()
    d = r.json()
    lines = [f"Dominio: {domain}"]
    for ev in d.get("events", []):
        label = {"registration": "Registrado", "expiration": "Expira", "last changed": "Modificado"}.get(
            ev.get("eventAction")
        )
        if label:
            lines.append(f"{label}: {ev.get('eventDate', '')[:10]}")
    for ent in d.get("entities", []):
        if "registrar" in ent.get("roles", []):
            for item in ent.get("vcardArray", [None, []])[1]:
                if item[0] == "fn":
                    lines.append(f"Registrador: {item[3]}")
    ns = [n.get("ldhName", "").lower() for n in d.get("nameservers", [])]
    if ns:
        lines.append("Nameservers: " + ", ".join(ns))
    if d.get("status"):
        lines.append("Estado: " + ", ".join(d["status"]))
    return "\n".join(lines)


async def dns(domain: str) -> str:
    domain = clean_domain(domain)
    out = [f"DNS de {domain}"]
    async with httpx.AsyncClient(timeout=TIMEOUT, headers={"Accept": "application/dns-json"}) as c:
        for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
            r = await c.get(
                "https://cloudflare-dns.com/dns-query", params={"name": domain, "type": rtype}
            )
            answers = [a["data"] for a in r.json().get("Answer", []) if a.get("type") == _DNS_TYPES[rtype]]
            if answers:
                out.append(f"\n{rtype}:")
                out.extend(f"  {a}" for a in answers[:10])
    return "\n".join(out) if len(out) > 1 else "Sin registros."


_DNS_TYPES = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28}


async def subdomains(domain: str) -> str:
    domain = clean_domain(domain)
    async with httpx.AsyncClient(timeout=httpx.Timeout(30.0), headers=UA) as c:
        r = await c.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"})
    r.raise_for_status()
    names: set[str] = set()
    for row in r.json():
        for n in row.get("name_value", "").splitlines():
            n = n.strip().lower().lstrip("*.")
            if n.endswith(domain):
                names.add(n)
    if not names:
        return "No encontré subdominios en los certificados públicos."
    shown = sorted(names)
    extra = f"\n… y {len(shown) - 60} más" if len(shown) > 60 else ""
    return f"{len(shown)} subdominios en crt.sh:\n" + "\n".join(shown[:60]) + extra


async def ip_info(raw: str) -> str:
    try:
        ip = ipaddress.ip_address(raw.strip())
    except ValueError:
        raise ToolError("IP no válida. Ejemplo: 8.8.8.8")
    if not ip.is_global:
        raise ToolError("Esa IP es privada o reservada.")
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=UA) as c:
        d = (await c.get(f"https://ipwho.is/{ip}")).json()
    if not d.get("success"):
        raise ToolError("Sin datos para esa IP.")
    conn = d.get("connection", {})
    return (
        f"IP: {ip}\nPaís: {d.get('country')} ({d.get('country_code')})\n"
        f"Región/Ciudad: {d.get('region')}, {d.get('city')}\n"
        f"ISP: {conn.get('isp')}\nOrganización: {conn.get('org')}\nASN: AS{conn.get('asn')}"
    )


SEC_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}


async def headers(raw: str) -> str:
    url = raw.strip()
    if "://" not in url:
        url = "https://" + url
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False, headers=UA) as c:
        for _ in range(4):
            p = urlparse(url)
            if p.scheme not in ("http", "https") or not p.hostname:
                raise ToolError("URL no válida.")
            await _resolve_public(p.hostname)
            r = await c.get(url)
            if r.is_redirect and r.headers.get("location"):
                url = str(httpx.URL(url).join(r.headers["location"]))
                continue
            break
    h = {k.lower(): v for k, v in r.headers.items()}
    lines = [f"{url} -> HTTP {r.status_code}"]
    for key, label in SEC_HEADERS.items():
        lines.append(f"{'OK  ' if key in h else 'FALTA'} {label}")
    for key in ("server", "x-powered-by"):
        if key in h:
            lines.append(f"Revela {key}: {h[key]}")
    return "\n".join(lines)


async def ssl_info(domain: str) -> str:
    domain = clean_domain(domain)
    await _resolve_public(domain)

    def fetch():
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=8) as s:
            with ctx.wrap_socket(s, server_hostname=domain) as t:
                return t.getpeercert(), t.version()

    try:
        cert, ver = await asyncio.to_thread(fetch)
    except ssl.SSLError as e:
        return f"{domain}: certificado NO válido ({e.reason or e})"
    except OSError:
        raise ToolError("No pude conectar al puerto 443.")
    exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    days = (exp - datetime.now(timezone.utc)).days
    issuer = dict(x[0] for x in cert["issuer"]).get("organizationName", "?")
    subject = dict(x[0] for x in cert["subject"]).get("commonName", "?")
    return (
        f"{domain}\nSujeto: {subject}\nEmisor: {issuer}\nExpira: {exp:%Y-%m-%d} ({days} días)\n"
        f"Protocolo: {ver}\nVálido: sí"
    )


async def tech(raw: str) -> str:
    url = raw.strip()
    if "://" not in url:
        url = "https://" + url
    p = urlparse(url)
    if not p.hostname:
        raise ToolError("URL no válida.")
    await _resolve_public(p.hostname)
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False, headers=UA) as c:
        r = await c.get(url)
    h = {k.lower(): v for k, v in r.headers.items()}
    body = r.text[:200_000].lower()
    found = []
    for key in ("server", "x-powered-by", "x-generator", "via"):
        if key in h:
            found.append(f"{key}: {h[key]}")
    if "cf-ray" in h:
        found.append("Cloudflare")
    sigs = {
        "WordPress": "wp-content", "Shopify": "cdn.shopify.com", "Wix": "wixstatic.com",
        "Next.js": "/_next/", "React": "react", "Vue": "vue", "Bootstrap": "bootstrap",
        "jQuery": "jquery", "Google Analytics": "googletagmanager.com",
    }
    found += [name for name, sig in sigs.items() if sig in body]
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', r.text[:200_000], re.I)
    if m:
        found.append(f"generator: {m.group(1)}")
    return "Tecnologías detectadas:\n" + "\n".join(found) if found else "No detecté tecnologías conocidas."


# ------------------------------------------------------------- seguridad personal
async def pwned_password(password: str) -> str:
    sha = hashlib.sha1(password.encode()).hexdigest().upper()
    async with httpx.AsyncClient(timeout=TIMEOUT, headers={**UA, "Add-Padding": "true"}) as c:
        r = await c.get(f"https://api.pwnedpasswords.com/range/{sha[:5]}")
    r.raise_for_status()
    for line in r.text.splitlines():
        suffix, _, count = line.partition(":")
        if suffix == sha[5:] and int(count) > 0:
            return f"Esa contraseña apareció {int(count):,} veces en filtraciones. No la uses."
    return "No aparece en filtraciones conocidas (eso no garantiza que sea fuerte)."


async def pwned_email(email: str, api_key: str | None) -> str:
    if not api_key:
        raise ToolError("Falta HIBP_API_KEY (Have I Been Pwned cobra por esta consulta).")
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        raise ToolError("Correo no válido.")
    async with httpx.AsyncClient(timeout=TIMEOUT, headers={**UA, "hibp-api-key": api_key}) as c:
        r = await c.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}",
            params={"truncateResponse": "true"},
        )
    if r.status_code == 404:
        return "Ese correo no aparece en filtraciones conocidas."
    r.raise_for_status()
    names = [b["Name"] for b in r.json()]
    return f"Aparece en {len(names)} filtraciones:\n" + ", ".join(names)


async def check_link(url: str, api_key: str | None) -> str:
    if not api_key:
        raise ToolError("Falta VT_API_KEY (clave gratis de virustotal.com).")
    uid = base64.urlsafe_b64encode(url.strip().encode()).decode().rstrip("=")
    async with httpx.AsyncClient(timeout=TIMEOUT, headers={**UA, "x-apikey": api_key}) as c:
        r = await c.get(f"https://www.virustotal.com/api/v3/urls/{uid}")
    if r.status_code == 404:
        return "VirusTotal aún no ha analizado ese enlace."
    r.raise_for_status()
    s = r.json()["data"]["attributes"]["last_analysis_stats"]
    return (
        f"Maliciosos: {s['malicious']}  Sospechosos: {s['suspicious']}  "
        f"Limpios: {s['harmless']}  Sin detectar: {s['undetected']}"
    )


# ------------------------------------------------------------------------- CTF
def codec(kind: str, mode: str, text: str) -> str:
    try:
        if kind == "b64":
            return base64.b64encode(text.encode()).decode() if mode == "e" else base64.b64decode(text).decode(errors="replace")
        if kind == "hex":
            return text.encode().hex() if mode == "e" else bytes.fromhex(text).decode(errors="replace")
        if kind == "url":
            from urllib.parse import unquote
            return quote(text, safe="") if mode == "e" else unquote(text)
    except ValueError:
        raise ToolError("Entrada no válida para ese formato.")
    raise ToolError("Formato desconocido.")


def rot13(text: str) -> str:
    import codecs
    return codecs.encode(text, "rot_13")


def hashes(text: str) -> str:
    data = text.encode()
    return "\n".join(f"{a.upper()}: {hashlib.new(a, data).hexdigest()}" for a in ("md5", "sha1", "sha256", "sha512"))


def hash_id(h: str) -> str:
    h = h.strip()
    if re.fullmatch(r"\$2[aby]?\$\d\d\$.{53}", h):
        return "bcrypt"
    if h.startswith("$argon2"):
        return "Argon2"
    if h.startswith("$6$"):
        return "SHA-512 crypt (Linux)"
    if h.startswith("$5$"):
        return "SHA-256 crypt (Linux)"
    if h.startswith("$1$"):
        return "MD5 crypt"
    if re.fullmatch(r"[0-9a-fA-F]+", h):
        by_len = {
            32: "MD5 / NTLM", 40: "SHA-1", 56: "SHA-224", 64: "SHA-256 (o SHA3-256)",
            96: "SHA-384", 128: "SHA-512 (o SHA3-512)",
        }
        return by_len.get(len(h), f"Hexadecimal de {len(h)} caracteres, tipo desconocido")
    return "Formato no reconocido."


def jwt_decode(token: str) -> str:
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ToolError("Un JWT tiene 3 partes separadas por puntos.")

    def dec(p: str):
        return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))

    try:
        header, payload = dec(parts[0]), dec(parts[1])
    except Exception:
        raise ToolError("No pude decodificar ese JWT.")
    return (
        "Header:\n" + json.dumps(header, indent=2) + "\n\nPayload:\n" + json.dumps(payload, indent=2)
        + "\n\n(La firma NO se verifica.)"
    )


def gen_password(n: int = 16) -> str:
    n = max(8, min(n, 64))
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_=+"
    return "".join(secrets.choice(alphabet) for _ in range(n))


QUOTES = [
    "Hello, friend.",
    "Control is an illusion.",
    "We are all living in a simulation. Nobody's real.",
    "Sometimes I dream of saving the world.",
    "People always make the best exploits.",
    "Our democracy has been hacked.",
    "Give a man a gun and he can rob a bank. Give a man a bank and he can rob the world.",
]
