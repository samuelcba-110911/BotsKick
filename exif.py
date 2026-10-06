"""Extracción de metadatos EXIF (cámara, fecha, GPS) con Pillow."""
import io
from typing import Optional

from PIL import ExifTags, Image

GPS_IFD = 0x8825
EXIF_IFD = 0x8769


def _to_degrees(value, ref) -> Optional[float]:
    try:
        d, m, s = (float(x) for x in value)
    except (TypeError, ValueError):
        return None
    deg = d + m / 60 + s / 3600
    return -deg if ref in ("S", "W") else deg


def extract(data: bytes) -> dict:
    """Devuelve los metadatos legibles de una imagen. Dict vacío si no hay EXIF."""
    img = Image.open(io.BytesIO(data))
    exif = img.getexif()
    if not exif:
        return {}

    info: dict = {"Formato": f"{img.format} {img.width}x{img.height}"}
    tags = {ExifTags.TAGS.get(k, k): v for k, v in exif.items()}
    tags.update(
        {ExifTags.TAGS.get(k, k): v for k, v in exif.get_ifd(EXIF_IFD).items()}
    )

    for key, label in (
        ("Make", "Marca"),
        ("Model", "Modelo"),
        ("Software", "Software"),
        ("DateTimeOriginal", "Fecha de captura"),
        ("DateTime", "Fecha de modificación"),
        ("LensModel", "Lente"),
    ):
        if key in tags:
            info[label] = str(tags[key]).strip("\x00 ")

    gps = {ExifTags.GPSTAGS.get(k, k): v for k, v in exif.get_ifd(GPS_IFD).items()}
    lat = _to_degrees(gps.get("GPSLatitude"), gps.get("GPSLatitudeRef"))
    lon = _to_degrees(gps.get("GPSLongitude"), gps.get("GPSLongitudeRef"))
    if lat is not None and lon is not None:
        info["GPS"] = f"{lat:.6f}, {lon:.6f}"
        info["Mapa"] = f"https://www.google.com/maps?q={lat:.6f},{lon:.6f}"
        if "GPSAltitude" in gps:
            info["Altitud"] = f"{float(gps['GPSAltitude']):.0f} m"
    return info


def format_report(info: dict) -> str:
    if not info:
        return "No encontré metadatos EXIF en esta imagen (puede haber sido limpiada)."
    return "\n".join(f"{k}: {v}" for k, v in info.items())
