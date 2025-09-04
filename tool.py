#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OSINT Helper – minimal utilities for username/email pivots and artefact triage.
Pretty CLI met kleuren & banner.

Voorbeelden:
  python tool.py --username ds89banks
  python tool.py --email rikc.janssen89@gmail.com
  python tool.py --hash file.jpg
  python tool.py --exif file.jpg
  python tool.py --json
  python tool.py --spoiler

Zonder arguments -> toont help (zoals een normale CLI).

Dependencies:
  - Python 3.9+
  - Optional: Pillow (voor EXIF): pip install pillow
  - Optional: colorama (Windows kleuren): pip install colorama

NOTE: Training/fictief. Niet gebruiken tegen echte doelen zonder expliciete toestemming.

# Contact/owner (training/fake):
#   rikc.janssen89@gmail.com
#   https://facebook.com/rik.janssen.89   # fictief profiel voor OSINT-oefening
"""

import argparse
import base64
import hashlib
import html
import json
import mimetypes
import os
import re
import sys
from urllib.parse import quote_plus

# -----------------------------
# Optional color support
# -----------------------------
USE_COLOR = sys.stdout.isatty()
try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init()
    C = {
        "reset": Style.RESET_ALL,
        "dim": Style.DIM,
        "bold": Style.BRIGHT,
        "red": Fore.RED,
        "green": Fore.GREEN,
        "yellow": Fore.YELLOW,
        "blue": Fore.BLUE,
        "magenta": Fore.MAGENTA,
        "cyan": Fore.CYAN,
        "white": Fore.WHITE,
    }
except Exception:
    class _Dummy:
        def __getattr__(self, _): return ""
    Fore = Style = _Dummy()
    C = {k: "" for k in ["reset","dim","bold","red","green","yellow","blue","magenta","cyan","white"]}
    USE_COLOR = False

def c(txt, *styles):
    """Wrap text in ANSI styles if TTY."""
    if not USE_COLOR or not styles:
        return txt
    return "".join(styles) + txt + C["reset"]

# -----------------------------
# Optional EXIF dependency
# -----------------------------
try:
    from PIL import Image
    from PIL.ExifTags import TAGS
    PIL_OK = True
except Exception:
    PIL_OK = False

# -----------------------------
# Banner (clean, aligned)
# -----------------------------
def banner():
    title = "OSINT HELPER"
    subtitle = "username/email pivots · file triage · exif peek"
    width = 62
    top = "┌" + "─" * (width - 2) + "┐"
    mid1 = "│ " + f"{title:^{width-4}}" + " │"
    mid2 = "│ " + f"{subtitle:^{width-4}}" + " │"
    bot = "└" + "─" * (width - 2) + "┘"
    print(c(top, C["cyan"], C["bold"]))
    print(c(mid1, C["white"], C["bold"]))
    print(c(mid2, C["dim"]))
    print(c(bot, C["cyan"], C["bold"]))
    print()

# -----------------------------
# Pivot helpers
# -----------------------------
def pivot_username(u: str) -> dict:
    """Return useful pivot/search URLs for a username."""
    q = quote_plus(u)
    return {
        "google": f"https://www.google.com/search?q={q}",
        "bing": f"https://www.bing.com/search?q={q}",
        "github_user": f"https://github.com/{u}",
        "github_search": f"https://github.com/search?q={q}",
        "twitter_x": f"https://x.com/search?q={q}&src=typed_query&f=user",
        "telegram": f"https://t.me/{u}",
        "urlscan_search": f"https://urlscan.io/search/#query:{q}",
        "wayback": f"https://web.archive.org/web/*/{u}",
        "reddit": f"https://www.reddit.com/search/?q={q}",
        "haveibeensold": f"https://www.google.com/search?q=site%3Apastebin.com+{q}",
        "images_google": f"https://www.google.com/search?tbm=isch&q={q}",
    }

def pivot_email(e: str) -> dict:
    """Return useful pivot/search URLs for an email (plus gravatar hash)."""
    q = quote_plus(e)
    md5 = hashlib.md5(e.strip().lower().encode("utf-8")).hexdigest()
    return {
        "google": f"https://www.google.com/search?q={q}",
        "bing": f"https://www.bing.com/search?q={q}",
        "urlscan_search": f"https://urlscan.io/search/#query:{q}",
        "wayback": f"https://web.archive.org/web/*/{q}",
        "github_code": f"https://github.com/search?q={q}&type=code",
        "paste_sites": f"https://www.google.com/search?q=site%3Apastebin.com+{q}",
        "gravatar_md5": md5,
        "gravatar_avatar": f"https://www.gravatar.com/avatar/{md5}?d=404",
        "facebook_find": f"https://www.facebook.com/search/top?q={q}",
        "linkedin_find": f"https://www.google.com/search?q=site%3Alinkedin.com+{q}",
    }

# -----------------------------
# File/EXIF helpers
# -----------------------------
def sha256_file(path: str) -> str:
    """Return SHA-256 of a file (streaming)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def quick_file_facts(path: str) -> dict:
    """Basic facts about a file."""
    size = os.path.getsize(path)
    mime, _ = mimetypes.guess_type(path)
    return {"path": path, "size_bytes": size, "mime": mime or "unknown"}

def exif_dump(path: str) -> dict:
    """Extract EXIF + JPEG Comment (COM) + enkele XMP velden (Description/Title)."""
    if not PIL_OK:
        return {"error": "Pillow not installed. pip install pillow"}
    try:
        img = Image.open(path)
        out = {}

        # --- EXIF (klassiek) ---
        try:
            exifdata = img.getexif()
        except Exception:
            exifdata = None

        def _decode_exif_bytes(tag_name: str, data: bytes):
            b = bytes(data)
            tl = str(tag_name).lower()
            # XP* (UTF-16-LE met nulls)
            if tl.startswith("xp"):
                try:
                    return b.decode("utf-16-le", "ignore").rstrip("\x00")
                except Exception:
                    pass
            # UserComment met prefix
            if tl == "usercomment" and len(b) >= 8:
                prefix, payload = b[:8], b[8:]
                if prefix.startswith(b"ASCII"):
                    try:
                        return payload.decode("ascii", "ignore").rstrip("\x00")
                    except Exception:
                        pass
                if prefix.startswith(b"UNICODE"):
                    try:
                        return payload.decode("utf-16-be", "ignore").rstrip("\x00")
                    except Exception:
                        pass
            # Fallback
            try:
                return b.decode("utf-8", "replace")
            except Exception:
                return base64.b64encode(b).decode("ascii")

        if exifdata:
            for tag_id in exifdata:
                tag = TAGS.get(tag_id, tag_id)
                data = exifdata.get(tag_id)
                if isinstance(data, (bytes, bytearray)):
                    data = _decode_exif_bytes(str(tag), data)
                out[str(tag)] = data

        # --- JPEG Comment (COM) ---
        try:
            cmt = img.info.get("comment") or img.info.get("COM")
            if cmt:
                if isinstance(cmt, (bytes, bytearray)):
                    cmt = cmt.decode("utf-8", "replace")
                out["Comment"] = cmt
        except Exception:
            pass

        # --- XMP (pak Description/Title als aanwezig) ---
        try:
            xmp = img.info.get("XML:com.adobe.xmp") or img.info.get("xmp")
            if xmp:
                if isinstance(xmp, (bytes, bytearray)):
                    xmp = xmp.decode("utf-8", "replace")
                # dc:description -> rdf:li
                m = re.search(r"<dc:description[^>]*>.*?<rdf:li[^>]*>(.*?)</rdf:li>.*?</dc:description>",
                              xmp, re.I | re.S)
                if m:
                    out["XMP:Description"] = html.unescape(re.sub(r"<[^>]+>", "", m.group(1))).strip()
                # dc:title -> rdf:li
                m = re.search(r"<dc:title[^>]*>.*?<rdf:li[^>]*>(.*?)</rdf:li>.*?</dc:title>",
                              xmp, re.I | re.S)
                if m:
                    out["XMP:Title"] = html.unescape(re.sub(r"<[^>]+>", "", m.group(1))).strip()
        except Exception:
            pass

        return out or {"info": "No EXIF/XMP/Comment found"}
    except Exception as e:
        return {"error": str(e)}

# -----------------------------
# Pretty printers
# -----------------------------
def print_username_block(results):
    print(c("[Username] ", C["magenta"], C["bold"]) + c(results['username']['input'], C["white"], C["bold"]))
    for k, v in results["username"]["pivots"].items():
        print(f"  {c('- '+k+':', C['cyan']):20s} {v}")
    print()

def print_email_block(results):
    print(c("[Email]   ", C["magenta"], C["bold"]) + c(results['email']['input'], C["white"], C["bold"]))
    piv = results["email"]["pivots"]
    ordered = ["google","bing","urlscan_search","wayback","github_code","paste_sites","facebook_find","linkedin_find"]
    for k in ordered:
        print(f"  {c('- '+k+':', C['cyan']):20s} {piv.get(k)}")
    print(f"  {c('- gravatar_md5:', C['cyan']):20s} {piv['gravatar_md5']}")
    print(f"  {c('- gravatar_avatar:', C['cyan']):20s} {piv['gravatar_avatar']}")
    print()

def print_file_hash_block(results):
    f = results["file_hash"]["facts"]
    line = f"[File] {f['path']}  ({f['mime']}, {f['size_bytes']} bytes)"
    print(c(line, C["yellow"]))
    print(f"  {c('- sha256:', C['cyan']):20s} {results['file_hash']['sha256']}")
    print()

def print_exif_block(results):
    f = results["exif"]["facts"]
    line = f"[EXIF] {f['path']}  ({f['mime']}, {f['size_bytes']} bytes)"
    print(c(line, C["yellow"]))
    tags = results["exif"]["tags"]

    if "error" in tags:
        print("  " + c("! ", C["red"]) + tags["error"])
        print()
        return
    if "info" in tags:
        print(f"  {c('- info:', C['cyan']):20s} {tags['info']}")
        print()
        return

    # Toon kernvelden + alles met 'comment' of 'desc' in de naam (case-insensitive)
    base_keys = {"artist","make","model","software","datetime","datetimeoriginal","usercomment","imagedescription"}
    shown = False
    for k, v in tags.items():
        kl = str(k).lower()
        if (kl in base_keys) or ("comment" in kl) or ("desc" in kl) or kl.startswith("xmp:"):
            print(f"  {c('- '+k+':', C['cyan']):20s} {v}")
            shown = True

    if not shown:
        print("  " + c("(Geen relevante sleutelvelden gevonden — gebruik --json voor alle tags.)", C["dim"]))
    else:
        print("  " + c("(Gebruik --json om alle tags te zien.)", C["dim"]))
    print()

def print_spoiler_block(results):
    print(c("[Spoiler] ", C["green"], C["bold"]) + results["spoiler"]["hint"])
    print()

# -----------------------------
# Main
# -----------------------------
def main():
    banner()
    ap = argparse.ArgumentParser(
        description="OSINT helper (training) – username/email pivots, file hash & EXIF peek.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    ap.add_argument("--username", help="Pivot URLs voor username")
    ap.add_argument("--email", help="Pivot URLs voor email")
    ap.add_argument("--hash", metavar="FILE", help="SHA-256 van bestand")
    ap.add_argument("--exif", metavar="IMAGE", help="EXIF/XMP/Comment-dump van afbeelding")
    ap.add_argument("--json", action="store_true", help="JSON-uitvoer")
    ap.add_argument("--spoiler", action="store_true", help="Toon een kleine verborgen hint")
    args = ap.parse_args()

    # Geen vlaggen → help + exit(1)
    if not (args.username or args.email or args.hash or args.exif or args.spoiler):
        ap.print_help()
        sys.exit(1)

    results = {}

    if args.username:
        u = args.username.strip()
        results["username"] = {"input": u, "pivots": pivot_username(u)}

    if args.email:
        e = args.email.strip()
        results["email"] = {"input": e, "pivots": pivot_email(e)}

    if args.hash:
        p = args.hash
        if not os.path.isfile(p):
            print(c(f"[!] Not a file: {p}", C["red"], C["bold"]), file=sys.stderr)
            sys.exit(2)
        results["file_hash"] = {
            "facts": quick_file_facts(p),
            "sha256": sha256_file(p)
        }

    if args.exif:
        p = args.exif
        if not os.path.isfile(p):
            print(c(f"[!] Not a file: {p}", C["red"], C["bold"]), file=sys.stderr)
            sys.exit(2)
        results["exif"] = {
            "facts": quick_file_facts(p),
            "tags": exif_dump(p)
        }

    if args.spoiler:
        # NB: pas desgewenst de hinttekst aan
        results["spoiler"] = {
            "hint": "Tip: Vergeet ook SnapChat Niet :)."
        }

    # Output
    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    else:
        if "username" in results:
            print_username_block(results)
        if "email" in results:
            print_email_block(results)
        if "file_hash" in results:
            print_file_hash_block(results)
        if "exif" in results:
            print_exif_block(results)
        if "spoiler" in results:
            print_spoiler_block(results)

if __name__ == "__main__":
    main()
