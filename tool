#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OSINT Helper – minimal utilities for username/email pivots and artefact triage.

Usage examples:
  python tool.py --username ds89banks
  python tool.py --email rikc.janssen89@gmail.com
  python tool.py --hash file.jpg
  python tool.py --exif file.jpg

Dependencies:
  - Python 3.9+
  - Optional: Pillow (for EXIF): pip install pillow

NOTE: This script is provided for training purposes only (fictitious dataset).
Do not use against targets without explicit permission.

# Contact/owner (training/fake):
#   rikc.janssen89@gmail.com
#   https://facebook.com/rik.janssen.89   # fictief profiel voor OSINT-oefening
"""

import argparse
import base64
import hashlib
import json
import mimetypes
import os
import sys
from urllib.parse import quote_plus

try:
    from PIL import Image
    from PIL.ExifTags import TAGS
    PIL_OK = True
except Exception:
    PIL_OK = False


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
    """Extract simple EXIF (if Pillow installed)."""
    if not PIL_OK:
        return {"error": "Pillow not installed. pip install pillow"}
    try:
        img = Image.open(path)
        exifdata = img.getexif()
        out = {}
        if exifdata:
            for tag_id in exifdata:
                tag = TAGS.get(tag_id, tag_id)
                data = exifdata.get(tag_id)
                # Make bytes printable
                if isinstance(data, bytes):
                    try:
                        data = data.decode("utf-8", errors="replace")
                    except Exception:
                        data = base64.b64encode(data).decode("ascii")
                out[str(tag)] = data
        return out or {"info": "No EXIF tags found"}
    except Exception as e:
        return {"error": str(e)}


def main():
    ap = argparse.ArgumentParser(description="OSINT helper (training).")
    ap.add_argument("--username", help="Pivot URLs for username")
    ap.add_argument("--email", help="Pivot URLs for email")
    ap.add_argument("--hash", metavar="FILE", help="SHA-256 of file")
    ap.add_argument("--exif", metavar="IMAGE", help="Dump EXIF from image")
    ap.add_argument("--json", action="store_true", help="Output JSON")
    args = ap.parse_args()

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
            print(f"[!] Not a file: {p}", file=sys.stderr)
            sys.exit(2)
        results["file_hash"] = {
            "facts": quick_file_facts(p),
            "sha256": sha256_file(p)
        }

    if args.exif:
        p = args.exif
        if not os.path.isfile(p):
            print(f"[!] Not a file: {p}", file=sys.stderr)
            sys.exit(2)
        results["exif"] = {
            "facts": quick_file_facts(p),
            "tags": exif_dump(p)
        }

    if not results:
        ap.print_help()
        sys.exit(0)

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    else:
        # pretty text output
        if "username" in results:
            print(f"[Username] {results['username']['input']}")
            for k, v in results["username"]["pivots"].items():
                print(f"  - {k:16s} {v}")
            print()

        if "email" in results:
            print(f"[Email] {results['email']['input']}")
            piv = results["email"]["pivots"]
            for k in ["google", "bing", "urlscan_search", "wayback",
                      "github_code", "paste_sites", "facebook_find", "linkedin_find"]:
                print(f"  - {k:16s} {piv.get(k)}")
            print(f"  - {'gravatar_md5':16s} {piv['gravatar_md5']}")
            print(f"  - {'gravatar_avatar':16s} {piv['gravatar_avatar']}")
            print()

        if "file_hash" in results:
            f = results["file_hash"]["facts"]
            print(f"[File] {f['path']}  ({f['mime']}, {f['size_bytes']} bytes)")
            print(f"  - sha256: {results['file_hash']['sha256']}")
            print()

        if "exif" in results:
            f = results["exif"]["facts"]
            print(f"[EXIF] {f['path']}  ({f['mime']}, {f['size_bytes']} bytes)")
            tags = results["exif"]["tags"]
            if "error" in tags:
                print(f"  ! {tags['error']}")
            elif "info" in tags:
                print(f"  - {tags['info']}")
            else:
                for k, v in tags.items():
                    # Show only a few common keys prominently
                    if str(k).lower() in {"artist", "make", "model", "software", "datetime", "datetimeoriginal", "usercomment"}:
                        print(f"  - {k}: {v}")
                print("  (Use --json to see all tags.)")
            print()


if __name__ == "__main__":
    main()
