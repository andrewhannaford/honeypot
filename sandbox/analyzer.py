"""Static analysis — zero execution.

ELF architecture detection matters specifically for this corpus: IoT botnet
download loops (Mirai/Gafgyt-family, matching the "satan_x86_64" naming already
seen live) typically try several architectures per victim (x86, ARM, MIPS,
...) — capturing which one a given sample is is useful on its own for telling
those spray patterns apart, independent of whether anything ever runs it.
"""

import struct
from urllib.parse import urlparse

import magic

_ELF_MACHINE_NAMES = {
    0x03: "x86",
    0x08: "MIPS",
    0x14: "PowerPC",
    0x28: "ARM",
    0x2A: "SuperH",
    0x32: "IA-64",
    0x3E: "x86_64",
    0xB7: "AArch64",
    0xF3: "RISC-V",
}


def detect_mime(content):
    try:
        return magic.from_buffer(content, mime=True)
    except Exception:
        return "application/octet-stream"


def detect_elf_architecture(content):
    """Returns an architecture string for ELF files, 'not_elf' for anything else
    (scripts, text, etc. — still potentially executable via an interpreter, just
    not what this function checks), or None if the buffer is too short to tell."""
    if len(content) < 20:
        return None
    if content[:4] != b"\x7fELF":
        return "not_elf"
    ei_data = content[5]  # 1 = little-endian, 2 = big-endian
    endian = "<" if ei_data == 1 else ">"
    try:
        (e_machine,) = struct.unpack_from(endian + "H", content, 18)
    except struct.error:
        return "unknown_elf"
    return _ELF_MACHINE_NAMES.get(e_machine, f"unknown_elf(0x{e_machine:x})")


def is_x86_64_elf(architecture):
    return architecture == "x86_64"


# Confirmed live against this honeypot's own samples before writing this: of
# the first 5 things ever stored, 2 were plain text/html web pages, 1 was a
# 22-byte application/json blob — none of that is malware, it's what you get
# when a URL embedded in attacker input happens to point at an ordinary site
# rather than a payload host. Only the two text/x-shellscript rows were
# actually interesting.
#
# javascript/wasm/xhtml+xml added after a second incident: a backfill retry
# against a URL that used to be dead turned out to now serve an ordinary
# WordPress/Shopify storefront, and the (since-capped, see fetcher.py's
# second-stage re-scan bounds) recursive link-follow kept 92 of that page's
# own CDN assets as "samples" — jQuery, FontAwesome, Google Fonts, Shopify
# checkout bundles, a .wasm blob. None of that is malware on this honeypot's
# threat profile (Linux IoT/cron/Redis droppers — ELF binaries and shell/
# python scripts, not browser-executed JS). text/troff and
# application/SIMH-tape-data were libmagic misidentifying plain CSS via
# heuristic byte-pattern matching, not real formats anything here would
# legitimately serve.
#
# text/plain and application/octet-stream are deliberately NOT excluded by
# MIME type, even though they accounted for most of that same incident's
# noise (CSS/JS without a strong-enough signature for magic to name them
# precisely sniffs as text/plain) — both are also exactly what a real shell/
# python dropper with no recognizable header looks like, and this filter is
# built to risk false positives over silently discarding a real payload.
#
# A full re-check of every historical not_malware URL (done after the MIME
# tightening above) hit this exact gap again: 66 more legitimate CDN/
# WordPress/Shopify assets got kept, all text/plain or application/octet-
# stream. But every single one of those 66 — and all 92 from the first
# incident, 158 total, zero exceptions — had a URL path ending in .css or
# .js. Nothing genuinely malicious captured on this honeypot ever has: real
# droppers here are .sh, .py, or extensionless. That's a much more reliable
# signal than MIME type for exactly this ambiguous bucket, so it closes the
# gap without touching the MIME-exclusion tradeoff above — see
# _url_looks_like_web_asset and its use below. Real ELF content still always
# wins regardless of the URL it came from.
_NOT_INTERESTING_MIME_PREFIXES = (
    "text/html", "text/css", "image/", "font/", "audio/", "video/",
    "application/javascript", "text/javascript", "application/x-javascript",
    "application/xhtml+xml", "text/troff",
)
_NOT_INTERESTING_MIME_EXACT = frozenset({
    "application/json", "application/xml", "text/xml", "application/rss+xml",
    "application/atom+xml", "text/calendar", "application/wasm",
    "application/SIMH-tape-data",
})
_WEB_ASSET_URL_EXTENSIONS = (".css", ".js")


def _url_looks_like_web_asset(url):
    if not url:
        return False
    try:
        path = urlparse(url).path.lower()
    except ValueError:
        return False
    return path.endswith(_WEB_ASSET_URL_EXTENSIONS)


def looks_like_malware(mime_type, architecture, url=None):
    """Best-effort keep/discard filter, applied before a fetched sample is
    written to disk. Errs toward keeping when ambiguous — a false negative
    (silently discarding a real payload because its MIME type wasn't
    anticipated) is worse than a false positive (keeping an uninteresting
    text file) for something whose whole purpose is capturing what attackers
    actually push. Any genuine ELF (any architecture, including ones this
    box can't run) is always kept regardless of URL; otherwise a fixed set
    of clearly-not-malware MIME types (web pages, images, stylesheets,
    browser-executed JS/WASM, structured API-style responses) is excluded.
    text/plain and application/octet-stream stay ambiguous-keep by MIME
    alone (see the comment above the exclusion lists), but a .css/.js URL
    extension excludes them too — pass the URL this content was actually
    fetched from (final_url, post-redirect) as `url` to get that check;
    omit it and this behaves exactly as before (MIME/architecture only)."""
    if architecture not in (None, "not_elf"):
        return True
    if mime_type in _NOT_INTERESTING_MIME_EXACT:
        return False
    if mime_type and mime_type.startswith(_NOT_INTERESTING_MIME_PREFIXES):
        return False
    if _url_looks_like_web_asset(url):
        return False
    return True
