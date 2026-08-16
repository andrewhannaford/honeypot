import datetime
import os
import socket
import ssl
import threading
import time
import ratelimit
from logger import log_event
from config import HTTPS_PORT, DATA_DIR, HTTPS_CERT_CN
from services.http_honey import _handle_client

_CERT_PATH = os.path.join(DATA_DIR, "https_honey_cert.pem")
_KEY_PATH = os.path.join(DATA_DIR, "https_honey_key.pem")


def _ensure_cert():
    """Generate a self-signed cert once and reuse it.

    Kept in DATA_DIR (a persisted volume) deliberately: a certificate whose
    fingerprint changes on every restart is itself a honeypot tell, and scanners
    like Shodan/Censys fingerprint exactly that.
    """
    if os.path.exists(_CERT_PATH) and os.path.exists(_KEY_PATH):
        return True

    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError:
        print("[HTTPS] cryptography not available — cannot generate cert, trap disabled")
        return False

    os.makedirs(DATA_DIR, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Subject mirrors what a neglected self-hosted box would present: a plain
    # hostname, no organisation, long validity.
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, HTTPS_CERT_CN),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=390))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(HTTPS_CERT_CN)]), critical=False
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    with open(_KEY_PATH, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    os.chmod(_KEY_PATH, 0o600)
    with open(_CERT_PATH, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"[HTTPS] Generated self-signed cert for {HTTPS_CERT_CN}")
    return True


def _build_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=_CERT_PATH, keyfile=_KEY_PATH)
    # Scanners routinely negotiate down to old versions to fingerprint a host, and
    # refusing them loses the observation. Accept whatever they offer.
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    except (ValueError, AttributeError):
        pass
    ctx.set_ciphers("ALL:@SECLEVEL=0")
    return ctx


def _handle_tls(raw_sock, addr, ctx):
    client_ip = addr[0]
    try:
        raw_sock.settimeout(20)
        tls_sock = ctx.wrap_socket(raw_sock, server_side=True)
    except Exception as e:
        # A failed handshake is still a probe worth recording — plenty of scanners
        # only ever grab the certificate and disconnect.
        log_event(client_ip, HTTPS_PORT, "HTTPS", "connect", {"tls_error": str(e)[:120]})
        try:
            raw_sock.close()
        except Exception:
            pass
        ratelimit.release()
        return

    # Handshake succeeded: hand the decrypted stream to the shared HTTP handler,
    # which releases the ratelimit slot and closes the socket itself.
    _handle_client(tls_sock, addr, port=HTTPS_PORT, service="HTTPS")


def start_https_server():
    if not _ensure_cert():
        return

    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            ctx = _build_context()
            sock.bind(("0.0.0.0", HTTPS_PORT))
            sock.listen(100)
            print(f"[HTTPS] Listening on port {HTTPS_PORT}")
            while True:
                client, addr = sock.accept()
                if not ratelimit.check_and_acquire(addr[0]):
                    client.close()
                    log_event(addr[0], HTTPS_PORT, "HTTPS", "rate_limited")
                    continue
                threading.Thread(target=_handle_tls, args=(client, addr, ctx), daemon=True).start()
        except Exception as e:
            print(f"[HTTPS] Crashed: {e} — restarting in 5s")
            time.sleep(5)
        finally:
            sock.close()
