import socket
import threading
import time
import traceback
import ratelimit
from logger import log_event
from alerts.discord import send_alert
from config import TELNET_PORT, TELNET_BANNER, TELNET_ACCEPT_RATE
from services.fake_shell import run_shell
from session_recorder import SessionRecorder

# Telnet negotiation bytes: WILL SUPPRESS-GO-AHEAD, WILL ECHO
_NEGOTIATE = b"\xff\xfb\x03\xff\xfb\x01"


def _recv_line(sock, send_fn, echo=True, max_len=1024):
    """Read one line from socket one byte at a time, discarding Telnet IAC sequences.
    Echoes characters back to the client via send_fn if echo is True — routed through
    a callback rather than sock.sendall directly so a caller can swap in a recording
    send_fn (see session_recorder.SessionRecorder) once a session is worth capturing,
    without this function needing to know anything about recording.
    """
    buf = b""
    while len(buf) < max_len:
        try:
            b = sock.recv(1)
            if not b:
                return None
            byte = b[0]

            if byte == 0xFF:  # IAC
                cmd = sock.recv(1)
                if not cmd:
                    return None
                cmd_byte = cmd[0]
                if cmd_byte in (0xFB, 0xFC, 0xFD, 0xFE):  # WILL, WONT, DO, DONT — 3-byte
                    sock.recv(1)  # consume option byte
                elif cmd_byte == 0xFA:  # SB — sub-negotiation, read until IAC SE
                    # Bounded: no legitimate sub-negotiation is anywhere near
                    # this long. Previously unbounded — trickling one byte at
                    # a time without ever sending IAC SE held the thread (and
                    # one of ratelimit.py's shared global connection slots)
                    # indefinitely, since each successful recv(1) refreshes
                    # the socket's own timeout.
                    prev = 0
                    for _ in range(256):
                        sb = sock.recv(1)
                        if not sb:
                            return None
                        if prev == 0xFF and sb[0] == 0xF0:  # IAC SE
                            break
                        prev = sb[0]
                    else:
                        return None
                continue

            if byte in (0x0D, 0x0A):  # CR or LF
                if echo:
                    send_fn("\r\n")
                # If it was just a lone LF/CR, we might get an empty string.
                # Real telnet often sends \r\n or \r\0.
                return buf.decode("utf-8", errors="ignore").strip()

            if byte in (0x08, 0x7F):  # Backspace
                if len(buf) > 0:
                    buf = buf[:-1]
                    if echo:
                        send_fn("\x08 \x08")
                continue

            buf += bytes([byte])
            if echo:
                send_fn(bytes([byte]).decode("utf-8", errors="replace"))
        except Exception:
            return None

    return buf.decode("utf-8", errors="ignore").strip()


def _raw_send(sock, x):
    try:
        sock.sendall(x.encode("utf-8", errors="replace"))
    except Exception:
        pass


def _handle_client(client_sock, client_addr):
    client_ip = client_addr[0]
    session = None
    try:
        log_event(client_ip, TELNET_PORT, "TELNET", "connect")
        send_alert("TELNET", client_ip, "New connection", alert_type="connect")

        client_sock.settimeout(120)
        client_sock.sendall(_NEGOTIATE)

        # Unrecorded send_fn for the negotiation/login phase — Telnet is by far the
        # highest-volume trap here, and almost all of that volume is single-shot
        # credential-stuffing that never reaches a shell. Recording from connect
        # would make "Sessions" mostly noise; see session_recorder.py.
        login_send = lambda x: _raw_send(client_sock, x)
        login_send(f"\r\n{TELNET_BANNER}\r\n\r\n")

        attempt_count = 0
        username = None

        while attempt_count < TELNET_ACCEPT_RATE:
            login_send("login: ")
            username = _recv_line(client_sock, login_send)
            if username is None:
                return

            login_send("Password: ")
            # Echo False for password
            password = _recv_line(client_sock, login_send, echo=False)
            if password is None:
                return
            login_send("\r\n")

            attempt_count += 1
            log_event(client_ip, TELNET_PORT, "TELNET", "credential",
                      {"username": username, "password": password})
            send_alert("TELNET", client_ip, f"Login attempt: `{username}` / `{password}`",
                       alert_type="credential")

            if attempt_count >= TELNET_ACCEPT_RATE:
                break

            login_send("Login incorrect\r\n\r\n")

        # Login succeeded — this is the "dropped into a shell" moment. Recording
        # starts here: create the session and rewrap send_fn before recv_line_fn is
        # built, so keystroke echo inside the shell is captured too, not just output.
        session = SessionRecorder(client_ip, TELNET_PORT, "TELNET", username)
        send_fn = session.wrap(lambda x: _raw_send(client_sock, x))

        def recv_line_fn():
            return _recv_line(client_sock, send_fn)

        run_shell(send_fn, recv_line_fn, client_ip, TELNET_PORT, "TELNET", username, session=session)

    except Exception:
        # traceback.print_exc()
        pass
    finally:
        if session:
            session.finalize()
        try:
            client_sock.close()
        except Exception:
            pass
        ratelimit.release()


def start_telnet_server():
    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("0.0.0.0", TELNET_PORT))
            sock.listen(100)
            print(f"[TELNET] Listening on port {TELNET_PORT}")
            while True:
                client, addr = sock.accept()
                if not ratelimit.check_and_acquire(addr[0]):
                    client.close()
                    log_event(addr[0], TELNET_PORT, "TELNET", "rate_limited")
                    continue
                threading.Thread(target=_handle_client, args=(client, addr), daemon=True).start()
        except Exception as e:
            print(f"[TELNET] Crashed: {e} — restarting in 5s")
            time.sleep(5)
        finally:
            sock.close()
