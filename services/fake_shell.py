import threading
import time
import json
import re
import google.generativeai as genai
from config import GEMINI_API_KEY
from logger import log_event
from alerts.discord import send_alert
from payloads import save_payload

# Max concurrent shell sessions across all services
_session_cap = threading.Semaphore(20)

# URL regex for download attempts
URL_REGEX = re.compile(r"https?://\S+")

# Configure Gemini if key is present
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
    _model = genai.GenerativeModel('gemini-1.5-flash')
else:
    _model = None

# Fake filesystem content
_FS = {
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
    "/etc/hostname": "ubuntu\n",
    "/etc/os-release": 'PRETTY_NAME="Ubuntu 22.04.3 LTS"\nNAME="Ubuntu"\nVERSION_ID="22.04"\n',
    "/proc/version": "Linux version 5.15.0-76-generic (buildd@lcy02-amd64-067) (gcc (Ubuntu 11.3.0-1ubuntu1~22.04.1) 11.3.0) #83-Ubuntu SMP Tue Jun 20 16:02:47 UTC 2023\n",
    "/var/log/auth.log": "Jul  4 10:20:01 ubuntu sshd[1234]: Accepted password for root from 1.2.3.4 port 54321 ssh2\n",
}

def _get_llm_response(cmd, cwd):
    """Get a realistic shell response from Gemini LLM."""
    if not _model:
        return f"bash: {cmd.split()[0] if cmd else ''}: command not found\r\n"
    
    prompt = f"""You are a Linux bash shell. The user is root on a server named 'ubuntu'.
Current working directory is '{cwd}'.
The user just typed this command: '{cmd}'
Respond with the EXACT output that a real Ubuntu 22.04 LTS shell would give.
Do not include any explanations or conversational text. ONLY the shell output.
If the command would produce no output, respond with an empty string.
"""
    try:
        response = _model.generate_content(prompt)
        text = response.text.strip()
        if text:
            # Normalize line endings for terminal
            return text.replace("\r\n", "\n").replace("\n", "\r\n") + "\r\n"
        return ""
    except Exception:
        return f"bash: {cmd.split()[0] if cmd else ''}: command not found\r\n"

def run_shell(send_fn, recv_line_fn, ip, port, service, username):
    """
    Runs a fake interactive shell with LLM fallback for unknown commands.
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
                
            line = line.strip()
            if not line:
                send_fn(f"root@ubuntu:{cwd}# ")
                continue
                
            # Log every command
            log_event(ip, port, service, "command", {"cmd": line, "cwd": cwd})
            
            # Dispatch
            parts = line.split()
            cmd = parts[0]
            args = parts[1:]
            
            if cmd in ("exit", "logout"):
                break
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
                else:
                    cwd = "/root"
            elif cmd == "cat":
                if args:
                    path = args[0]
                    if not path.startswith("/"):
                        full_path = f"{cwd}/{path}".replace("//", "/")
                    else:
                        full_path = path
                        
                    if full_path in _FS:
                        send_fn(_FS[full_path].replace("\n", "\r\n"))
                    else:
                        send_fn(f"cat: {path}: No such file or directory\r\n")
                else:
                    pass
            elif cmd in ("wget", "curl"):
                urls = URL_REGEX.findall(line)
                event = log_event(ip, port, service, "download_attempt", {"command": line, "urls": urls})
                send_alert(service, ip, f"Download attempt in shell: `{line}`", alert_type="download_attempt")
                save_payload(ip, service, line.encode(), event_id=event.get("rowid"))
                time.sleep(1)
                send_fn(f"{cmd}: connecting to {urls[0] if urls else 'remote host'}... failed: Connection refused.\r\n")
            else:
                # Use LLM for unknown commands
                llm_output = _get_llm_response(line, cwd)
                send_fn(llm_output)
                
            send_fn(f"root@ubuntu:{cwd}# ")
            
    finally:
        _session_cap.release()
