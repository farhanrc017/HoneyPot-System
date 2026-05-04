#!/usr/bin/env python3
"""
HoneyTrap v2 — Advanced Multi-Protocol Honeypot
Detects: Brute Force, SQLi, XSS, RCE, Path Traversal, Phishing indicators,
         MitM indicators, DDoS/Flood, Recon/Scanning, Malware C2, Backdoor
"""

import socket, threading, json, os, time, requests, logging, re, hashlib, sqlite3
from datetime import datetime
from dotenv import load_dotenv
load_dotenv()
from collections import defaultdict

# ─── CONFIG ────────────────────────────────────────────────────────────────
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID   = os.environ.get("TELEGRAM_CHAT_ID",   "")
DB_PATH  = os.path.join(os.path.dirname(__file__), "logs", "attacks.db")
LOG_PATH = os.path.join(os.path.dirname(__file__), "logs", "honeypot.log")

HONEYPOT_PORTS = {
    2222:  "SSH",
    8080:  "HTTP",
    2121:  "FTP",
    2323:  "Telnet",
    3307:  "MySQL",
    5901:  "VNC",
    6380:  "Redis",
    27018: "MongoDB",
    9200:  "Elasticsearch",
    5432:  "PostgreSQL",
}

# ─── LOGGING ───────────────────────────────────────────────────────────────
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOG_PATH), logging.StreamHandler()]
)
log = logging.getLogger("honeytrap")

# ─── DATABASE ──────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS attacks (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp    TEXT NOT NULL,
        ip           TEXT NOT NULL,
        port         INTEGER,
        service      TEXT,
        attack_cat   TEXT,
        attack_type  TEXT,
        severity     TEXT,
        confidence   INTEGER DEFAULT 70,
        payload      TEXT,
        country      TEXT DEFAULT 'Unknown',
        country_code TEXT DEFAULT 'XX',
        city         TEXT DEFAULT 'Unknown',
        isp          TEXT DEFAULT 'Unknown',
        asn          TEXT DEFAULT 'Unknown',
        flag_emoji   TEXT DEFAULT '🏳️',
        mitre_tactic TEXT DEFAULT '',
        mitre_tech   TEXT DEFAULT '',
        session_id   TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS ip_stats (
        ip           TEXT PRIMARY KEY,
        total_attempts INTEGER DEFAULT 0,
        risk_score   INTEGER DEFAULT 0,
        first_seen   TEXT,
        last_seen    TEXT,
        country      TEXT DEFAULT 'Unknown',
        country_code TEXT DEFAULT 'XX',
        flag_emoji   TEXT DEFAULT '🏳️',
        isp          TEXT DEFAULT 'Unknown',
        tags         TEXT DEFAULT ''
    )""")
    conn.commit(); conn.close()

# ─── COUNTRY FLAG EMOJI ────────────────────────────────────────────────────
COUNTRY_FLAGS = {
    "China":"🇨🇳","Russia":"🇷🇺","United States":"🇺🇸","Germany":"🇩🇪",
    "France":"🇫🇷","United Kingdom":"🇬🇧","India":"🇮🇳","Brazil":"🇧🇷",
    "Netherlands":"🇳🇱","Ukraine":"🇺🇦","Iran":"🇮🇷","Vietnam":"🇻🇳",
    "Romania":"🇷🇴","Turkey":"🇹🇷","Indonesia":"🇮🇩","South Korea":"🇰🇷",
    "Japan":"🇯🇵","Canada":"🇨🇦","Australia":"🇦🇺","Singapore":"🇸🇬",
    "Pakistan":"🇵🇰","Bangladesh":"🇧🇩","Nigeria":"🇳🇬","Mexico":"🇲🇽",
    "Argentina":"🇦🇷","Poland":"🇵🇱","Czech Republic":"🇨🇿","Sweden":"🇸🇪",
    "Hungary":"🇭🇺","Bulgaria":"🇧🇬","Local":"🏠","Unknown":"🏳️",
}

def get_flag(country):
    return COUNTRY_FLAGS.get(country, "🏳️")

# ─── GEO LOOKUP ────────────────────────────────────────────────────────────
_geo_cache = {}
def get_geo(ip):
    if ip in _geo_cache:
        return _geo_cache[ip]
    if any(ip.startswith(p) for p in ("127.","10.","192.168.","172.")):
        result = {"country":"Local","country_code":"LO","city":"LAN",
                  "isp":"Private Network","asn":"RFC1918","flag":"🏠"}
        _geo_cache[ip] = result
        return result
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,as",
            timeout=3)
        d = r.json()
        if d.get("status") == "success":
            result = {
                "country":      d.get("country","Unknown"),
                "country_code": d.get("countryCode","XX"),
                "city":         d.get("city","Unknown"),
                "isp":          d.get("isp","Unknown"),
                "asn":          (d.get("as","") or "Unknown").split()[0],
                "flag":         get_flag(d.get("country","Unknown")),
            }
            _geo_cache[ip] = result
            return result
    except Exception:
        pass
    result = {"country":"Unknown","country_code":"XX","city":"Unknown",
              "isp":"Unknown","asn":"Unknown","flag":"🏳️"}
    _geo_cache[ip] = result
    return result

# ─── MITRE ATT&CK MAP ──────────────────────────────────────────────────────
MITRE = {
    "DDoS":       ("Impact",            "T1498 – Network DoS"),
    "Phishing":   ("Initial Access",    "T1566 – Phishing"),
    "MitM":       ("Credential Access", "T1557 – Adversary-in-the-Middle"),
    "BruteForce": ("Credential Access", "T1110 – Brute Force"),
    "SQLi":       ("Initial Access",    "T1190 – Exploit Public-Facing App"),
    "XSS":        ("Execution",         "T1059.007 – JavaScript"),
    "RCE":        ("Execution",         "T1203 – Exploitation for Client Exec"),
    "Recon":      ("Reconnaissance",    "T1595 – Active Scanning"),
    "Malware":    ("Execution",         "T1204 – User Execution"),
    "Ransomware": ("Impact",            "T1486 – Data Encrypted for Impact"),
    "Backdoor":   ("Persistence",       "T1543 – Create/Modify System Process"),
    "C2":         ("Command & Control", "T1071 – App Layer Protocol"),
    "Exfil":      ("Exfiltration",      "T1041 – Exfil Over C2 Channel"),
    "BotNet":     ("Command & Control", "T1583 – Acquire Infrastructure"),
}

# ─── ADVANCED DETECTION PATTERNS ───────────────────────────────────────────
PATTERNS = [
    # ── SQL Injection ─────────────────────────────────────────────────────
    (r"union[\s\+]+select|select.{0,40}from|insert\s+into|drop\s+table|"
     r"truncate\s+table|exec\s*\(|xp_cmdshell|information_schema|"
     r"sleep\s*\(\d|benchmark\s*\(|load_file\s*\(|into\s+outfile|"
     r"'.*or.*'.*=.*'|1=1|1 or 1|admin'--",
     "SQLi", "SQL Injection", "high", 90),

    # ── XSS ──────────────────────────────────────────────────────────────
    (r"<script[\s>]|javascript:|vbscript:|onload\s*=|onerror\s*=|"
     r"onclick\s*=|onmouseover\s*=|alert\s*\(|document\.cookie|"
     r"document\.write|eval\s*\(|fromcharcode|&#x|%3cscript",
     "XSS", "Cross-Site Scripting (XSS)", "high", 88),

    # ── Remote Code Execution ─────────────────────────────────────────────
    (r";\s*(wget|curl|bash|sh|python|perl|ruby|nc|netcat|ncat)\s|"
     r"/bin/sh|/bin/bash|cmd\.exe|powershell|"
     r"system\s*\(|exec\s*\(|passthru|shell_exec|popen|proc_open|"
     r"`[^`]+`|\$\(.*\)|&&\s*(wget|curl|bash)|"
     r"base64_decode.*eval|eval.*base64",
     "RCE", "Remote Code Execution", "critical", 95),

    # ── Path Traversal ────────────────────────────────────────────────────
    (r"\.\./|\.\.\%2f|\.\.\%5c|%2e%2e/|\.\.\\|"
     r"/etc/passwd|/etc/shadow|/etc/hosts|/proc/self|"
     r"c:\\windows\\|c:/windows/|boot\.ini|win\.ini",
     "PathTraversal", "Path Traversal", "high", 92),

    # ── Phishing Indicators ───────────────────────────────────────────────
    (r"(paypal|apple|google|amazon|microsoft|facebook|instagram|"
     r"netflix|bank|secure|account|verify|update|confirm|"
     r"signin|login).*\.(tk|ml|ga|cf|gq|xyz|top|club|online|site)|"
     r"password.*=|passwd.*=|pwd.*=|credential|harvest",
     "Phishing", "Phishing – Credential Harvest", "high", 85),

    # ── MitM Indicators ──────────────────────────────────────────────────
    (r"arp\s+(spoof|poison|who-has)|"
     r"x-forwarded-proto:\s*http|"
     r"via:\s*\d+\.\d+\s+\S+-proxy|"
     r"ssl.strip|sslstrip|"
     r"x-real-ip|x-original-url.*https|"
     r"de:ad:be:ef|ca:fe:ba:be",
     "MitM", "Man-in-the-Middle Indicator", "critical", 80),

    # ── DDoS / Flood Patterns ─────────────────────────────────────────────
    (r"(GET|POST|HEAD)\s+/\s+HTTP.+\r?\n.+(GET|POST|HEAD)\s+/\s+HTTP|"
     r"slowloris|rudy\s+attack|r-u-dead-yet|"
     r"hping|loic|hoic|goldeneye|hulk\s+ddos|"
     r"connection:\s*keep-alive.{0,200}connection:\s*keep-alive",
     "DDoS", "DDoS / Application Layer Flood", "critical", 82),

    # ── Malware / C2 Beaconing ────────────────────────────────────────────
    (r"meterpreter|metasploit|cobalt.strike|empire\s+framework|"
     r"user-agent:\s*(python-requests|go-http|curl/|wget/|masscan|zgrab|"
     r"nikto|sqlmap|havij|acunetix|nessus|openvas)|"
     r"x5o!p%@ap\[4\\pzx54\(p\^|eicar|"
     r"cmd=|c2_beacon|implant",
     "Malware", "Malware / C2 Beacon", "critical", 88),

    # ── Ransomware Indicators ─────────────────────────────────────────────
    (r"\.encrypt|\.locked|\.ransom|your.files.are.encrypted|"
     r"bitcoin|btc.wallet|pay.*ransom|decrypt.*key|"
     r"shadow\s+copy|vssadmin\s+delete|wmic.*shadowcopy",
     "Ransomware", "Ransomware Indicator", "critical", 85),

    # ── Backdoor / Persistence ────────────────────────────────────────────
    (r"nc\s+-l\s+-p|netcat\s+-l|"
     r"crontab\s+-e|/etc/cron\.|at\s+now|"
     r"useradd|adduser|passwd\s+root|"
     r"authorized_keys|id_rsa|\.ssh/|"
     r"webshell|c99\.php|r57\.php|b374k",
     "Backdoor", "Backdoor / Persistence Attempt", "critical", 90),

    # ── Recon / Scanning ──────────────────────────────────────────────────
    (r"nmap|masscan|zmap|shodan|censys|nuclei|"
     r"dirbuster|gobuster|ffuf|wfuzz|dirb\s|"
     r"nessus|openvas|burpsuite|"
     r"\.well-known/security|robots\.txt|sitemap\.xml|"
     r"phpinfo|server-status|\.git/config|\.env",
     "Recon", "Recon / Active Scanning", "medium", 80),

    # ── Brute Force (generic) ─────────────────────────────────────────────
    (r"(root|admin|administrator|test|guest|oracle|sa|postgres|"
     r"ubuntu|pi|vagrant|ansible|deploy):("
     r"password|123456|admin|root|toor|pass|test|qwerty|"
     r"letmein|welcome|default|changeme)",
     "BruteForce", "Credential Brute Force", "medium", 85),

    # ── Data Exfiltration ─────────────────────────────────────────────────
    (r"select.*into\s+outfile|load\s+data\s+infile|"
     r"curl.*http.*\$\(|wget.*http.*&&|"
     r"base64\s+-w\s+0|base64\s+--wrap|"
     r"tar.*czf.*\|.*nc|zip.*-P.*\|.*curl",
     "Exfil", "Data Exfiltration Attempt", "critical", 87),

    # ── BotNet C2 ─────────────────────────────────────────────────────────
    (r"mirai|qbot|emotet|trickbot|dridex|"
     r"irc\s+bot|ircbot|botmaster|"
     r"!commands|!spread|!infect|"
     r"syn.flood|udp.flood|http.flood",
     "BotNet", "BotNet Command", "critical", 83),
]

# ─── SERVICE-LEVEL DEFAULT CLASSIFICATION ─────────────────────────────────
SERVICE_DEFAULTS = {
    "SSH":           ("BruteForce", "SSH Brute Force",          "medium", 75),
    "FTP":           ("BruteForce", "FTP Brute Force",          "medium", 75),
    "Telnet":        ("Recon",      "Telnet Probe",             "medium", 70),
    "MySQL":         ("Recon",      "DB Unauthorized Access",   "high",   78),
    "Redis":         ("Recon",      "Redis Unauthorized Access","high",   78),
    "MongoDB":       ("Recon",      "MongoDB Probe",            "high",   75),
    "Elasticsearch": ("Recon",      "Elasticsearch Probe",      "high",   75),
    "PostgreSQL":    ("Recon",      "PostgreSQL Probe",         "high",   75),
    "VNC":           ("BruteForce", "VNC Brute Force",         "medium", 70),
    "HTTP":          ("Recon",      "HTTP Probe",               "low",    60),
}

def classify(payload: str, service: str):
    p = payload.lower()
    for pattern, cat, atype, sev, conf in PATTERNS:
        if re.search(pattern, p, re.IGNORECASE | re.DOTALL):
            return cat, atype, sev, conf
    cat, atype, sev, conf = SERVICE_DEFAULTS.get(service,
        ("Recon","Unknown Probe","low",50))
    return cat, atype, sev, conf

# ─── SAVE TO DB ────────────────────────────────────────────────────────────
def save_attack(ip, port, service, cat, atype, sev, conf, payload, geo):
    ts  = datetime.utcnow().isoformat()
    sid = hashlib.md5(f"{ip}{port}{ts}".encode()).hexdigest()[:10]
    tactic, tech = MITRE.get(cat, ("",""))
    risk = {"low":3,"medium":8,"high":15,"critical":25}.get(sev,5)

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""INSERT INTO attacks
        (timestamp,ip,port,service,attack_cat,attack_type,severity,confidence,
         payload,country,country_code,city,isp,asn,flag_emoji,
         mitre_tactic,mitre_tech,session_id)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (ts, ip, port, service, cat, atype, sev, conf, payload[:1500],
         geo["country"], geo["country_code"], geo["city"],
         geo["isp"], geo["asn"], geo["flag"],
         tactic, tech, sid))
    c.execute("""INSERT INTO ip_stats
        (ip,total_attempts,risk_score,first_seen,last_seen,
         country,country_code,flag_emoji,isp)
        VALUES(?,1,?,?,?,?,?,?,?)
        ON CONFLICT(ip) DO UPDATE SET
          total_attempts=total_attempts+1,
          risk_score=MIN(100,risk_score+?),
          last_seen=excluded.last_seen""",
        (ip, risk, ts, ts,
         geo["country"], geo["country_code"], geo["flag"], geo["isp"],
         risk))
    conn.commit(); conn.close()
    log.warning(f"[{service}] {cat} | {atype} | {ip} ({geo['flag']} {geo['country']}) | {sev}")
    return sid, ts

# ─── RATE LIMITER (suppress duplicate TG alerts) ──────────────────────────
_rate = defaultdict(list)
_rl   = threading.Lock()
def is_rate_limited(ip):
    now = time.time()
    with _rl:
        _rate[ip] = [t for t in _rate[ip] if now-t < 60]
        count = len(_rate[ip])
        _rate[ip].append(now)
    return count > 20

# ─── TELEGRAM ──────────────────────────────────────────────────────────────
SEV_EMOJI = {"low":"🟡","medium":"🟠","high":"🔴","critical":"🚨"}
CAT_EMOJI = {
    "DDoS":"💥","Phishing":"🎣","MitM":"🕵️","BruteForce":"🔑",
    "SQLi":"💉","XSS":"📜","RCE":"💻","Recon":"🔭",
    "Ransomware":"💰","Malware":"🦠","Backdoor":"🚪",
    "C2":"📡","BotNet":"🤖","Exfil":"📤","PathTraversal":"📂",
}

def send_telegram(ip, port, service, cat, atype, sev, conf, geo, sid, ts, payload=""):
    if not TELEGRAM_BOT_TOKEN: return
    se = SEV_EMOJI.get(sev,"⚠️")
    ce = CAT_EMOJI.get(cat,"🔴")
    tactic, tech = MITRE.get(cat, ("Unknown","Unknown"))
    msg_parts = [
        f"{se}{ce} *HoneyTrap — {cat} Detected*",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"🕒 `{ts[:19]} UTC`",
        f"🌐 *IP:* `{ip}` on *{service}* port `{port}`",
        f"{geo['flag']} *Location:* {geo['city']}, {geo['country']}",
        f"🏢 *ISP:* {geo['isp']}  |  *ASN:* {geo['asn']}",
        f"⚔️ *Attack:* `{atype}`",
        f"📊 *Severity:* `{sev.upper()}`  🎯 *Confidence:* `{conf}%`",
        f"🛡 *MITRE:* [{tactic}] {tech}",
        f"🔑 *Session:* `{sid}`",
    ]
    if payload:
        short = payload[:250].replace("`","'")
        msg_parts.append(f"📦 *Payload:*\n```\n{short}\n```")
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            json={"chat_id":TELEGRAM_CHAT_ID,"text":"\n".join(msg_parts),
                  "parse_mode":"Markdown"},
            timeout=5)
    except Exception as e:
        log.warning(f"Telegram error: {e}")

# ─── FAKE BANNERS ─────────────────────────────────────────────────────────
BANNERS = {
    "SSH":           b"SSH-2.0-OpenSSH_9.3p1 Ubuntu-3ubuntu0.3\r\n",
    "FTP":           b"220 FileZilla Server 1.7.0\r\n",
    "Telnet":        b"\xff\xfb\x01\xff\xfb\x03\r\nUbuntu 22.04 LTS\r\nlogin: ",
    "MySQL":         b"\x4a\x00\x00\x00\x0a\x38\x2e\x30\x2e\x33\x35\x00",
    "HTTP":          b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Length: 0\r\n\r\n",
    "VNC":           b"RFB 003.008\n",
    "Redis":         b"+PONG\r\n",
    "MongoDB":       b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    "Elasticsearch": b'{"name":"node-1","cluster_name":"elasticsearch"}\n',
    "PostgreSQL":    b"R\x00\x00\x00\x08\x00\x00\x00\x00",
}

# ─── DDOS RATE TRACKER ────────────────────────────────────────────────────
_ddos_tracker = defaultdict(list)
_ddos_lock    = threading.Lock()
DDOS_THRESHOLD = 25  # connections per 10 seconds per IP

def check_ddos(ip, port):
    now = time.time()
    with _ddos_lock:
        _ddos_tracker[ip] = [t for t in _ddos_tracker[ip] if now-t < 10]
        _ddos_tracker[ip].append(now)
        rate = len(_ddos_tracker[ip])
    if rate >= DDOS_THRESHOLD:
        return True, rate
    return False, rate

# ─── CLIENT HANDLER ───────────────────────────────────────────────────────
def handle_client(conn, addr, port, service):
    ip = addr[0]
    try:
        conn.settimeout(2)
        raw = b""

        # --- RECEIVE DATA FIRST ---
        try:
            chunk = conn.recv(1024)
            if chunk:
                raw += chunk

            while True:
                try:
                    chunk = conn.recv(1024)
                    if not chunk:
                        break
                    raw += chunk
                except socket.timeout:
                    break
        except Exception:
            pass

        # --- SEND BANNER AFTER ---
                # --- SEND BANNER ---
        banner = BANNERS.get(service, b"")
        if banner:
            try:
                conn.sendall(banner)
            except Exception:
                pass

        # --- CAPTURE ATTACKER INPUT ---
        raw = b""

        if service == "SSH":
            try:
                conn.settimeout(30)

                conn.sendall(b"login: ")
                user = b""
                while not user.endswith(b"\n"):
                    chunk = conn.recv(1024)
                    if not chunk:
                        break
                    user += chunk

                conn.sendall(b"Password: ")
                pwd = b""
                while not pwd.endswith(b"\n"):
                    chunk = conn.recv(1024)
                    if not chunk:
                        break
                    pwd += chunk

                raw = user.strip() + b":" + pwd.strip()

                time.sleep(1)
                conn.sendall(b"\nAccess denied\r\n")

            except Exception as e:
                log.debug(f"SSH simulation error ({ip}): {e}")

        else:
            # --- OTHER SERVICES INPUT ---
            conn.settimeout(15)
            try:
                while True:
                    chunk = conn.recv(1024)
                    if not chunk:
                        break
                    raw += chunk
            except socket.timeout:
                pass

        # --- PROCESS PAYLOAD ---
        payload = raw.decode("utf-8", errors="replace").strip()

        # --- HANDLE EMPTY PAYLOAD ---
        if not payload:
            cat  = "Recon"
            atype = f"{service} Scan / Connection"
            sev  = "low"
            conf = 60
        else:
            cat, atype, sev, conf = classify(payload, service)

        # --- DEBUG LOG ---
        log.info(f"Connection from {ip}:{port} | Payload: {payload}")

        # --- GEO ---
        geo = get_geo(ip)

        # --- SAVE ATTACK ---
        session_id, ts = save_attack(
            ip, port, service, cat, atype, sev, conf, payload, geo
        )

        # --- TELEGRAM ALERT ---
        if not is_rate_limited(ip):
            threading.Thread(
                target=send_telegram,
                args=(ip, port, service, cat, atype, sev, conf, geo, session_id, ts, payload),
                daemon=True,
            ).start()
    except Exception as e: 
                log.debug(f"handle_client error ({ip}): {e}") 
    finally: 
                try: conn.close() 
                except Exception:
                    pass

# ─── LISTENER ─────────────────────────────────────────────────────────────
def start_listener(port, service):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port))
        s.listen(100)
        log.info(f"[*] {service} honeypot on port {port}")
        while True:
            try:
                conn, addr = s.accept()
                threading.Thread(target=handle_client,
                    args=(conn,addr,port,service),daemon=True).start()
            except Exception as e:
                log.error(f"Accept error {port}: {e}")
    except PermissionError:
        log.error(f"Cannot bind port {port} (need root for <1024)")
    except Exception as e:
        log.error(f"Listener {port} failed: {e}")

# ─── MAIN ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    log.info("="*55)
    log.info("  HoneyTrap v2 — Advanced Detection Engine")
    log.info("="*55)
    init_db()
    for port, service in HONEYPOT_PORTS.items():
        threading.Thread(target=start_listener,args=(port,service),daemon=True).start()
    log.info(f"{len(HONEYPOT_PORTS)} honeypot listeners active")
    log.info("Dashboard → http://localhost:5000")
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        log.info("Shutting down.")