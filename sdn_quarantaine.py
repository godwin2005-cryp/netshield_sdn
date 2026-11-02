import json
import time
import os
import threading
import subprocess
import re
import socket
import ipaddress
import urllib.request
import urllib.parse
import requests
from datetime import datetime
from flask import Flask, render_template_string, jsonify, request, send_file
try:
    import paramiko
    PARAMIKO_OK = True
except ImportError:
    PARAMIKO_OK = False
from netmiko import ConnectHandler

# Charge les variables d'environnement depuis .env si python-dotenv est disponible
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------
SWITCH_PARAMS = {
    'device_type': 'tplink_jetstream_telnet',
    'host':     os.environ.get('SWITCH_HOST',   '192.168.0.1'),
    'username': os.environ.get('SWITCH_USER',   'admin'),
    'password': os.environ.get('SWITCH_PASS',   'admin'),
    'secret':   os.environ.get('SWITCH_SECRET', 'admin'),
    'conn_timeout': 20,
    'global_delay_factor': 2,
}

PORT_MONITORING   = "1/0/1"
PORT_UPLINK       = "1/0/28"    # Port qui apporte la connexion Internet
# Ports jamais mis en quarantaine — port mirroring Suricata + uplink Internet
PROTECTED_PORTS   = {PORT_MONITORING, PORT_UPLINK}
VLAN_QUARANTAINE  = 666
VLAN_NORMAL       = 1
TRUSTED_VLANS     = '1,10'
SURICATA_LOG      = "/var/log/suricata/eve.json"
HOME_NET          = "192.168.0.0/24"
SWITCH_PORT_COUNT = 28          # T1600G-28PS : 24 GE + 4 SFP+

# Mapping port actif → port backup
# Ports 2-14 : actifs (employés)  |  Ports 15-27 : backup (éteints par défaut)
# Port 2 ↔ 15, Port 3 ↔ 16, ..., Port 14 ↔ 27
PORT_BACKUP_MAP = {str(i): str(i + 13) for i in range(2, 15)}
# Inverse : backup → actif
PORT_PRIMARY_MAP = {v: k for k, v in PORT_BACKUP_MAP.items()}

# IPs qui ne doivent JAMAIS être mises en quarantaine (serveurs, switch, gateway).
# Si l'une de ces IPs est la CIBLE d'une attaque → seul l'attaquant est banni.
PROTECTED_IPS = {
    '192.168.0.1',    # Switch / Gateway
    '192.168.0.10',   # Serveur SDN (cette machine) — NE JAMAIS quarantiner
    '127.0.0.1',
}

# MACs qui ne doivent JAMAIS être bannis.
PROTECTED_MACS = {
    'f4:ee:08:a5:17:d0',
}

# ---------------------------------------------------------------------------
# DONNÉES GLOBALES
# ---------------------------------------------------------------------------
_lock                  = threading.Lock()   # protège toutes les structures ci-dessous
_sw_sem                = threading.Semaphore(1)  # 1 seule connexion Telnet à la fois
_persistent_nc         = None               # connexion Telnet persistante (évite reconnexion)
_sw_table_cache        = {'mac': '', 'arp': '', 'ts': 0}  # cache tables switch
_admin_op_pending      = False              # True pendant une action admin → cache/watchdog pausés
monitoring_active      = False
WARN_DURATION_SEC      = 8    # secondes d'affichage de la page d'avertissement
backup_ports_active    = {}   # {port_backup: port_primaire} — ports backup actuellement allumés
alerts_list            = []
quarantined_list       = []      # machines actuellement en VLAN 666
mac_blacklist          = set()   # MACs bloqués sur tous les ports
logs_list              = []
mac_history            = {}
machine_info_cache     = {}
switch_cmd_log         = []      # Journal de toutes les commandes envoyées au switch
_quarantine_cooldown   = {}      # {ip: timestamp} — anti-spam quarantaine par IP
_alert_rate            = {}      # {ip: [timestamps]} — compteur volumétrie par IP
_alert_dedup           = {}      # {ip: last_ts} — déduplique rafales Suricata (0.5s)
_suspects              = {}      # {ip: {count, first_ts, last_ts, last_sig, dst}} visible dashboard
DEDUP_WINDOW_SEC       = 0.5    # même IP source dans 0.5s = même événement (multi-règles)

MAX_MACHINE_CACHE      = 500
QUARANTINE_DELAY_SEC   = 60
ALERT_THRESHOLD        = 3       # nb d'alertes nécessaires pour déclencher la quarantaine
ALERT_WINDOW_SEC       = 10      # fenêtre de temps pour compter les alertes (secondes)
STATE_FILE             = '/home/dell/sdn_state.json'

AGENT_LISTEN_PORT = 9999   # port local sur chaque PC cible — reçoit les notifications

# ---------------------------------------------------------------------------
# DÉPLOIEMENT AGENT — TOUTES LES MÉTHODES
# ---------------------------------------------------------------------------
AGENT_EXE         = '/home/dell/NetShield_Agent'
AGENT_REMOTE_PATH = '/tmp/.netshield_agent'
AGENT_SHARE_PATH  = '/srv/netshield'          # Partage Samba/HTTP
SSH_PORT          = 22
_deployed_ips     = set()

# Identifiants SSH à essayer (du plus probable au moins probable)
SSH_CREDENTIALS = [
    ('dell',  'dell'),
    ('kali',  'kali'),
    ('root',  'root'),
    ('admin', 'admin'),
    ('user',  'user'),
    ('pi',    'raspberry'),
]

def _get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('192.168.0.1', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '192.168.0.10'

def _detect_display_ssh(ssh):
    """Détecte le DISPLAY actif sur le PC distant via SSH."""
    for cmd in [
        'echo $DISPLAY',
        'ls /tmp/.X11-unix/ 2>/dev/null | head -1 | sed "s/X/:/"',
        'who | grep -oP ":\\d+" | head -1',
    ]:
        try:
            _, out, _ = ssh.exec_command(cmd)
            val = out.read().decode().strip()
            if val and val.startswith(':'):
                return val
        except Exception:
            pass
    return ':0'

def _method_ssh(ip):
    """Méthode 1 : SSH + SCP — essaie plusieurs identifiants, lance avec DISPLAY."""
    if not PARAMIKO_OK:
        return False
    for user, pwd in SSH_CREDENTIALS:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, port=SSH_PORT, username=user, password=pwd, timeout=6)

            sftp = ssh.open_sftp()
            sftp.put(AGENT_EXE, AGENT_REMOTE_PATH)
            sftp.chmod(AGENT_REMOTE_PATH, 0o755)
            sftp.close()

            display   = _detect_display_ssh(ssh)
            xauth     = f'/home/{user}/.Xauthority'
            launch    = (
                f'DISPLAY={display} XAUTHORITY={xauth} '
                f'nohup {AGENT_REMOTE_PATH} > /dev/null 2>&1 &'
            )
            ssh.exec_command(launch)
            ssh.close()
            add_log(f"[DEPLOY] ✅ SSH ({user}@{ip}) DISPLAY={display}", "success")
            return True
        except Exception:
            continue
    return False

def _method_samba(ip):
    """Méthode 2 : Copie via Samba (partages Linux/Windows courants)."""
    shares = ['C$', 'Users', 'home', 'Public', 'share']
    for share in shares:
        try:
            cmd = [
                'smbclient', f'//{ip}/{share}', '-N', '-c',
                f'put {AGENT_EXE} .netshield_agent; exit'
            ]
            r = subprocess.run(cmd, capture_output=True, timeout=8)
            if r.returncode == 0:
                add_log(f"[DEPLOY] ✅ Samba ({share}) → {ip}", "success")
                return True
        except Exception:
            continue
    return False

def _method_http_notify(ip):
    """Méthode 3 : lien HTTP — l'utilisateur télécharge l'agent manuellement."""
    local_ip = _get_local_ip()
    url = f"http://{local_ip}:5000/download/agent"
    add_log(
        f"[DEPLOY] ℹ️ {ip} — SSH/Samba inaccessibles. "
        f"Lien manuel : {url}",
        "warning"
    )

def _deploy_agent_to(ip):
    """Essaie SSH → Samba → HTTP dans l'ordre, marque l'IP comme déployée."""
    if not os.path.exists(AGENT_EXE):
        add_log(f"[DEPLOY] ⚠️ Exécutable absent : {AGENT_EXE}", "warning")
        return
    if _method_ssh(ip):
        _deployed_ips.add(ip); return
    if _method_samba(ip):
        _deployed_ips.add(ip); return
    _method_http_notify(ip)

def _notify_agent_quarantine(ip, qinfo):
    """
    Notifie l'agent AVANT le switch VLAN pour qu'il reçoive le signal
    tant qu'il a encore la connectivité réseau.
    """
    try:
        requests.post(
            f"http://{ip}:{AGENT_LISTEN_PORT}/quarantine",
            json=qinfo, timeout=1
        )
        add_log(f"[AGENT] ✅ Écran rouge → {ip}", "success")
    except Exception:
        pass

def _notify_agent_release(ip):
    """Notifie l'agent que la quarantaine est levée."""
    try:
        requests.post(
            f"http://{ip}:{AGENT_LISTEN_PORT}/release",
            json={}, timeout=1
        )
    except Exception:
        pass

def _discover_ips_ping(subnet):
    """Ping sweep rapide du sous-réseau — retourne les IPs qui répondent."""
    ips = set()
    try:
        r = subprocess.run(
            ['fping', '-a', '-g', subnet, '-t', '300'],
            capture_output=True, text=True, timeout=15
        )
        for line in r.stdout.splitlines():
            ip = line.strip()
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                ips.add(ip)
    except FileNotFoundError:
        # fping absent → nmap fallback
        try:
            r = subprocess.run(
                ['nmap', '-sn', '--min-rate', '500', subnet],
                capture_output=True, text=True, timeout=20
            )
            for line in r.stdout.splitlines():
                m = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if m:
                    ips.add(m.group(1))
        except Exception:
            pass
    except Exception:
        pass
    return ips

def _discover_ips_arp(nc):
    """Lit la table ARP du switch — retourne les IPs connues."""
    ips = set()
    try:
        arp_table = nc.send_command("show arp")
        for line in arp_table.splitlines():
            for token in line.split():
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', token):
                    ips.add(token)
                    break
    except Exception:
        pass
    return ips

def deploy_agent_all():
    """
    Découvre tous les hôtes actifs (ARP switch + ping sweep)
    et déploie l'agent sur chacun en parallèle.
    """
    if not os.path.exists(AGENT_EXE):
        add_log("[DEPLOY] ⚠️ NetShield_Agent introuvable — déploiement ignoré", "warning")
        return

    local_ip = _get_local_ip()
    # Déduire le sous-réseau à partir de l'IP locale (ex: 192.168.0.0/24)
    try:
        subnet = str(ipaddress.ip_network(f"{local_ip}/24", strict=False))
    except Exception:
        subnet = "192.168.0.0/24"

    # Découverte combinée
    ips_arp  = set()
    nc = None
    try:
        nc = _connect()
        ips_arp = _discover_ips_arp(nc)
        nc.disconnect()
    except Exception:
        if nc:
            try: nc.disconnect()
            except: pass

    ips_ping = _discover_ips_ping(subnet)
    all_ips  = (ips_arp | ips_ping) - PROTECTED_IPS - _deployed_ips - {local_ip}

    if not all_ips:
        add_log("[DEPLOY] Aucun PC découvert sur le réseau", "info")
        return

    add_log(f"[DEPLOY] {len(all_ips)} PC(s) découvert(s) — déploiement agent en cours...", "info")
    for ip in all_ips:
        threading.Thread(target=_deploy_agent_to, args=(ip,), daemon=True).start()

# ---------------------------------------------------------------------------
# TELEGRAM BOT
# ---------------------------------------------------------------------------
TELEGRAM_TOKEN   = os.environ.get('TELEGRAM_TOKEN',   '')  # défini via variable d'environnement, jamais en dur
TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '')

# ---------------------------------------------------------------------------
# PERSISTANCE ÉTAT
# ---------------------------------------------------------------------------
def _persist_state():
    """Sauvegarde l'état critique sur disque."""
    try:
        with _lock:
            data = {
                'quarantined_list': quarantined_list,
                'mac_blacklist':    list(mac_blacklist),
                'alerts_list':      alerts_list[-500:],
                'mac_history':      mac_history,
                'telegram_chat_id': TELEGRAM_CHAT_ID,
                'monitoring_active': monitoring_active,
            }
        with open(STATE_FILE, 'w') as f:
            json.dump(data, f, indent=2, default=str)
    except Exception:
        pass

def _load_state():
    """Recharge l'état depuis le disque au démarrage."""
    global quarantined_list, mac_blacklist, alerts_list, mac_history, TELEGRAM_CHAT_ID
    if not os.path.exists(STATE_FILE):
        return
    try:
        with open(STATE_FILE) as f:
            data = json.load(f)
        with _lock:
            quarantined_list[:] = data.get('quarantined_list', [])
            mac_blacklist.clear()
            mac_blacklist.update(data.get('mac_blacklist', []))
            alerts_list[:] = data.get('alerts_list', [])
            mac_history.update(data.get('mac_history', {}))
        if data.get('telegram_chat_id'):
            TELEGRAM_CHAT_ID = data['telegram_chat_id']
    except Exception:
        pass


def _tg_api(endpoint, payload):
    """Appel bas-niveau à l'API Telegram (stdlib uniquement)."""
    if not TELEGRAM_TOKEN:
        return None
    try:
        data = urllib.parse.urlencode(payload).encode()
        req  = urllib.request.Request(
            f'https://api.telegram.org/bot{TELEGRAM_TOKEN}/{endpoint}',
            data=data, method='POST'
        )
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        with urllib.request.urlopen(req, timeout=6) as resp:
            return json.loads(resp.read())
    except Exception as e:
        add_log(f"[TELEGRAM] Erreur API ({endpoint}): {e}", "warning")
        return None


def telegram_auto_detect_chat():
    """Récupère automatiquement le chat_id depuis getUpdates."""
    global TELEGRAM_CHAT_ID
    if TELEGRAM_CHAT_ID:
        return TELEGRAM_CHAT_ID
    result = _tg_api('getUpdates', {'limit': 5, 'timeout': 0})
    if result and result.get('ok'):
        for upd in result.get('result', []):
            cid = (upd.get('message') or upd.get('callback_query', {}).get('message', {})).get('chat', {}).get('id')
            if cid:
                TELEGRAM_CHAT_ID = str(cid)
                _persist_state()
                add_log(f"[TELEGRAM] Chat ID détecté : {TELEGRAM_CHAT_ID}", "success")
                return TELEGRAM_CHAT_ID
    return None


def send_telegram(message):
    """Envoie un message HTML au bot Telegram."""
    global TELEGRAM_CHAT_ID
    if not TELEGRAM_TOKEN:
        return
    if not TELEGRAM_CHAT_ID:
        telegram_auto_detect_chat()
    if not TELEGRAM_CHAT_ID:
        add_log("[TELEGRAM] chat_id inconnu — envoie /start au bot @sdnquarantaine_bot", "warning")
        return
    _tg_api('sendMessage', {
        'chat_id':    TELEGRAM_CHAT_ID,
        'text':       message,
        'parse_mode': 'HTML',
    })


def _telegram_alert_quarantine(entry):
    """Construit et envoie l'alerte complète pour une mise en quarantaine."""
    def f(d, k):
        v = (d or {}).get(k)
        return v if v and v not in ('Unknown', 'N/A', '') else '—'

    atk = entry.get('attacker_info') or {}
    vic = entry.get('victim_info')   or {}

    lines = [
        f"🚨 <b>ALERTE SDN SECURITY</b> 🚨",
        "",
        f"⚔️ <b>ATTAQUANT</b>",
        f"  • IP  : <code>{entry.get('attacker_ip', 'N/A')}</code>",
        f"  • MAC : <code>{entry.get('attacker_mac', 'N/A')}</code>",
        f"  • Port : <code>{entry.get('attacker_port', 'N/A')}</code>  →  <b>VLAN 666</b>",
        f"  • Hostname  : {f(atk, 'hostname')}",
        f"  • OS        : {f(atk, 'os')[:60]}",
        f"  • Modèle    : {f(atk, 'model')}",
        f"  • Fabricant : {f(atk, 'vendor')}",
        f"  • N° Série  : {f(atk, 'serial')}",
        "",
        f"🎯 <b>VICTIME / SERVEUR</b>",
        f"  • IP  : <code>{entry.get('victim_ip', 'N/A')}</code>",
        f"  • MAC : <code>{entry.get('victim_mac', 'N/A')}</code>",
        f"  • Port : <code>{entry.get('victim_port', 'N/A')}</code>",
        f"  • Hostname  : {f(vic, 'hostname')}",
        f"  • OS        : {f(vic, 'os')[:60]}",
        f"  • Modèle    : {f(vic, 'model')}",
        f"  • N° Série  : {f(vic, 'serial')}",
        "",
        f"🦠 <b>Attaque</b> : {entry.get('attack_icon', '')} {entry.get('attack_desc', '')}",
        f"📋 <b>Signature</b> : {entry.get('signature', '?')} — SID {entry.get('sid', '?')}",
        f"⚡ <b>Mode</b> : {entry.get('mode', '')}",
        f"🕐 <b>Heure</b> : {entry.get('time', '')}",
    ]
    send_telegram('\n'.join(lines))

# ---------------------------------------------------------------------------
# PATTERNS SURICATA (SIDs 1000001-1000011 — local.rules)
# ---------------------------------------------------------------------------
ATTACK_PATTERNS = {
    'PING_SCAN': {
        'patterns': ['ALERTE PING', 'PING DETECTE'],
        'sids': [1000001],
        'color': '#00ffcc', 'icon': '🏓', 'description': 'Ping / Scan ICMP',
    },
    'DDOS_FLOOD': {
        'patterns': ['[ATTACK]', 'DDOS', 'FLOOD DETECTE', 'SYN FLOOD', 'UDP FLOOD', 'ICMP FLOOD', 'FLOOD DETECTED'],
        'sids': [1000002, 1000003, 1000012],
        'color': '#ff0000', 'icon': '💥', 'description': 'DDoS / Flooding',
    },
    'NETWORK_SCAN': {
        'patterns': ['[SCAN]', 'TENTATIVE DE SCAN', 'SCAN TCP', 'SCAN UDP', 'NMAP', 'MASSCAN'],
        'sids': [1000004, 1000005],
        'color': '#ff8800', 'icon': '🔍', 'description': 'Scan Réseau',
    },
    'BRUTE_FORCE': {
        'patterns': ['[AUTH]', 'BRUTE FORCE', 'SSH SUSPECT', 'TELNET SUSPECT'],
        'sids': [1000006, 1000007],
        'color': '#ff00ff', 'icon': '🔨', 'description': 'Brute Force',
    },
    'C2_MALWARE': {
        'patterns': ['[C2]', 'METASPLOIT', 'FLUX SUSPECT', 'REVERSE SHELL', 'BACKDOOR', 'TROJAN'],
        'sids': [1000008, 1000009],
        'color': '#8800ff', 'icon': '💀', 'description': 'C2 / Malware',
    },
    'RANSOMWARE': {
        'patterns': ['[MALWARE]', 'RANSOMWARE', 'PROPAGATION RANSOMWARE', 'SMB', 'RPC'],
        'sids': [1000010, 1000011],
        'color': '#00ffff', 'icon': '🔐', 'description': 'Ransomware',
    },
}

ATTACK_SID_MAP = {
    1000001: 'PING_SCAN',
    1000002: 'DDOS_FLOOD',  1000003: 'DDOS_FLOOD',  1000012: 'DDOS_FLOOD',
    1000004: 'NETWORK_SCAN', 1000005: 'NETWORK_SCAN',
    1000006: 'BRUTE_FORCE', 1000007: 'BRUTE_FORCE',
    1000008: 'C2_MALWARE',  1000009: 'C2_MALWARE',
    1000010: 'RANSOMWARE',  1000011: 'RANSOMWARE',
}

# ---------------------------------------------------------------------------
# UTILITAIRES RÉSEAU
# ---------------------------------------------------------------------------

def is_local_ip(ip):
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(HOME_NET, strict=False)
    except Exception:
        return False


def is_protected_ip(ip):
    """Retourne True si l'IP est un serveur/équipement qui ne doit jamais être mis en quarantaine."""
    return ip in PROTECTED_IPS


def detect_attack_type(signature, sid=None):
    if sid and sid in ATTACK_SID_MAP:
        return ATTACK_SID_MAP[sid]
    sig_upper = signature.upper()
    for atype, cfg in ATTACK_PATTERNS.items():
        for p in cfg['patterns']:
            if p.upper() in sig_upper:
                return atype
    return 'UNKNOWN'


def determine_strategy(src_ip, dst_ip):
    """
    Priorité 1 — cible protégée (serveur, switch, gateway) :
      SERVER_LOCAL_ATTACK   : attaquant LOCAL  cible un serveur protégé → ban attaquant seul
      SERVER_EXTERNAL_ATTACK: attaquant EXTERNE cible un serveur protégé → log uniquement
                               (impossible d'agir côté switch sur un IP externe)

    Priorité 2 — cas standard :
      DUAL_QUARANTINE  : les deux IPs sont locales
      PROTECT_VICTIM   : attaquant externe, victime locale
      ISOLATE_ATTACKER : attaquant local, victime externe
      EXTERNAL_ONLY    : les deux externes (log uniquement)
    """
    src_local = is_local_ip(src_ip)
    dst_local = is_local_ip(dst_ip)

    # Source protégée → ne jamais agir (trafic de réponse du serveur/switch)
    if is_protected_ip(src_ip):
        return 'EXTERNAL_ONLY', src_ip, dst_ip

    # --- La cible est un serveur/équipement protégé ---
    if is_protected_ip(dst_ip):
        if src_local:
            # Attaquant local qui s'en prend au serveur → ban l'attaquant uniquement
            return 'SERVER_LOCAL_ATTACK', src_ip, dst_ip
        else:
            # Attaquant externe visant le serveur → on ne peut pas agir sur le switch
            return 'SERVER_EXTERNAL_ATTACK', src_ip, dst_ip

    # --- Cas standard ---
    if src_local and dst_local:
        return 'DUAL_QUARANTINE',  src_ip, dst_ip
    if not src_local and dst_local:
        return 'PROTECT_VICTIM',   src_ip, dst_ip
    if src_local and not dst_local:
        return 'ISOLATE_ATTACKER', src_ip, dst_ip
    return 'EXTERNAL_ONLY', src_ip, dst_ip


def add_log(message, level='info'):
    ts = datetime.now().strftime('%H:%M:%S')
    with _lock:
        logs_list.insert(0, {'time': ts, 'message': message, 'level': level})
        if len(logs_list) > 150:
            logs_list.pop()


def log_switch_cmd(port, commands, reason=''):
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with _lock:
        switch_cmd_log.insert(0, {
            'time':     ts,
            'port':     port,
            'commands': commands,
            'reason':   reason,
        })
        if len(switch_cmd_log) > 100:
            switch_cmd_log.pop()

# ---------------------------------------------------------------------------
# SCAN MACHINE (hostname, OS, modèle, fabricant, numéro de série)
# ---------------------------------------------------------------------------

_BAD_SERIALS = {'', 'n/a', 'none', 'unknown', 'to be filled by o.e.m.',
                'default string', '0', 'not specified', 'system serial number'}

def _snmp_val(ip, oid, timeout=3):
    """snmpget simple — renvoie la valeur STRING ou None."""
    try:
        r = subprocess.run(
            ['snmpget', '-v2c', '-c', 'public', '-t', str(timeout), '-r', '1', ip, oid],
            capture_output=True, text=True, timeout=timeout + 1)
        if 'STRING:' in r.stdout:
            return r.stdout.split('STRING:')[1].strip().strip('"').strip()
    except Exception:
        pass
    return None

def _snmpwalk_first(ip, oid_base, timeout=5):
    """snmpwalk — renvoie la première valeur STRING ou None."""
    try:
        r = subprocess.run(
            ['snmpwalk', '-v2c', '-c', 'public', '-t', str(timeout), ip, oid_base],
            capture_output=True, text=True, timeout=timeout + 1)
        for line in r.stdout.splitlines():
            if 'STRING:' in line:
                val = line.split('STRING:')[1].strip().strip('"').strip()
                if val.lower() not in _BAD_SERIALS:
                    return val
    except Exception:
        pass
    return None

def _get_lldp_neighbor_info(port):
    """Interroge le switch pour les infos LLDP du voisin sur le port donné."""
    result = {}
    try:
        nc = _connect()
        try:
            out = nc.send_command(
                f'show lldp neighbor-information interface gigabitEthernet 1/0/{port}',
                expect_string=r'#', read_timeout=10)
            for line in out.splitlines():
                l = line.strip()
                if 'System Name' in l:
                    result['system_name'] = l.split(':', 1)[-1].strip()
                elif 'System Description' in l:
                    result['system_desc'] = l.split(':', 1)[-1].strip()
                elif 'Chassis ID' in l:
                    result['chassis_id'] = l.split(':', 1)[-1].strip()
                elif 'Port Description' in l:
                    result['port_desc'] = l.split(':', 1)[-1].strip()
        finally:
            try: nc.disconnect()
            except: pass
    except Exception:
        pass
    return result

def scan_machine_info(ip, switch_port=None):
    with _lock:
        if ip in machine_info_cache:
            return machine_info_cache[ip]
    info = {
        'ip': ip, 'hostname': 'Unknown', 'model': 'Unknown',
        'serial': 'Unknown', 'os': 'Unknown', 'mac': 'Unknown',
        'vendor': 'Unknown', 'open_ports': [],
        'last_scan': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    }

    # ── 1. DNS reverse ────────────────────────────────────────────────────
    try:
        info['hostname'] = socket.gethostbyaddr(ip)[0]
    except Exception:
        pass

    # ── 2. nmap ping scan → MAC + fabricant ──────────────────────────────
    try:
        r = subprocess.run(['nmap', '-sn', '-T4', '--privileged', ip],
                           capture_output=True, text=True, timeout=10)
        mac_m = re.search(r'([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}', r.stdout)
        if mac_m:
            info['mac'] = mac_m.group(0)
        vm = re.search(r'MAC Address:.*?\((.+?)\)', r.stdout)
        if vm:
            info['vendor'] = vm.group(1)
    except Exception:
        pass

    # ── 3. nmap OS detection + ports ouverts ─────────────────────────────
    try:
        r = subprocess.run(
            ['nmap', '-O', '--osscan-guess', '-T4', '--privileged',
             '-p', '22,23,80,135,139,443,445,3389,8080,8443', ip],
            capture_output=True, text=True, timeout=25)
        for line in r.stdout.splitlines():
            if 'Running:' in line:
                info['os'] = line.split('Running:')[1].strip(); break
            if 'OS details:' in line:
                info['os'] = line.split('OS details:')[1].strip(); break
        info['open_ports'] = re.findall(r'(\d+/tcp\s+open\s+\S+)', r.stdout)[:10]
    except Exception:
        pass

    # ── 4. nmap SMB → hostname, OS, modèle, série (Windows) ──────────────
    try:
        r = subprocess.run(
            ['nmap', '-p', '139,445', '--script',
             'smb-os-discovery,smb-system-info,nbstat', '-T4', ip],
            capture_output=True, text=True, timeout=20)
        for line in r.stdout.splitlines():
            ls = line.strip()
            if 'Computer name:' in ls:
                info['hostname'] = ls.split('Computer name:')[1].strip()
            elif 'NetBIOS name:' in ls:
                v = ls.split('NetBIOS name:')[1].strip()
                if info['hostname'] == 'Unknown': info['hostname'] = v
            elif 'OS:' in ls and info['os'] == 'Unknown':
                info['os'] = ls.split('OS:')[1].strip()
            elif 'Manufacturer:' in ls:
                v = ls.split('Manufacturer:')[1].strip()
                if v and info['vendor'] == 'Unknown': info['vendor'] = v
            elif 'Product Name:' in ls and info['model'] == 'Unknown':
                v = ls.split('Product Name:')[1].strip()
                if v and v.lower() not in _BAD_SERIALS: info['model'] = v
            elif 'Serial Number:' in ls and info['serial'] == 'Unknown':
                v = ls.split('Serial Number:')[1].strip()
                if v.lower() not in _BAD_SERIALS: info['serial'] = v
            elif 'Version:' in ls and info['model'] != 'Unknown':
                v = ls.split('Version:')[1].strip()
                if v: info['model'] += ' ' + v
    except Exception:
        pass

    # ── 5. SNMP Entity MIB → serial + modèle ────────────────────────────
    # sysName, sysDescr, entPhysicalSerialNum, entPhysicalModelName
    snmp_map = [
        ('hostname_s', '1.3.6.1.2.1.1.5.0'),
        ('os_s',       '1.3.6.1.2.1.1.1.0'),
        ('serial',     '1.3.6.1.2.1.47.1.1.1.1.11.1'),
        ('model',      '1.3.6.1.2.1.47.1.1.1.1.13.1'),
    ]
    for key, oid in snmp_map:
        val = _snmp_val(ip, oid, timeout=2)
        if not val or val.lower() in _BAD_SERIALS:
            continue
        if key == 'hostname_s' and info['hostname'] == 'Unknown':
            info['hostname'] = val
        elif key == 'os_s' and info['os'] == 'Unknown':
            info['os'] = val[:100]
        elif key == 'serial' and info['serial'] == 'Unknown':
            info['serial'] = val
        elif key == 'model' and info['model'] == 'Unknown':
            info['model'] = val

    # snmpwalk fallback pour serial et modèle
    if info['serial'] == 'Unknown':
        v = _snmpwalk_first(ip, '1.3.6.1.2.1.47.1.1.1.1.11', timeout=5)
        if v: info['serial'] = v
    if info['model'] == 'Unknown':
        v = _snmpwalk_first(ip, '1.3.6.1.2.1.47.1.1.1.1.13', timeout=5)
        if v: info['model'] = v

    # ── 6. LLDP via switch (si port connu) ──────────────────────────────
    if switch_port and switch_port not in ('N/A', None) and switch_port not in PROTECTED_PORTS:
        try:
            lldp = _get_lldp_neighbor_info(switch_port)
            if lldp.get('system_name') and info['hostname'] == 'Unknown':
                info['hostname'] = lldp['system_name']
            if lldp.get('system_desc'):
                desc = lldp['system_desc']
                if info['os'] == 'Unknown':
                    info['os'] = desc[:100]
                # Tenter d'extraire modèle depuis la description LLDP
                if info['model'] == 'Unknown':
                    for pat in [r'Model[:\s]+(\S[\w\- ]+)', r'Product[:\s]+(\S[\w\- ]+)']:
                        m = re.search(pat, desc, re.IGNORECASE)
                        if m:
                            info['model'] = m.group(1).strip()[:50]
                            break
        except Exception:
            pass

    # ── 7. Extraire modèle depuis sysDescr si toujours inconnu ───────────
    if info['model'] == 'Unknown' and info['os'] not in ('Unknown', ''):
        for pat in [r'Model[:\s]+(\S+)', r'model\s+(\S+)', r'HW\s+Version[:\s]+(\S+)']:
            m = re.search(pat, info['os'], re.IGNORECASE)
            if m:
                info['model'] = m.group(1).strip()
                break

    add_log(
        f"[SCAN] {ip} → hostname={info['hostname']} | vendor={info['vendor']} "
        f"| model={info['model']} | S/N={info['serial']} | OS={info['os'][:40]}", "info")
    with _lock:
        if len(machine_info_cache) >= MAX_MACHINE_CACHE:
            machine_info_cache.pop(next(iter(machine_info_cache)))
        machine_info_cache[ip] = info
    return info

# ---------------------------------------------------------------------------
# HELPERS SWITCH
# ---------------------------------------------------------------------------

def _connect():
    global _persistent_nc
    if not _sw_sem.acquire(timeout=20):
        raise Exception("Switch occupé — connexion en cours, réessayez dans quelques secondes")
    try:
        # Réutiliser la connexion existante si encore vivante (évite le handshake Telnet)
        if _persistent_nc is not None:
            try:
                _persistent_nc.send_command_timing('', delay_factor=0.1)
                nc = _persistent_nc
                def _patched_disconnect():
                    _sw_sem.release()  # libère le sémaphore SANS fermer la connexion
                nc.disconnect = _patched_disconnect
                return nc
            except Exception:
                try: _persistent_nc._real_disconnect()
                except: pass
                _persistent_nc = None

        # Nouvelle connexion Telnet
        nc = ConnectHandler(**SWITCH_PARAMS)
        nc.enable()
        nc._real_disconnect = nc.disconnect.__func__.__get__(nc) if hasattr(nc.disconnect, '__func__') else nc.disconnect
        _persistent_nc = nc

        def _patched_disconnect():
            _sw_sem.release()  # libère sémaphore SANS fermer la connexion TCP
        nc.disconnect = _patched_disconnect
        return nc
    except Exception:
        _sw_sem.release()
        raise


def _close_persistent():
    """Ferme proprement la connexion persistante (appel en fin de programme)."""
    global _persistent_nc
    if _persistent_nc is not None:
        try: _persistent_nc._real_disconnect()
        except: pass
        _persistent_nc = None


def _save(nc):
    out = nc.send_command_timing("copy running-config startup-config", delay_factor=3)
    if "confirm" in out.lower() or "[y/n]" in out.lower():
        nc.send_command_timing("Y", delay_factor=1)


def _norm_mac(mac):
    """Normalise un MAC en minuscules avec deux-points (format switch : aa:bb:cc:dd:ee:ff)."""
    return re.sub(r'[:\-\.]', ':', mac).lower()


def find_port_for_ip(nc, ip):
    """Retourne (port, mac) pour une IP (fetch les tables depuis le switch)."""
    mac_table = nc.send_command("show mac address-table")
    arp_table  = nc.send_command("show arp")
    return _find_from_tables(mac_table, arp_table, ip)


def _find_from_tables(mac_table, arp_table, ip, hint_mac=None):
    """
    Retourne (port, mac) depuis des tables déjà fetchées.
    hint_mac : MAC déjà connu (ex: fourni par Suricata) → skip la recherche ARP.
    """
    found_mac_raw = hint_mac
    if not found_mac_raw:
        for line in arp_table.splitlines():
            if ip in line:
                m = re.search(r'([0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}'
                              r'[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2})', line)
                if m:
                    found_mac_raw = m.group(0)
                    break
    if not found_mac_raw:
        return None, None

    search_mac = _norm_mac(found_mac_raw)
    for line in mac_table.splitlines():
        line_norm = _norm_mac(line) if any(c in line for c in [':', '-']) else line.lower()
        if search_mac in line_norm and '1/0/' in line:
            for p in line.split():
                if '1/0/' in p:
                    port = p.replace('Gi', '').replace('gi', '').replace('GigabitEthernet', '')
                    return port, search_mac
    return None, search_mac


def _get_backup_port_label(port):
    """Retourne le port backup formaté '1/0/X' ou None."""
    if not port or port == 'N/A':
        return None
    num = _extract_port_num(port)
    backup = PORT_BACKUP_MAP.get(num)
    return f'1/0/{backup}' if backup else None


def _extract_port_num(port):
    """Extrait le numéro depuis '1/0/N' → 'N'."""
    return port.split('/')[-1] if '/' in port else port


def do_activate_backup_port(primary_port, nc=None):
    """Allume le port backup correspondant. Réutilise nc si fourni."""
    num = _extract_port_num(primary_port)
    backup_num = PORT_BACKUP_MAP.get(num)
    if not backup_num:
        return
    backup_port = f'1/0/{backup_num}'
    cmds = [
        f'interface gigabitEthernet {backup_port}',
        f'no switchport general allowed vlan {VLAN_QUARANTAINE}',
        f'switchport general allowed vlan {TRUSTED_VLANS} untagged',
        f'switchport pvid {VLAN_NORMAL}',
        'no shutdown',
        'exit',
    ]
    own_conn = nc is None
    try:
        if own_conn:
            nc = _connect()
        nc.send_config_set(cmds)
        if own_conn:
            _save(nc)
            nc.disconnect()
        with _lock:
            backup_ports_active[backup_port] = primary_port
        log_switch_cmd(backup_port, cmds, f'BACKUP ACTIVÉ — remplace port {primary_port}')
        add_log(f"[BACKUP] Port {backup_port} allumé — remplace {primary_port} en quarantaine", "warning")
    except Exception as e:
        if own_conn and nc:
            try: nc.disconnect()
            except: pass
        add_log(f"[!] Erreur activation backup {backup_port}: {e}", "error")


def do_deactivate_backup_port(primary_port, nc=None):
    """Éteint le port backup correspondant. Réutilise nc si fourni."""
    num = _extract_port_num(primary_port)
    backup_num = PORT_BACKUP_MAP.get(num)
    if not backup_num:
        return
    backup_port = f'1/0/{backup_num}'
    cmds = [
        f'interface gigabitEthernet {backup_port}',
        'shutdown',
        'exit',
    ]
    own_conn = nc is None
    try:
        if own_conn:
            nc = _connect()
        nc.send_config_set(cmds)
        if own_conn:
            _save(nc)
            nc.disconnect()
        with _lock:
            backup_ports_active.pop(backup_port, None)
        log_switch_cmd(backup_port, cmds, f'BACKUP DÉSACTIVÉ — port {primary_port} restauré')
        add_log(f"[BACKUP] Port {backup_port} éteint — port {primary_port} restauré", "success")
    except Exception as e:
        if own_conn and nc:
            try: nc.disconnect()
            except: pass
        add_log(f"[!] Erreur désactivation backup {backup_port}: {e}", "error")


def _get_local_ip():
    """Retourne l'IP locale de la machine sur le réseau HOME_NET."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((SWITCH_PARAMS['host'], 80))
        return s.getsockname()[0]
    except Exception:
        return None


def do_warn_attacker(attacker_ip, attack_type='ATTAQUE', duration=None):
    """
    Avant le shutdown : redirige le HTTP de l'attaquant vers notre page d'avertissement.
    Mécanisme : ARP spoof + iptables PREROUTING → port 5000 (Flask).
    """
    if duration is None:
        duration = WARN_DURATION_SEC
    our_ip    = _get_local_ip()
    gateway   = SWITCH_PARAMS['host']
    iface     = None

    if not our_ip:
        add_log(f"[WARN] Impossible de déterminer l'IP locale — page avertissement ignorée", "warning")
        return

    try:
        # Détecter l'interface réseau active
        r = subprocess.run(['ip', 'route', 'get', attacker_ip], capture_output=True, text=True, timeout=3)
        for token in r.stdout.split():
            if token == 'dev':
                iface = r.stdout.split('dev')[1].strip().split()[0]
                break
    except Exception:
        pass

    add_log(f"[⚠ WARN] Activation page avertissement → {attacker_ip} ({duration}s)", "warning")

    try:
        # IP forwarding ON
        subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], capture_output=True)

        # Rediriger le port 80 de l'attaquant vers notre Flask (port 5000)
        iptables_add = ['iptables', '-t', 'nat', '-I', 'PREROUTING',
                        '-s', attacker_ip, '-p', 'tcp', '--dport', '80',
                        '-j', 'REDIRECT', '--to-port', '5000']
        subprocess.run(iptables_add, capture_output=True)

        # ARP spoof : on se fait passer pour la gateway auprès de l'attaquant
        arp_proc = None
        if iface:
            try:
                arp_proc = subprocess.Popen(
                    ['arpspoof', '-i', iface, '-t', attacker_ip, gateway],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
            except FileNotFoundError:
                add_log("[WARN] arpspoof non trouvé — installer dsniff pour le redirect ARP", "warning")

        time.sleep(duration)

    finally:
        # Nettoyage iptables
        iptables_del = ['iptables', '-t', 'nat', '-D', 'PREROUTING',
                        '-s', attacker_ip, '-p', 'tcp', '--dport', '80',
                        '-j', 'REDIRECT', '--to-port', '5000']
        subprocess.run(iptables_del, capture_output=True)
        if arp_proc:
            arp_proc.terminate()
        add_log(f"[WARN] Page avertissement terminée pour {attacker_ip}", "info")


def _quarantine_cmds(port):
    return [
        f'interface gigabitEthernet {port}',
        f'no switchport general allowed vlan {TRUSTED_VLANS}',
        f'switchport general allowed vlan {VLAN_QUARANTAINE} untagged',
        f'switchport pvid {VLAN_QUARANTAINE}',
        'no shutdown',
        'exit',
    ]

def do_quarantine_port(port, reason='', nc=None, activate_backup=True):
    """Isolation directe du port en VLAN 666. Si nc fourni, réutilise la connexion.
    activate_backup=False pour l'attaquant (on ne lui offre pas de port de secours)."""
    cmds = _quarantine_cmds(port)
    own_conn = nc is None
    try:
        if own_conn:
            nc = _connect()
        nc.send_config_set(cmds)
        if own_conn:
            _save(nc)
            nc.disconnect()
        log_switch_cmd(port, cmds, f'ISOLATION VLAN {VLAN_QUARANTAINE} | {reason}')
        add_log(f"[🔒 VLAN {VLAN_QUARANTAINE}] Port {port} isolé directement ({reason})", "error")
        if activate_backup:
            do_activate_backup_port(port, nc=nc)
        else:
            add_log(f"[BACKUP] Port backup de {port} conservé en shutdown (attaquant isolé)", "warning")
    except Exception as e:
        if own_conn and nc:
            try: nc.disconnect()
            except: pass
        add_log(f"[!] Erreur isolation port {port}: {e}", "error")


def do_restore_port(nc, port):
    """Remet un port dans les VLANs normaux et éteint son port backup."""
    cmds = [
        f'interface gigabitEthernet {port}',
        f'no switchport general allowed vlan {VLAN_QUARANTAINE}',
        f'switchport general allowed vlan {TRUSTED_VLANS} untagged',
        f'switchport pvid {VLAN_NORMAL}',
        'no shutdown',
        'exit',
    ]
    nc.send_config_set(cmds)
    log_switch_cmd(port, cmds, f'RESTAURATION → VLAN {TRUSTED_VLANS}')
    do_deactivate_backup_port(port, nc=nc)


def do_block_mac(mac, nc=None):
    """Bloque un MAC sur tous les VLANs (1, 10, 666) — aucun accès possible.
    Si nc est fourni, réutilise la connexion (évite deadlock sur le sémaphore)."""
    normalized = _norm_mac(mac)
    if normalized in PROTECTED_MACS:
        add_log(f"[INFO] MAC protégé {normalized} — bannissement ignoré", "warning")
        return
    all_vlans = [v.strip() for v in TRUSTED_VLANS.split(',') if v.strip()] + [str(VLAN_QUARANTAINE)]
    cmds = [f'mac address-table filtering {normalized} vid {v}' for v in all_vlans]
    own_conn = nc is None
    try:
        if own_conn:
            nc = _connect()
        nc.send_config_set(cmds)
        if own_conn:
            _save(nc)
            nc.disconnect()
        with _lock:
            mac_blacklist.add(normalized)
        _persist_state()
        log_switch_cmd('ALL', cmds, f'BAN MAC {normalized} → VLANs {", ".join(all_vlans)}')
        add_log(f"[BAN MAC] {normalized} bloqué sur VLANs {', '.join(all_vlans)}", "error")
    except Exception as e:
        if own_conn and nc:
            try: nc.disconnect()
            except: pass
        add_log(f"[!] Erreur blocage MAC {normalized}: {e}", "error")






def do_unblock_mac(mac, nc=None):
    """Retire le filtre MAC sur tous les VLANs (1, 10, 666).
    Si nc est fourni, réutilise la connexion existante (pas de double session)."""
    normalized = _norm_mac(mac)
    all_vlans = [v.strip() for v in TRUSTED_VLANS.split(',') if v.strip()] + [str(VLAN_QUARANTAINE)]
    cmds = [f'no mac address-table filtering {normalized} vid {v}' for v in all_vlans]
    own_conn = nc is None
    # Retirer de la blacklist mémoire immédiatement (décision admin = irrévocable)
    with _lock:
        mac_blacklist.discard(normalized)
    try:
        if own_conn:
            nc = _connect()
        nc.send_config_set(cmds)
        if own_conn:
            _save(nc)
            nc.disconnect()
        log_switch_cmd('ALL', cmds, f'DÉBLOCAGE MAC {normalized} — VLANs {", ".join(all_vlans)}')
        add_log(f"[DÉBLOCAGE MAC] {normalized} — filtres VLANs {', '.join(all_vlans)} retirés", "success")
    except Exception as e:
        add_log(f"[!] Switch injoignable ({e}) — MAC {normalized} retirée de la blacklist mémoire uniquement", "warning")

def do_unblock_ip(nc, ip):
    """Aucun déblocage IP spécifique nécessaire : le blocage est géré par MAC/VLAN."""
    add_log(f"[INFO] Aucun déblocage IP spécifique appliqué pour {ip}", "info")

# ---------------------------------------------------------------------------
# TRAITEMENT PRINCIPAL D'ALERTE — QUARANTAINE DIRECTE
# ---------------------------------------------------------------------------

def process_alert(mac_src, alert_info, eve_data=None):
    """
    Réaction IMMÉDIATE à une alerte Suricata :
    1. Détermine la stratégie (DUAL / PROTECT_VICTIM / ISOLATE_ATTACKER)
    2. Met les ports concernés DIRECTEMENT en VLAN 666
    3. Bloque le MAC de l'attaquant sur TOUS les ports (si local)
    4. Scanne les machines pour récupérer toutes leurs infos
    5. Seul l'admin peut restaurer depuis l'interface web
    """
    nc = None
    try:
        data      = eve_data or alert_info
        src_ip    = data.get('src_ip', 'N/A')
        dst_ip    = data.get('dest_ip', 'N/A')
        signature = alert_info.get('signature', 'Unknown')
        sid       = alert_info.get('signature_id', None)
        severity  = alert_info.get('severity', 0)

        # ── Ignorer les alertes dont la SOURCE est une IP protégée.
        # Ex : réponse ICMP du serveur → src=serveur, dst=attaquant.
        # Sans ce filtre, le serveur serait compté comme attaquant et
        # déclencherait un DUAL_QUARANTINE qui active le port backup de l'attaquant.
        if is_protected_ip(src_ip):
            return

        norm_src_mac = _norm_mac(mac_src) if mac_src and mac_src not in ('N/A', '') else None

        # ── FAST PATH : déjà en quarantaine + MAC déjà bloqué → rien à faire
        with _lock:
            _mac_blocked    = bool(norm_src_mac and norm_src_mac in mac_blacklist)
            _ip_quarantined = any(
                q['attacker_ip'] == src_ip and not q.get('restored', False)
                for q in quarantined_list
            )
        if _mac_blocked and _ip_quarantined:
            add_log(f"[⚡ SKIP] {src_ip} déjà en quarantaine + MAC bloqué — pas d'action switch", "info")
            return

        # ── Seuil volumétrie : ALERT_THRESHOLD alertes en ALERT_WINDOW_SEC secondes ─
        # Évite les faux positifs (un ping isolé ne déclenche pas la quarantaine)
        now = time.time()
        with _lock:
            times = _alert_rate.get(src_ip, [])
            times = [t for t in times if now - t < ALERT_WINDOW_SEC]  # purge old
            times.append(now)
            _alert_rate[src_ip] = times
            rate_count = len(times)
        if rate_count < ALERT_THRESHOLD:
            add_log(f"[RATE] {src_ip} : {rate_count}/{ALERT_THRESHOLD} alertes — seuil non atteint", "info")
            return

        # Anti-spam : ignorer si la même IP source a déjà été traitée dans les 30s
        with _lock:
            last = _quarantine_cooldown.get(src_ip, 0)
            if now - last < 30:
                return
            _quarantine_cooldown[src_ip] = now

        attack_type = detect_attack_type(signature, sid)
        attack_cfg  = ATTACK_PATTERNS.get(attack_type, {'color':'#888','icon':'⚠️','description':'Inconnu'})
        mode, attacker_ip, victim_ip = determine_strategy(src_ip, dst_ip)

        add_log(f"[{attack_cfg['icon']} {attack_type}] SID:{sid} | {src_ip} → {dst_ip}", "error")
        add_log(f"[STRATÉGIE] {mode}", "warning")

        if mode == 'EXTERNAL_ONLY':
            add_log("[INFO] Les deux IPs sont externes — log uniquement", "info")
            _record_quarantine_entry(None, None, None, None, attacker_ip, victim_ip,
                                     {}, {}, mode, attack_type, attack_cfg,
                                     signature, sid, severity)
            return

        if mode == 'SERVER_EXTERNAL_ATTACK':
            add_log(f"[SERVEUR] Attaque externe {attacker_ip} → serveur protégé {victim_ip}", "error")
            add_log(f"[SERVEUR] Attaquant hors réseau local — aucune action switch possible", "warning")
            _record_quarantine_entry(None, None, None, None, attacker_ip, victim_ip,
                                     {}, {}, mode, attack_type, attack_cfg,
                                     signature, sid, severity)
            return

        # ── Connexion switch (persistante = pas de handshake si déjà connecté) ─
        nc = _connect()
        try:
            # Utiliser le cache si < 6s — évite show mac + show arp (~3s économisés)
            cache = _sw_table_cache
            if time.time() - cache['ts'] < 6 and cache['mac']:
                mac_table = cache['mac']
                arp_table = cache['arp']
            else:
                mac_table = nc.send_command("show mac address-table")
                arp_table = nc.send_command("show arp")
            # Attaquant : utilise MAC Suricata (hint_mac) → skip show arp pour lui
            attacker_port, attacker_mac = _find_from_tables(mac_table, arp_table, attacker_ip, hint_mac=norm_src_mac)
            victim_port,   victim_mac   = _find_from_tables(mac_table, arp_table, victim_ip)

            # Port protégé (mirroring Suricata port 1, uplink port 28) → ignorer totalement
            if attacker_port in PROTECTED_PORTS:
                add_log(f"[SKIP] Port {attacker_port} protégé (mirroring/uplink) — alerte ignorée", "info")
                return

            # Scans machine en parallèle (avec port pour LLDP)
            attacker_info_store = {}
            victim_info_store   = {}
            _ap = attacker_port; _vp = victim_port
            t1 = threading.Thread(
                target=lambda: attacker_info_store.update(scan_machine_info(attacker_ip, switch_port=_ap)),
                daemon=True)
            t2 = threading.Thread(
                target=lambda: victim_info_store.update(scan_machine_info(victim_ip, switch_port=_vp)),
                daemon=True)
            t1.start(); t2.start()

            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            def _ban_attacker(mac):
                if mac:
                    do_block_mac(mac, nc=nc)

            if mode in ('SERVER_LOCAL_ATTACK', 'DUAL_QUARANTINE', 'ISOLATE_ATTACKER'):
                _ban_attacker(attacker_mac)

            # ── Avertir l'attaquant AVANT isolation (page rouge) ─────────────
            if attacker_ip and attacker_ip != 'N/A' and mode in (
                    'SERVER_LOCAL_ATTACK', 'DUAL_QUARANTINE', 'ISOLATE_ATTACKER'):
                threading.Thread(
                    target=do_warn_attacker,
                    args=(attacker_ip, attack_type),
                    daemon=True
                ).start()

            # ── Préparer le payload de notification pour les agents ──────────
            _qinfo_notif = {
                'attack_type': attack_type,
                'attack_desc': attack_cfg.get('description', ''),
                'attack_icon': attack_cfg.get('icon', '⚠️'),
            }

            # ── Quarantaine VLAN ─────────────────────────────────────────────
            # IMPORTANT : notifier les agents AVANT de couper le VLAN,
            # sinon le PC perd la connexion avant de recevoir le signal.
            # Règles backup :
            #   Attaquant → JAMAIS de port backup (il est banni, inutile)
            #   Victime   → port backup activé (continue à travailler)
            #   SERVER_LOCAL_ATTACK → aucun backup (serveur protégé, pas touché)
            if mode == 'SERVER_LOCAL_ATTACK':
                add_log(f"[SERVEUR PROTÉGÉ] {victim_ip} — seul l'attaquant {attacker_ip} est banni (aucun backup)", "error")
                if attacker_ip and attacker_ip != 'N/A':
                    threading.Thread(target=_notify_agent_quarantine,
                                     args=(attacker_ip, _qinfo_notif), daemon=True).start()
                if attacker_port and attacker_port not in PROTECTED_PORTS:
                    do_quarantine_port(attacker_port, f'SERVER_ATTACK par {attacker_ip}', nc=nc, activate_backup=False)

            elif mode == 'DUAL_QUARANTINE':
                add_log(f"[DUAL] Quarantaine : attaquant {attacker_ip} (pas de backup) / victime {victim_ip} (backup activé)", "error")
                if attacker_ip and attacker_ip != 'N/A':
                    threading.Thread(target=_notify_agent_quarantine,
                                     args=(attacker_ip, _qinfo_notif), daemon=True).start()
                if victim_ip and victim_ip != 'N/A':
                    threading.Thread(target=_notify_agent_quarantine,
                                     args=(victim_ip, _qinfo_notif), daemon=True).start()
                if attacker_port and attacker_port not in PROTECTED_PORTS:
                    do_quarantine_port(attacker_port, f'ATTAQUANT {attacker_ip}', nc=nc, activate_backup=False)
                if victim_port and victim_port not in PROTECTED_PORTS:
                    do_quarantine_port(victim_port, f'VICTIME {victim_ip}', nc=nc, activate_backup=True)

            elif mode == 'PROTECT_VICTIM':
                add_log(f"[VICTIME] Protection de {victim_ip} — attaquant externe {attacker_ip}", "error")
                if victim_ip and victim_ip != 'N/A':
                    threading.Thread(target=_notify_agent_quarantine,
                                     args=(victim_ip, _qinfo_notif), daemon=True).start()
                if victim_port and victim_port not in PROTECTED_PORTS:
                    do_quarantine_port(victim_port, f'VICTIME {victim_ip}', nc=nc, activate_backup=True)

            elif mode == 'ISOLATE_ATTACKER':
                add_log(f"[ATTAQUANT] Isolation de {attacker_ip} (aucun backup)", "error")
                if attacker_ip and attacker_ip != 'N/A':
                    threading.Thread(target=_notify_agent_quarantine,
                                     args=(attacker_ip, _qinfo_notif), daemon=True).start()
                if attacker_port and attacker_port not in PROTECTED_PORTS:
                    do_quarantine_port(attacker_port, f'ATTAQUANT {attacker_ip}', nc=nc, activate_backup=False)

        finally:
            nc.disconnect()
            nc = None
        # Sauvegarde config en arrière-plan — ne bloque pas la quarantaine
        def _async_save():
            try:
                nc2 = _connect()
                _save(nc2)
                nc2.disconnect()
            except Exception:
                pass
        threading.Thread(target=_async_save, daemon=True).start()

        # Attendre les scans (max 35s)
        t1.join(timeout=35); t2.join(timeout=35)

        # Historique MAC
        with _lock:
            for m_addr, port_addr, role in [
                (attacker_mac or mac_src, attacker_port, attack_type),
                (victim_mac,              victim_port,   'VICTIM_OF_' + attack_type),
            ]:
                if m_addr and m_addr != 'N/A':
                    if m_addr not in mac_history:
                        mac_history[m_addr] = {'port': port_addr, 'violations': 0,
                                               'first_seen': timestamp, 'hostname': 'Unknown'}
                    mac_history[m_addr]['violations']  += 1
                    mac_history[m_addr]['last_seen']    = timestamp
                    mac_history[m_addr]['last_attack']  = role
                    if port_addr:
                        mac_history[m_addr]['port'] = port_addr

        _record_quarantine_entry(
            attacker_mac or mac_src, attacker_port,
            victim_mac, victim_port,
            attacker_ip, victim_ip,
            dict(attacker_info_store), dict(victim_info_store),
            mode, attack_type, attack_cfg,
            signature, sid, severity
        )

        add_log(f"[AUTO] Quarantaine effectuée — seul l'admin peut restaurer", "warning")

    except Exception as e:
        add_log(f"[!] Erreur traitement alerte: {e}", "error")
    finally:
        if nc is not None:
            try: nc.disconnect()
            except: pass


def _record_quarantine_entry(attacker_mac, attacker_port, victim_mac, victim_port,
                              attacker_ip, victim_ip,
                              attacker_info, victim_info,
                              mode, attack_type, attack_cfg,
                              signature, sid, severity):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    entry = {
        'id':            timestamp + '_' + (attacker_ip or ''),
        'time':          timestamp,
        'mode':          mode,
        'attack_type':   attack_type,
        'attack_icon':   attack_cfg['icon'],
        'attack_color':  attack_cfg['color'],
        'attack_desc':   attack_cfg['description'],
        'signature':     signature,
        'sid':           sid,
        'severity':      severity,
        # Attaquant
        'attacker_ip':          attacker_ip   or 'N/A',
        'attacker_mac':         attacker_mac  or 'N/A',
        'attacker_port':        attacker_port or 'N/A',
        'attacker_backup_port': _get_backup_port_label(attacker_port),
        'attacker_info':        attacker_info,
        'mac_blocked':          bool(attacker_mac and _norm_mac(attacker_mac) in mac_blacklist),
        # Victime
        'victim_ip':          victim_ip   or 'N/A',
        'victim_mac':         victim_mac  or 'N/A',
        'victim_port':        victim_port or 'N/A',
        'victim_backup_port': _get_backup_port_label(victim_port),
        'victim_info':        victim_info,
        # Statut
        'status':    'QUARANTAINE ACTIVE',
        'restored':  False,
    }
    with _lock:
        quarantined_list.insert(0, entry)
        if len(quarantined_list) > 200:
            quarantined_list.pop()
        # Réinitialiser le compteur suspect — la machine est isolée, plus besoin de compter
        _suspects.pop(attacker_ip, None)
        _alert_dedup.pop(attacker_ip, None)
    _persist_state()

    # Notification Telegram en arrière-plan
    threading.Thread(target=_telegram_alert_quarantine, args=(entry,), daemon=True).start()

# ---------------------------------------------------------------------------
# BOUCLE SURICATA
# ---------------------------------------------------------------------------

def monitor_loop():
    global monitoring_active
    with open(SURICATA_LOG, 'r') as f:
        f.seek(0, os.SEEK_END)
        while monitoring_active:
            line = f.readline()
            if not line:
                time.sleep(0.3)
                continue
            try:
                data = json.loads(line)
                if data.get('event_type') != 'alert':
                    continue
                ab       = data.get('alert', {})
                mac_src  = (data.get('ether', {}).get('src_mac') or data.get('src_mac', 'N/A'))
                ip_src   = data.get('src_ip', 'N/A')
                ip_dst   = data.get('dest_ip', 'N/A')
                sig      = ab.get('signature', 'Unknown')
                sid      = ab.get('signature_id', None)
                severity = ab.get('severity', 0)
                now      = time.time()

                attack_type = detect_attack_type(sig, sid)
                acfg        = ATTACK_PATTERNS.get(attack_type, {'icon':'⚠️','description':'Inconnu'})

                # ── Toujours afficher l'alerte dans le log ────────────────────
                with _lock:
                    alerts_list.insert(0, {
                        'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'mac': mac_src, 'ip_src': ip_src, 'ip_dst': ip_dst,
                        'alert': sig, 'sid': sid, 'severity': severity,
                        'attack_type': attack_type, 'attack_icon': acfg['icon'],
                        'attack_description': acfg['description'],
                    })
                    if len(alerts_list) > 200:
                        alerts_list.pop()

                add_log(f"[{acfg['icon']}] {attack_type} | SID:{sid} | {ip_src}→{ip_dst}", "warning")

                # ── Déduplication : même IP source dans DEDUP_WINDOW_SEC ──────
                # Suricata peut tirer plusieurs règles sur le même paquet ;
                # on ne compte qu'UN événement par IP toutes les 0.5s.
                with _lock:
                    last_dedup = _alert_dedup.get(ip_src, 0)
                    if now - last_dedup < DEDUP_WINDOW_SEC:
                        continue          # même rafale → on affiche mais on ne recompte pas
                    _alert_dedup[ip_src] = now

                    # ── Compteur suspect visible sur le dashboard ─────────────
                    s = _suspects.get(ip_src)
                    if s and now - s['last_ts'] < ALERT_WINDOW_SEC:
                        s['count']   += 1
                        s['last_ts']  = now
                        s['last_sig'] = sig
                        s['dst']      = ip_dst
                    else:
                        _suspects[ip_src] = {
                            'count':    1,
                            'first_ts': now,
                            'last_ts':  now,
                            'last_sig': sig,
                            'dst':      ip_dst,
                            'icon':     acfg['icon'],
                        }

                threading.Thread(
                    target=process_alert,
                    args=(mac_src, {'signature': sig, 'signature_id': sid,
                                    'severity': severity, 'src_ip': ip_src, 'dest_ip': ip_dst}, data),
                    daemon=True
                ).start()
            except Exception as e:
                add_log(f"[!] Parsing: {e}", "error")

def sw_table_cache_loop():
    """Rafraîchit show mac address-table + show arp toutes les 4s en arrière-plan.
    Pause si une action admin est en cours (_admin_op_pending) pour libérer le sémaphore."""
    global _sw_table_cache
    while True:
        time.sleep(4)
        if not monitoring_active or _admin_op_pending:
            continue
        try:
            nc = _connect()
            mac = nc.send_command("show mac address-table")
            arp = nc.send_command("show arp")
            nc.disconnect()
            _sw_table_cache = {'mac': mac, 'arp': arp, 'ts': time.time()}
        except Exception:
            pass


def mac_watchdog_loop():
    """
    Toutes les 5s, vérifie si un MAC blacklisté réapparaît dans la table MAC.
    Si oui, quarantaine immédiate du port (T1600G n'a pas d'ACL CLI — seule protection).
    Ne re-quarantaine PAS si l'admin a déjà restauré la quarantaine correspondante.
    """
    while monitoring_active:
        time.sleep(5)
        if not mac_blacklist or _admin_op_pending:
            continue
        try:
            nc = _connect()
            mac_table = nc.send_command("show mac address-table")
            nc.disconnect()
            for line in mac_table.splitlines():
                ll = line.lower()
                for blocked_mac in list(mac_blacklist):
                    norm = _norm_mac(blocked_mac)
                    if norm not in ll:
                        continue
                    # Si l'admin a restauré la quarantaine → retirer de la blacklist, ne pas re-quarantiner
                    with _lock:
                        admin_restored = any(
                            q.get('restored') and norm == _norm_mac(q.get('attacker_mac', ''))
                            for q in quarantined_list
                        )
                    if admin_restored:
                        with _lock:
                            mac_blacklist.discard(norm)
                        add_log(f"[WATCHDOG] MAC {norm} — quarantaine restaurée par admin, supprimé de la blacklist", "info")
                        continue
                    m = re.search(r'(?:Gi|gi)?(\d+/\d+/\d+)', line, re.IGNORECASE)
                    if m:
                        port = m.group(1)
                        if port not in PROTECTED_PORTS:
                            add_log(f"[WATCHDOG] MAC banni {norm} → port {port} — re-quarantaine forcée", "error")
                            do_quarantine_port(port, f'WATCHDOG MAC {norm}')
        except Exception as e:
            add_log(f"[WATCHDOG] Erreur: {e}", "error")


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetShield SDN</title>
<style>html,body{background:#f8fafc!important;color:#0f172a;margin:0}</style>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" media="print" onload="this.media='all'">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js" onerror="window.Chart=null"></script>
<style>
:root{
  --bg:#f8fafc; --bg2:#f1f5f9; --bg3:#e2e8f0;
  --glass:rgba(0,0,0,.03); --glass2:rgba(0,0,0,.05); --glass3:rgba(0,0,0,.08);
  --sb-w:400px; --tb-h:100px;
  --blue:#3b82f6;   --blue-d:#1d4ed8;   --blue-l:rgba(59,130,246,.1);   --blue-b:rgba(59,130,246,.3);
  --red:#ef4444;    --red-d:#b91c1c;    --red-l:rgba(239,68,68,.1);     --red-b:rgba(239,68,68,.35);
  --green:#10b981;  --green-d:#065f46;  --green-l:rgba(16,185,129,.1);  --green-b:rgba(16,185,129,.35);
  --orange:#f59e0b; --orange-l:rgba(245,158,11,.1);  --orange-b:rgba(245,158,11,.35);
  --purple:#8b5cf6; --purple-l:rgba(139,92,246,.1);  --purple-b:rgba(139,92,246,.35);
  --cyan:#06b6d4;   --cyan-l:rgba(6,182,212,.1);     --cyan-b:rgba(6,182,212,.3);
  --tx:#000000; --tx2:#000000; --tx3:#000000;
  --border:rgba(0,0,0,.1); --border2:rgba(0,0,0,.2);
  --r:14px; --r-sm:9px;
  --shadow:0 8px 32px rgba(0,0,0,.1);
  --shadow-md:0 16px 48px rgba(0,0,0,.15);
  --card:rgba(255,255,255,.8);
}
*{margin:0;padding:0;box-sizing:border-box}
::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-thumb{background:rgba(0,0,0,.15);border-radius:4px}
::-webkit-scrollbar-track{background:transparent}
body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--tx);min-height:100vh;font-size:30px;line-height:1.9}
/* ── APP ── */
.app{display:flex;min-height:100vh;position:relative}
/* ── SIDEBAR ── */
.sidebar{width:var(--sb-w);background:var(--bg2);border-right:1px solid var(--border);position:fixed;top:0;left:0;height:100vh;z-index:200;display:flex;flex-direction:column;overflow-y:auto;box-shadow:4px 0 24px rgba(0,0,0,.35)}
.sb-logo{padding:22px 20px 18px;border-bottom:1px solid var(--border);background:linear-gradient(135deg,rgba(59,130,246,.06),rgba(139,92,246,.03))}
.sb-logo-top{display:flex;align-items:center;gap:12px;margin-bottom:4px}
.sb-logo-icon{width:44px;height:44px;background:linear-gradient(135deg,#3b82f6,#8b5cf6);border-radius:12px;display:flex;align-items:center;justify-content:center;color:#fff;font-size:1.1rem;font-weight:800;font-family:monospace;box-shadow:0 0 20px rgba(59,130,246,.35);flex-shrink:0}
.sb-logo-name{font-family:monospace;font-size:1.1rem;font-weight:700;letter-spacing:.5px;color:var(--tx)}
.sb-logo-sub{font-size:.88rem;color:var(--tx3);letter-spacing:1.5px;text-transform:uppercase;margin-left:56px}
.sb-nav{padding:12px 10px;flex:1}
.sb-section{font-size:.85rem;font-weight:700;text-transform:uppercase;letter-spacing:1.5px;color:var(--tx3);padding:16px 12px 6px;font-family:monospace}
.sb-item{display:flex;align-items:center;gap:10px;padding:13px 16px;border-radius:10px;cursor:pointer;color:var(--tx2);font-size:1rem;font-weight:500;margin-bottom:3px;transition:all .2s;border:1px solid transparent;background:transparent;width:100%;text-align:left;position:relative}
.sb-item:hover{background:var(--glass);color:var(--tx)}
.sb-item.active{background:var(--blue-l);color:var(--blue);font-weight:600;border-color:var(--blue-b)}
.sb-item.active::before{content:'';position:absolute;left:0;top:50%;transform:translateY(-50%);width:3px;height:55%;background:var(--blue);border-radius:0 3px 3px 0;box-shadow:0 0 10px var(--blue)}
.sb-item .si-icon{font-size:1.15rem;width:26px;text-align:center;flex-shrink:0}
.sb-item .si-txt{flex:1}
.sb-item .si-count{background:var(--red);color:#fff;font-size:.88rem;border-radius:10px;padding:2px 8px;font-weight:700;min-width:22px;text-align:center;box-shadow:0 0 8px rgba(239,68,68,.5)}
.sb-footer{padding:16px 18px;border-top:1px solid var(--border);margin-top:auto}
.sb-status{display:flex;align-items:center;gap:8px;padding:12px 14px;border-radius:10px;font-size:.96rem;font-weight:700;font-family:monospace;letter-spacing:.8px;text-transform:uppercase;border:1px solid}
.sb-status.on{background:var(--green-l);border-color:var(--green-b);color:var(--green);box-shadow:0 0 20px rgba(16,185,129,.12)}
.sb-status.off{background:var(--red-l);border-color:var(--red-b);color:var(--red)}
.sb-dot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
.sb-status.on .sb-dot{background:var(--green);animation:pulse 1.5s infinite;box-shadow:0 0 8px var(--green)}
.sb-status.off .sb-dot{background:var(--red)}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.4;transform:scale(.8)}}
@keyframes fadein{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
@keyframes glow-atk{0%,100%{box-shadow:0 0 0 1px rgba(245,158,11,.08),0 4px 24px rgba(245,158,11,.05)}50%{box-shadow:0 0 0 1px rgba(245,158,11,.18),0 4px 36px rgba(245,158,11,.12)}}
/* ── MAIN ── */
.main{margin-left:var(--sb-w);flex:1;display:flex;flex-direction:column;min-height:100vh}
/* ── TOPBAR ── */
.topbar{height:var(--tb-h);background:rgba(248,250,252,.92);backdrop-filter:blur(24px);border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;padding:0 28px;position:sticky;top:0;z-index:100;box-shadow:0 1px 0 rgba(255,255,255,.03),0 4px 24px rgba(0,0,0,.4)}
.tb-title{font-size:1.6rem;font-weight:700;color:var(--tx);letter-spacing:-.3px}
.tb-right{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.tb-clock{font-family:monospace;font-size:1.1rem;color:var(--blue);background:var(--blue-l);padding:7px 16px;border-radius:8px;border:1px solid var(--blue-b);letter-spacing:2px;box-shadow:0 0 16px rgba(59,130,246,.15)}
/* ── CONTENT ── */
.content{flex:1;padding:24px 28px;background:transparent}
/* ── PAGES ── */
.page{display:none}
.page.active{display:block;animation:fadein .25s ease}
/* ── STATS ── */
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px}
@media(max-width:900px){.stats{grid-template-columns:1fr 1fr}}
.stat{background:var(--glass);border:1px solid var(--border);border-radius:var(--r);padding:20px 22px;position:relative;overflow:hidden;transition:all .25s;backdrop-filter:blur(10px)}
.stat:hover{border-color:var(--border2);transform:translateY(-3px);box-shadow:var(--shadow)}
.stat::before{content:'';position:absolute;top:0;left:0;right:0;height:2px}
.stat.s-alert::before{background:linear-gradient(90deg,#ef4444,transparent)}
.stat.s-quar::before{background:linear-gradient(90deg,#f59e0b,transparent)}
.stat.s-block::before{background:linear-gradient(90deg,#8b5cf6,transparent)}
.stat.s-hist::before{background:linear-gradient(90deg,#06b6d4,transparent)}
.stat .lbl{font-size:.92rem;font-weight:600;text-transform:uppercase;letter-spacing:1.5px;color:var(--tx3);margin-bottom:10px;font-family:monospace}
.stat .num{font-size:3.6rem;font-weight:800;line-height:1;font-family:monospace}
.stat.s-alert .num{color:#ef4444}
.stat.s-quar  .num{color:#f59e0b}
.stat.s-block .num{color:#8b5cf6}
.stat.s-hist  .num{color:#06b6d4}
.stat .sub{font-size:.96rem;color:var(--tx3);margin-top:6px}
/* ── BUTTONS ── */
.btn{padding:12px 24px;border:none;border-radius:var(--r-sm);cursor:pointer;font-size:1rem;font-weight:600;letter-spacing:.8px;text-transform:uppercase;transition:all .2s;font-family:monospace;position:relative;overflow:hidden}
.btn:hover{filter:brightness(1.12);transform:translateY(-1px)}
.btn:active{transform:scale(.97);filter:brightness(.95)}
.btn-sm{padding:9px 16px;font-size:.94rem}
.btn-on  {background:var(--green); color:#fff;box-shadow:0 2px 14px rgba(16,185,129,.35)}
.btn-off {background:var(--red);   color:#fff;box-shadow:0 2px 14px rgba(239,68,68,.35)}
.btn-blue{background:var(--blue);  color:#fff;box-shadow:0 2px 14px rgba(59,130,246,.35)}
.btn-ora {background:var(--orange);color:#fff;box-shadow:0 2px 14px rgba(245,158,11,.3)}
.btn-pur {background:var(--purple);color:#fff;box-shadow:0 2px 14px rgba(139,92,246,.35)}
.btn-grn {background:var(--green); color:#fff;box-shadow:0 2px 14px rgba(16,185,129,.35)}
.btn-red {background:var(--red);   color:#fff;box-shadow:0 2px 14px rgba(239,68,68,.35)}
.btn-grey{background:var(--glass2);border:1px solid var(--border2);color:var(--tx2)}
.ctrls{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}
/* ── SECTION ── */
.sec{background:var(--glass);border:1px solid var(--border);border-radius:var(--r);padding:22px 24px;margin-bottom:16px;backdrop-filter:blur(10px)}
.sec-title{font-size:1rem;font-weight:700;color:var(--blue);margin-bottom:18px;padding-bottom:12px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:8px;font-family:monospace;text-transform:uppercase;letter-spacing:1.5px}
.sec-title::before{content:'//';color:var(--tx3);margin-right:2px}
/* ── DASHBOARD ── */
.dash-grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:20px;margin-bottom:24px}
@media(max-width:1100px){.dash-grid{grid-template-columns:1fr 1fr}}
@media(max-width:700px){.dash-grid{grid-template-columns:1fr}}
.dash-col{background:var(--glass);border:1px solid var(--border);border-radius:var(--r);padding:20px;backdrop-filter:blur(10px);transition:all .25s}
.dash-col:hover{border-color:var(--border2)}
.dash-col-green{border-top:2px solid var(--green)}
.dash-col-blue{border-top:2px solid var(--blue)}
.dash-col-red{border-top:2px solid var(--red)}
.dash-title{font-size:1.3rem;font-weight:700;margin-bottom:16px;display:flex;align-items:center;gap:8px;color:var(--tx)}
.dash-col-green .dash-title{color:var(--green)}
.dash-col-blue  .dash-title{color:var(--blue)}
.dash-col-red   .dash-title{color:var(--red)}
.icon-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.icon-btn{background:var(--glass2);border-radius:var(--r-sm);padding:14px 10px;text-align:center;cursor:pointer;border:1px solid var(--border);transition:all .2s;display:flex;flex-direction:column;align-items:center;gap:5px}
.icon-btn:hover{border-color:var(--blue-b);background:var(--blue-l);box-shadow:0 0 20px rgba(59,130,246,.15);transform:translateY(-2px)}
.ib-icon{font-size:1.7rem}
.ib-label{font-size:.94rem;font-weight:600;color:var(--tx2);text-transform:uppercase;letter-spacing:.5px}
.ib-count{font-size:1.05rem;font-weight:700;font-family:monospace}
.dash-stat-row{display:flex;gap:10px;margin-top:14px}
.dash-stat{flex:1;background:var(--glass2);border-radius:var(--r-sm);padding:14px;text-align:center;border:1px solid var(--border)}
.dash-stat-num{font-size:2.6rem;font-weight:800;font-family:monospace}
.dash-stat-lbl{font-size:.92rem;color:var(--tx2);text-transform:uppercase;letter-spacing:.8px;margin-top:2px}
.dash-col-green .dash-stat-num{color:var(--green)}
.dash-col-blue  .dash-stat-num{color:var(--blue)}
.dash-col-red   .dash-stat-num{color:var(--red)}
.dash-alert-item{background:var(--glass2);border-radius:8px;padding:12px 16px;margin-bottom:6px;border:1px solid var(--border);font-size:1rem;display:flex;align-items:center;gap:10px;transition:all .2s}
.dash-alert-item:hover{border-color:var(--border2)}
.dash-alert-item:last-child{margin-bottom:0}
.dash-mini-backup{display:flex;flex-wrap:wrap;gap:5px;margin-top:14px}
.machine-row{display:flex;align-items:center;gap:8px;padding:12px 14px;border-radius:8px;background:var(--glass2);border:1px solid var(--border);margin-bottom:5px;font-size:1rem;transition:all .2s}
.machine-row:hover{border-color:var(--border2)}
.machine-row.quar{border-left:2px solid var(--red);background:var(--red-l)}
.machine-row.blocked{border-left:2px solid var(--purple)}
.mr-port{font-family:monospace;font-weight:700;font-size:1rem;color:var(--green);background:var(--green-l);padding:4px 10px;border-radius:4px;white-space:nowrap;flex-shrink:0;border:1px solid var(--green-b)}
.mr-port.quar{color:var(--red);background:var(--red-l);border-color:var(--red-b)}
.mr-ip{font-family:monospace;font-weight:600;color:var(--tx);flex-shrink:0;min-width:105px}
.mr-mac{font-family:monospace;font-size:.94rem;color:var(--tx2);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.mr-vlan{font-size:.92rem;background:var(--blue-l);color:var(--blue);border:1px solid var(--blue-b);border-radius:3px;padding:3px 8px;font-family:monospace;flex-shrink:0}
.mr-badge{font-size:.92rem;padding:4px 10px;border-radius:3px;font-weight:700;flex-shrink:0}
.mr-actions{display:flex;gap:4px;flex-shrink:0}
.dash-bp{background:var(--glass2);border:1px solid var(--border);border-radius:6px;padding:5px 11px;font-family:monospace;font-size:.82rem;color:var(--tx3);text-align:center;transition:all .2s}
.dash-bp.active{border-color:var(--blue-b);color:var(--blue);background:var(--blue-l);font-weight:700;box-shadow:0 0 10px rgba(59,130,246,.15)}
.dash-threat{background:var(--glass2);border-radius:8px;padding:10px 14px;margin-bottom:6px;border:1px solid var(--border);font-size:.9rem;display:flex;align-items:center;justify-content:space-between;gap:8px}
/* ── TABLE ── */
table{width:100%;border-collapse:collapse;font-size:.92rem}
th,td{padding:12px 16px;text-align:left;border-bottom:1px solid var(--border)}
th{color:var(--tx3);font-weight:600;text-transform:uppercase;letter-spacing:1px;font-size:.8rem;font-family:monospace;background:var(--glass2)}
tr:hover td{background:var(--glass2)}
/* ── BADGE ── */
.badge{display:inline-flex;align-items:center;gap:4px;padding:3px 10px;border-radius:5px;font-size:.8rem;font-weight:700;white-space:nowrap;font-family:monospace;letter-spacing:.5px;text-transform:uppercase}
.b-cyan{background:var(--cyan-l);  color:var(--cyan);  border:1px solid var(--cyan-b)}
.b-red {background:var(--red-l);   color:var(--red);   border:1px solid var(--red-b)}
.b-ora {background:var(--orange-l);color:var(--orange);border:1px solid var(--orange-b)}
.b-grn {background:var(--green-l); color:var(--green); border:1px solid var(--green-b)}
.b-pur {background:var(--purple-l);color:var(--purple);border:1px solid var(--purple-b)}
.b-srv {background:var(--red-l);   color:var(--red);   border:2px solid var(--red)}
.b-act {background:var(--orange-l);color:var(--orange);border:1px solid var(--orange-b);animation:pulse-b 1.5s infinite}
.b-done{background:var(--green-l); color:var(--green); border:1px solid var(--green-b)}
@keyframes pulse-b{0%,100%{opacity:1}50%{opacity:.35}}
/* ── QUARANTINE CARDS ── */
.qcard{border:1px solid rgba(245,158,11,.2);border-left:3px solid var(--orange);border-radius:var(--r);padding:20px;margin-bottom:14px;background:var(--glass);transition:all .25s;backdrop-filter:blur(10px)}
.qcard:not(.restored){animation:glow-atk 3s ease-in-out infinite}
.qcard:hover{border-color:rgba(245,158,11,.4)}
.qcard.restored{opacity:.5;border-color:rgba(16,185,129,.18);border-left-color:var(--green);animation:none}
.qcard-head{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:14px;flex-wrap:wrap;gap:10px}
.qcard-title{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.qcard-badges{display:flex;gap:6px;align-items:center;flex-wrap:wrap}
.qcard-sig{font-family:monospace;font-size:.86rem;color:var(--tx2);margin-bottom:12px;padding:10px 14px;background:var(--glass2);border-radius:6px;word-break:break-all;border-left:2px solid var(--blue)}
/* ── MACHINE CARDS ── */
.machines{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:12px}
.port-bar{display:flex;gap:20px;align-items:flex-start;flex-wrap:wrap;background:var(--glass2);border-radius:10px;padding:12px 16px;margin:10px 0;border:1px solid var(--border)}
.port-bar-item{display:flex;flex-direction:column;align-items:flex-start;gap:4px}
.port-bar-label{font-size:.8rem;color:var(--tx3);text-transform:uppercase;letter-spacing:.8px;font-family:monospace}
.backup-badge{font-size:.82rem;font-family:monospace;color:var(--blue);background:var(--blue-l);border:1px solid var(--blue-b);border-radius:4px;padding:3px 10px}
.port-badge{font-family:monospace;font-size:.96rem;font-weight:700;padding:5px 14px;border-radius:6px;letter-spacing:.5px}
.port-badge.atk{background:var(--red-l);color:var(--red);border:1px solid var(--red-b)}
.port-badge.vic{background:var(--orange-l);color:var(--orange);border:1px solid var(--orange-b)}
.port-badge.srv{background:var(--purple-l);color:var(--purple);border:1px solid var(--purple-b)}
.port-badge.na{background:var(--glass2);color:var(--tx3);border:1px solid var(--border)}
.mcard{flex:1;min-width:200px;max-width:340px;background:var(--glass2);border-radius:10px;padding:14px;border:1px solid var(--border);transition:all .2s}
.mcard:hover{border-color:var(--border2)}
.mcard-title{font-size:.84rem;font-weight:700;margin-bottom:10px;font-family:monospace;text-transform:uppercase;letter-spacing:.8px}
.mcard-port{font-family:monospace;font-size:1.1rem;font-weight:800;text-align:center;padding:8px;border-radius:6px;margin-bottom:10px;letter-spacing:1px}
.mcard-row{display:flex;justify-content:space-between;align-items:flex-start;padding:4px 0;border-bottom:1px solid var(--border);gap:8px}
.mcard-row:last-child{border-bottom:none}
.mcard-label{font-size:.8rem;color:var(--tx3);text-transform:uppercase;letter-spacing:.8px;white-space:nowrap;min-width:80px;font-family:monospace}
.mcard-val{font-size:.9rem;color:var(--tx);text-align:right;word-break:break-all;font-family:monospace}
.mcard-val.serial{color:var(--orange);font-weight:700}
.atk{background:var(--red-l);color:var(--red)}
.vic{background:var(--orange-l);color:var(--orange)}
.na{background:var(--glass2);color:var(--tx3)}
/* ── SUSPECT BAR ── */
.suspect-card{background:var(--glass2);border:2px solid var(--orange);border-radius:10px;padding:12px 16px;margin-bottom:8px;display:flex;align-items:center;gap:14px}
.suspect-ip{font-family:monospace;font-weight:700;font-size:1rem;flex:1}
.suspect-dst{font-family:monospace;font-size:.8rem;color:var(--tx3)}
.suspect-count{font-size:1.5rem;font-weight:800;color:var(--orange);min-width:36px;text-align:center}
.suspect-bar-wrap{flex:2;min-width:100px}
.suspect-bar-track{background:var(--border2);border-radius:4px;height:8px;overflow:hidden}
.suspect-bar-fill{height:8px;border-radius:4px;background:var(--orange);transition:width .3s}
.suspect-bar-fill.danger{background:var(--red)}
.suspect-label{font-size:.72rem;color:var(--tx3);margin-top:3px;font-family:monospace}
/* ── ACTION CARDS ── */
.restore-btns{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px}
.action-card{background:var(--glass);border:1px solid var(--border);border-radius:var(--r);padding:18px 20px;margin-bottom:10px;display:flex;align-items:center;justify-content:space-between;gap:14px;flex-wrap:wrap;transition:all .25s;backdrop-filter:blur(10px)}
.action-card:hover{border-color:var(--border2);box-shadow:var(--shadow)}
.action-card.card-atk{border-left:3px solid var(--red)}
.action-card.card-vic{border-left:3px solid var(--orange)}
.action-card.card-mac{border-left:3px solid var(--purple)}
.ac-info{flex:1;min-width:180px}
.ac-title{font-size:1rem;font-weight:700;color:var(--tx);margin-bottom:6px;display:flex;align-items:center;gap:7px;flex-wrap:wrap}
.ac-sub{font-size:.88rem;color:var(--tx2);font-family:monospace;display:flex;flex-wrap:wrap;gap:10px;margin-top:4px}
.ac-btns{display:flex;gap:8px;flex-wrap:wrap;flex-shrink:0}
.hist-row{display:flex;align-items:center;justify-content:space-between;padding:12px 16px;border-bottom:1px solid var(--border);flex-wrap:wrap;gap:8px;font-size:.92rem}
.hist-row:last-child{border-bottom:none}
.empty-state{text-align:center;padding:50px 20px}
.es-icon{font-size:2.8rem;margin-bottom:12px;opacity:.6}
.es-text{font-size:.96rem;color:var(--tx3)}
/* ── BACKUP PANEL ── */
.backup-panel{background:var(--glass2);border:1px solid var(--border);border-radius:10px;padding:14px 16px;margin-bottom:16px}
.backup-panel-title{font-size:.86rem;font-weight:700;text-transform:uppercase;letter-spacing:.8px;color:var(--tx2);font-family:monospace;margin-bottom:10px;display:flex;align-items:center;gap:7px}
.backup-grid{display:flex;flex-wrap:wrap;gap:8px}
.bp-slot{display:flex;flex-direction:column;align-items:center;gap:3px;background:var(--glass);border:1px solid var(--border);border-radius:8px;padding:8px 12px;min-width:80px;transition:all .2s}
.bp-slot.active{border-color:var(--blue-b);background:var(--blue-l);box-shadow:0 0 16px rgba(59,130,246,.15)}
.bp-slot-label{font-size:.76rem;color:var(--tx3);text-transform:uppercase;letter-spacing:.5px;font-family:monospace}
.bp-slot-port{font-size:.92rem;font-weight:700;font-family:monospace;color:var(--tx2)}
.bp-slot.active .bp-slot-port{color:var(--blue)}
.bp-slot-status{font-size:.8rem;font-family:monospace}
.bp-slot-status.on{color:var(--green)}.bp-slot-status.off{color:var(--tx3)}
/* ── TERMINAL ── */
.term{background:#1e293b;border:1px solid rgba(0,0,0,.15);border-radius:10px;padding:16px;height:260px;overflow-y:auto;font-family:monospace;font-size:.9rem;box-shadow:inset 0 2px 20px rgba(0,0,0,.3)}
.log-line{padding:2px 0;display:flex;gap:10px}
.log-t{color:#2a3a5e;min-width:56px}
.log-info    .log-m{color:#60a5fa}
.log-success .log-m{color:#34d399}
.log-warning .log-m{color:#fbbf24}
.log-error   .log-m{color:#f87171}
/* ── CMD BLOCKS ── */
.cmd-block{margin-bottom:12px;border-radius:10px;border:1px solid var(--border);overflow:hidden}
.cmd-header{background:var(--glass2);padding:10px 16px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--border)}
.cmd-port  {color:var(--blue);font-family:monospace;font-weight:700;font-size:.92rem}
.cmd-reason{color:var(--tx2);font-size:.86rem;font-family:monospace}
.cmd-time  {color:var(--tx3);font-size:.84rem;font-family:monospace}
.cmd-body  {padding:14px 18px;font-family:monospace;font-size:.9rem;background:#1e293b}
.cmd-line  {color:#34d399;padding:2px 0}
.cmd-line::before{content:'$ ';color:#2a3a5e}
/* ── REF BOX ── */
.ref-box{background:var(--glass);border:1px solid var(--border);border-left:3px solid var(--blue);border-radius:10px;padding:18px}
.ref-title{color:var(--blue);font-size:.92rem;font-weight:700;margin-bottom:14px;font-family:monospace;text-transform:uppercase;letter-spacing:1px}
.ref-phase{margin-bottom:16px}
.ref-phase-title{color:var(--orange);font-size:.86rem;font-weight:700;margin-bottom:8px;text-transform:uppercase;letter-spacing:1px;font-family:monospace}
.ref-cmd{font-family:monospace;font-size:.9rem;color:var(--green);padding:2px 0;display:block}
.ref-cmd::before{content:'  ';white-space:pre}
.ref-comment{color:var(--tx3);font-size:.86rem;font-style:italic;margin-top:3px}
/* ── INPUT ── */
.input-row{display:flex;gap:10px;margin-bottom:10px;align-items:center;flex-wrap:wrap}
.input-row label{color:var(--tx2);font-size:.9rem;font-weight:600;min-width:130px;font-family:monospace;text-transform:uppercase;letter-spacing:.5px}
input,select{background:var(--glass2);border:1px solid var(--border);color:var(--tx);padding:10px 14px;border-radius:var(--r-sm);font-size:.92rem;font-family:monospace;transition:all .2s;min-width:160px}
input:focus,select:focus{outline:none;border-color:var(--blue);box-shadow:0 0 0 3px var(--blue-l)}
select option{background:var(--bg2)}
/* ── RESPONSIVE ── */
@media(max-width:768px){
  .sidebar{transform:translateX(-100%)}
  .main{margin-left:0}
  .stats{grid-template-columns:1fr 1fr}
  .machines{flex-direction:column}
}
</style>
</head>
<body>
<div class="app">

<!-- ═══ SIDEBAR ═══ -->
<aside class="sidebar">
  <div class="sb-logo">
    <div class="sb-logo-top">
      <div class="sb-logo-icon">⚡</div>
      <div>
        <div class="sb-logo-name">NetShield SDN</div>
        <div style="font-size:.58rem;color:var(--tx3);letter-spacing:1.5px;text-transform:uppercase;margin-top:2px">T1600G-28PS · VLAN {{ config.vlan }}</div>
      </div>
    </div>
  </div>
  <nav class="sb-nav">
    <div class="sb-section">Navigation</div>
    <button class="sb-item active" data-page="dashboard" onclick="showPage('dashboard')">
      <span class="si-icon">⬡</span><span class="si-txt">Tableau de bord</span>
    </button>
    <div class="sb-section">Sécurité</div>
    <button class="sb-item" data-page="quar" onclick="showPage('quar')">
      <span class="si-icon">🔒</span><span class="si-txt">Quarantaine</span>
      <span class="si-count" id="sb-quar" style="display:none"></span>
    </button>
    <button class="sb-item" data-page="restore" onclick="showPage('restore')">
      <span class="si-icon">🔓</span><span class="si-txt">Restaurer Ports</span>
      <span class="si-count" id="sb-restore" style="display:none"></span>
    </button>
    <button class="sb-item" data-page="macs" onclick="showPage('macs')">
      <span class="si-icon">⛔</span><span class="si-txt">MACs Bloqués</span>
      <span class="si-count" id="sb-macs" style="display:none"></span>
    </button>
    <div class="sb-section">Monitoring</div>
    <button class="sb-item" data-page="alerts" onclick="showPage('alerts')">
      <span class="si-icon">🚨</span><span class="si-txt">Alertes Suricata</span>
    </button>
    <button class="sb-item" data-page="cmds" onclick="showPage('cmds')">
      <span class="si-icon">💻</span><span class="si-txt">Commandes Switch</span>
    </button>
    <button class="sb-item" data-page="hist" onclick="showPage('hist')">
      <span class="si-icon">📋</span><span class="si-txt">Historique MAC</span>
    </button>
    <div class="sb-section">Administration</div>
    <button class="sb-item" data-page="switch" onclick="showPage('switch')">
      <span class="si-icon">🖥</span><span class="si-txt">Contrôle Switch</span>
    </button>
    <button class="sb-item" data-page="admin" onclick="showPage('admin')">
      <span class="si-icon">⚙️</span><span class="si-txt">Actions manuelles</span>
    </button>
    <button class="sb-item" data-page="cfg" onclick="showPage('cfg')">
      <span class="si-icon">🔧</span><span class="si-txt">Configuration</span>
    </button>
  </nav>
  <div class="sb-footer">
    <div class="sb-status {{ 'on' if monitoring else 'off' }}" id="sb-status-badge">
      <div class="sb-dot"></div>
      <span id="sb-status-txt">{{ 'SURVEILLANCE ACTIVE' if monitoring else 'SYSTÈME INACTIF' }}</span>
    </div>
  </div>
</aside>

<!-- ═══ MAIN ═══ -->
<div class="main">

  <!-- TOPBAR -->
  <div class="topbar">
    <div style="display:flex;align-items:center;gap:14px">
      <div class="tb-title" id="tb-title">Tableau de bord</div>
    </div>
    <div class="tb-right">
      <div class="tb-clock" id="clock">--:--:--</div>
      <button class="btn btn-on btn-sm" onclick="startMon()">▶ Démarrer</button>
      <button class="btn btn-off btn-sm" onclick="stopMon()">■ Arrêter</button>
      <button class="btn btn-blue btn-sm" onclick="refreshData()">↻ Sync</button>
      <button class="btn btn-sm" id="btn-audio-enable" style="background:var(--purple);color:#fff" onclick="_initAudio();this.style.display='none';testAlarm()">🔊 Son</button>
      <button class="btn btn-sm btn-grey" onclick="testAlarm()">🎵 Test</button>
      <button class="btn btn-sm" id="btn-sound" style="background:var(--orange);color:#fff;display:none" onclick="stopAlarm()">🔕 Alarme</button>
    </div>
  </div>

  <div class="content">

    <!-- STATS -->
    <div class="stats">
      <div class="stat s-alert">
        <div class="lbl">🚨 Alertes Suricata</div>
        <div class="num" id="s-alerts">{{ stats.alerts }}</div>
        <div class="sub">Événements détectés</div>
      </div>
      <div class="stat s-quar">
        <div class="lbl">🔒 Quarantaine VLAN {{ config.vlan }}</div>
        <div class="num" id="s-quar">{{ stats.quarantine }}</div>
        <div class="sub">Machines isolées actives</div>
      </div>
      <div class="stat s-block">
        <div class="lbl">⛔ MACs Bannis</div>
        <div class="num" id="s-block">{{ stats.blocked }}</div>
        <div class="sub">Reconnexion impossible</div>
      </div>
      <div class="stat s-hist">
        <div class="lbl">📋 Suivi MAC</div>
        <div class="num" id="s-hist">{{ stats.history }}</div>
        <div class="sub">Adresses enregistrées</div>
      </div>
    </div>

    <!-- ═══ PAGE : DASHBOARD ══════════════════════════════════════ -->
    <div id="page-dashboard" class="page active">
      <div class="dash-grid">

        <!-- Contrôle réseau -->
        <div class="dash-col dash-col-green">
          <div class="dash-title" style="justify-content:space-between">
            🌐 Contr&#244;le r&#233;seau
            <button class="btn btn-sm" style="background:var(--green);color:#fff;font-size:.6rem" onclick="scanConnected()">🔄 Scanner</button>
          </div>
          <div class="dash-stat-row" style="margin-bottom:12px">
            <div class="dash-stat">
              <div class="dash-stat-num" id="dash-connected-count">—</div>
              <div class="dash-stat-lbl">Machines connect&#233;es</div>
            </div>
            <div class="dash-stat">
              <div class="dash-stat-num" id="dash-backup-count">0</div>
              <div class="dash-stat-lbl">Backups actifs</div>
            </div>
            <div class="dash-stat">
              <div class="dash-stat-num" id="dash-port-count" style="color:var(--red)">0</div>
              <div class="dash-stat-lbl">En quarantaine</div>
            </div>
          </div>
          <div id="dash-machines-list" style="max-height:320px;overflow-y:auto">
            <div style="color:var(--tx3);font-size:.72rem;text-align:center;padding:16px">
              Cliquez sur 🔄 Scanner pour voir les machines connect&#233;es
            </div>
          </div>
          <div class="dash-mini-backup" id="dash-bp-mini" style="margin-top:10px"></div>
        </div>

        <!-- Supervision -->
        <div class="dash-col dash-col-blue">
          <div class="dash-title">📊 Supervision</div>
          <div id="dash-alerts-mini"></div>
          <div class="dash-stat-row">
            <div class="dash-stat">
              <div class="dash-stat-num" id="dash-al-count">0</div>
              <div class="dash-stat-lbl">Alertes totales</div>
            </div>
            <div class="dash-stat">
              <div class="dash-stat-num" id="dash-mac-count">0</div>
              <div class="dash-stat-lbl">MACs suivis</div>
            </div>
          </div>
          <div style="margin-top:12px">
            <div class="sec-title" style="margin-bottom:8px;border:none;padding:0">Derni&#232;res alertes</div>
            <div id="dash-recent-alerts"></div>
          </div>
        </div>

        <!-- Sécurité -->
        <div class="dash-col dash-col-red">
          <div class="dash-title">🛡 S&#233;curit&#233;</div>
          <div class="icon-grid">
            <div class="icon-btn" onclick="showPage('quar')">
              <div class="ib-icon">🔒</div>
              <div class="ib-label">Quarantaine</div>
              <div class="ib-count" id="dash-quar-count" style="color:var(--red)">0</div>
            </div>
            <div class="icon-btn" onclick="showPage('macs')">
              <div class="ib-icon">⛔</div>
              <div class="ib-label">MACs bloqu&#233;s</div>
              <div class="ib-count" id="dash-mac-blocked" style="color:var(--red)">0</div>
            </div>
            <div class="icon-btn" onclick="showPage('restore')">
              <div class="ib-icon">🔓</div>
              <div class="ib-label">Restaurer</div>
            </div>
            <div class="icon-btn" onclick="showPage('alerts')">
              <div class="ib-icon">🚨</div>
              <div class="ib-label">Alertes</div>
            </div>
          </div>
          <div style="margin-top:12px">
            <div class="sec-title" style="margin-bottom:8px;border:none;padding:0">Menaces actives</div>
            <div id="dash-threats"></div>
          </div>
        </div>
      </div>

      <!-- Console sur le dashboard -->
      <div class="sec">
        <div class="sec-title">📟 Console Syst&#232;me</div>
        <div class="term" id="term"></div>
      </div>

      <!-- ── ANALYTICS PANEL ── -->
      <div style="background:var(--glass);border:1px solid var(--border);border-radius:var(--r);padding:24px;margin-bottom:16px;backdrop-filter:blur(10px)">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px">
          <div style="display:flex;align-items:center;gap:12px">
            <div style="width:40px;height:40px;background:linear-gradient(135deg,#3b82f6,#8b5cf6);border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:1.1rem;box-shadow:0 0 20px rgba(59,130,246,.35)">📊</div>
            <div>
              <div style="color:var(--tx);font-weight:800;font-size:.95rem;font-family:monospace;letter-spacing:1px">THREAT ANALYTICS</div>
              <div style="color:var(--tx3);font-size:.6rem;letter-spacing:2px;text-transform:uppercase;margin-top:2px">Intelligence en temps réel</div>
            </div>
          </div>
          <div id="analytics-live" style="display:flex;align-items:center;gap:6px;background:var(--green-l);border:1px solid var(--green-b);border-radius:20px;padding:5px 14px">
            <div style="width:6px;height:6px;border-radius:50%;background:var(--green);animation:pulse 1.5s infinite;box-shadow:0 0 8px var(--green)"></div>
            <span style="color:var(--green);font-size:.62rem;font-family:monospace;letter-spacing:1px;font-weight:700">LIVE</span>
          </div>
        </div>

        <div style="display:grid;grid-template-columns:260px 1fr 1fr;gap:16px;align-items:start">

          <!-- Donut centré -->
          <div style="background:var(--glass2);border-radius:12px;padding:16px;border:1px solid var(--border);display:flex;flex-direction:column;align-items:center">
            <div style="color:var(--tx3);font-size:.58rem;text-transform:uppercase;letter-spacing:1.5px;font-family:monospace;margin-bottom:12px">Types d'attaques</div>
            <div style="position:relative;width:160px;height:160px">
              <canvas id="chart-types"></canvas>
              <div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);text-align:center;pointer-events:none">
                <div id="donut-total" style="font-size:1.8rem;font-weight:800;color:var(--tx);font-family:monospace;line-height:1">0</div>
                <div style="font-size:.52rem;color:var(--tx3);text-transform:uppercase;letter-spacing:1px">alertes</div>
              </div>
            </div>
            <div id="chart-legend" style="margin-top:12px;width:100%"></div>
          </div>

          <!-- Line chart timeline -->
          <div style="background:var(--glass2);border-radius:12px;padding:16px;border:1px solid var(--border)">
            <div style="color:var(--tx3);font-size:.58rem;text-transform:uppercase;letter-spacing:1.5px;font-family:monospace;margin-bottom:12px">Timeline (tranches 5 min)</div>
            <div style="position:relative;height:160px">
              <canvas id="chart-timeline"></canvas>
            </div>
          </div>

          <!-- Barres horizontales top menaces -->
          <div style="background:var(--glass2);border-radius:12px;padding:16px;border:1px solid var(--border)">
            <div style="color:var(--tx3);font-size:.58rem;text-transform:uppercase;letter-spacing:1.5px;font-family:monospace;margin-bottom:12px">Top menaces</div>
            <div style="position:relative;height:160px">
              <canvas id="chart-top"></canvas>
            </div>
          </div>

        </div>

        <!-- Indicateurs bas -->
        <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-top:16px">
          <div id="ind-total"  class="_ind" data-color="#ef4444"></div>
          <div id="ind-active" class="_ind" data-color="#f97316"></div>
          <div id="ind-mac"    class="_ind" data-color="#a855f7"></div>
          <div id="ind-sev"    class="_ind" data-color="#0891b2"></div>
        </div>
      </div>
    </div>

    <!-- ═══ PAGE : QUARANTAINE ════════════════════════════════════ -->
    <div id="page-quar" class="page">
      <div class="sec">
        <!-- ── Machines suspectes (compteur live) ── -->
        <div id="suspect-panel" style="display:none;margin-bottom:18px">
          <div class="sec-title" style="color:var(--orange)">⚠️ Machines suspectes — en cours de comptage</div>
          <div id="suspect-list"></div>
        </div>

        <div class="sec-title">🔒 Machines isol&#233;es — VLAN {{ config.vlan }}</div>
        <div id="backup-panel" class="backup-panel" style="display:none">
          <div class="backup-panel-title">🔄 <span>Ports backup</span> <span id="backup-active-count" style="color:var(--blue)"></span></div>
          <div class="backup-grid" id="backup-grid"></div>
        </div>
        <div id="quar-list"></div>
      </div>
    </div>

    <!-- ═══ PAGE : RESTAURER PORTS ════════════════════════════════ -->
    <div id="page-restore" class="page">
      <div class="sec">
        <div class="sec-title">🔓 Ports en quarantaine — action requise</div>
        <div id="restore-active"></div>
      </div>
      <div class="sec">
        <div class="sec-title">📜 Historique des restaurations</div>
        <div id="restore-done"></div>
      </div>
    </div>

    <!-- ═══ PAGE : MACs BLOQUÉS ═══════════════════════════════════ -->
    <div id="page-macs" class="page">
      <div class="sec">
        <div class="sec-title">⛔ MACs actuellement bloqu&#233;s</div>
        <div id="macs-active"></div>
      </div>
      <div class="sec">
        <div class="sec-title">📜 Historique des blocages MAC</div>
        <div id="macs-hist"></div>
      </div>
    </div>

    <!-- ═══ PAGE : ALERTES ════════════════════════════════════════ -->
    <div id="page-alerts" class="page">
      <div class="sec">
        <div class="sec-title">🚨 Journal des alertes Suricata</div>
        <table>
          <thead><tr><th></th><th>Heure</th><th>SID</th><th>IP Source</th><th>IP Dest</th><th>Signature</th><th>S&#233;v.</th></tr></thead>
          <tbody id="alerts-tb"></tbody>
        </table>
      </div>
    </div>

    <!-- ═══ PAGE : SWITCH CMDS ════════════════════════════════════ -->
    <div id="page-cmds" class="page">
      <div style="display:grid;grid-template-columns:1fr 360px;gap:16px;align-items:start">
        <div class="sec">
          <div class="sec-title">💻 Commandes envoy&#233;es au T1600G-28PS</div>
          <div id="cmd-list"><p style="color:var(--tx2);padding:20px;text-align:center;">Aucune commande envoy&#233;e</p></div>
        </div>
        <div>
          <div class="ref-box">
            <div class="ref-title">📖 R&#233;f&#233;rence — Isolation</div>
            <div class="ref-phase">
              <div class="ref-phase-title">Isolation VLAN {{ config.vlan }} — directe</div>
              <code class="ref-cmd">interface gigabitEthernet 1/0/X</code>
              <code class="ref-cmd">no switchport general allowed vlan {{ config.trusted_vlans }}</code>
              <code class="ref-cmd">switchport general allowed vlan {{ config.vlan }} untagged</code>
              <code class="ref-cmd">switchport pvid {{ config.vlan }}</code>
              <code class="ref-cmd">no shutdown</code>
              <code class="ref-cmd">exit</code>
              <div class="ref-comment" style="margin-top:4px;">&#8627; Isolation directe — aucun d&#233;lai</div>
            </div>
            <div class="ref-phase">
              <div class="ref-phase-title">Ban MAC global</div>
              <code class="ref-cmd">mac address-table filtering aa:bb:cc:dd:ee:ff vid {{ config.vlan_normal }}</code>
              <code class="ref-cmd">mac address-table filtering aa:bb:cc:dd:ee:ff vid 10</code>
              <code class="ref-cmd">mac address-table filtering aa:bb:cc:dd:ee:ff vid {{ config.vlan }}</code>
              <div class="ref-comment">&#8627; D&#233;blocage : m&#234;mes commandes pr&#233;fix&#233;es par <strong>no</strong></div>
            </div>
            <div class="ref-phase" style="margin-bottom:0">
              <div class="ref-phase-title">Restauration &#8594; VLAN {{ config.trusted_vlans }}</div>
              <code class="ref-cmd">interface gigabitEthernet 1/0/X</code>
              <code class="ref-cmd">no switchport general allowed vlan {{ config.vlan }}</code>
              <code class="ref-cmd">switchport general allowed vlan {{ config.trusted_vlans }} untagged</code>
              <code class="ref-cmd">switchport pvid {{ config.vlan_normal }}</code>
              <code class="ref-cmd">no shutdown</code>
              <code class="ref-cmd">exit</code>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- ═══ PAGE : HISTORIQUE MAC ══════════════════════════════════ -->
    <div id="page-hist" class="page">
      <div class="sec">
        <div class="sec-title">📋 Historique MAC</div>
        <table>
          <thead><tr><th>MAC</th><th>Port</th><th>1&#232;re Vue</th><th>Derni&#232;re Vue</th><th>Derni&#232;re Attaque</th><th>Violations</th><th>Statut</th></tr></thead>
          <tbody id="hist-tb"></tbody>
        </table>
      </div>
    </div>

    <!-- ═══ PAGE : SWITCH CONTROL ════════════════════════════════ -->
    <div id="page-switch" class="page">

      <!-- Inputs partagés -->
      <div class="sec" style="padding:14px 20px">
        <div style="display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end">
          <div><div style="font-size:.6rem;color:var(--tx2);text-transform:uppercase;letter-spacing:.8px;margin-bottom:4px;font-family:monospace">Port (ex: 1/0/5)</div>
            <input id="sw-port" placeholder="1/0/X" style="min-width:130px"></div>
          <div><div style="font-size:.6rem;color:var(--tx2);text-transform:uppercase;letter-spacing:.8px;margin-bottom:4px;font-family:monospace">VLAN ID</div>
            <input id="sw-vlan" placeholder="666" style="min-width:80px"></div>
          <div><div style="font-size:.6rem;color:var(--tx2);text-transform:uppercase;letter-spacing:.8px;margin-bottom:4px;font-family:monospace">Nom / Description</div>
            <input id="sw-name" placeholder="nom ou description" style="min-width:160px"></div>
          <div><div style="font-size:.6rem;color:var(--tx2);text-transform:uppercase;letter-spacing:.8px;margin-bottom:4px;font-family:monospace">IP cible / Commande</div>
            <input id="sw-target" placeholder="192.168.0.X ou show ..." style="min-width:200px"></div>
          <div><div style="font-size:.6rem;color:var(--tx2);text-transform:uppercase;letter-spacing:.8px;margin-bottom:4px;font-family:monospace">Vitesse</div>
            <select id="sw-speed" style="min-width:100px"><option value="auto">Auto</option><option value="10">10 Mbps</option><option value="100">100 Mbps</option><option value="1000">1 Gbps</option></select></div>
          <div><div style="font-size:.6rem;color:var(--tx2);text-transform:uppercase;letter-spacing:.8px;margin-bottom:4px;font-family:monospace">Duplex</div>
            <select id="sw-duplex" style="min-width:90px"><option value="auto">Auto</option><option value="full">Full</option><option value="half">Half</option></select></div>
        </div>
      </div>

      <div class="dash-grid" style="grid-template-columns:1fr 1fr;gap:16px">

        <!-- Gestion des Ports -->
        <div class="dash-col dash-col-green">
          <div class="dash-title">🔌 Gestion des Ports</div>
          <div class="icon-grid" style="grid-template-columns:repeat(3,1fr)">
            <div class="icon-btn" onclick="swCall('/api/switch/port/shutdown',{port:swPort()},'Éteindre port')">
              <div class="ib-icon">🔴</div><div class="ib-label">Shutdown</div></div>
            <div class="icon-btn" onclick="swCall('/api/switch/port/enable',{port:swPort()},'Allumer port')">
              <div class="ib-icon">🟢</div><div class="ib-label">No Shutdown</div></div>
            <div class="icon-btn" onclick="swCall('/api/switch/port/status',{port:swPort()},'Statut port')">
              <div class="ib-icon">📊</div><div class="ib-label">Statut</div></div>
            <div class="icon-btn" onclick="swCall('/api/switch/port/stats',{port:swPort()},'Stats port')">
              <div class="ib-icon">📈</div><div class="ib-label">Statistiques</div></div>
            <div class="icon-btn" onclick="swCall('/api/switch/port/speed',{port:swPort(),speed:document.getElementById('sw-speed').value,duplex:document.getElementById('sw-duplex').value},'Vitesse port')">
              <div class="ib-icon">⚡</div><div class="ib-label">Vitesse/Duplex</div></div>
            <div class="icon-btn" onclick="swCall('/api/switch/port/description',{port:swPort(),description:document.getElementById('sw-name').value},'Description port')">
              <div class="ib-icon">🏷</div><div class="ib-label">Description</div></div>
            <div class="icon-btn" onclick="swGet('/api/switch/port/all_status','Tous les ports')">
              <div class="ib-icon">🗂</div><div class="ib-label">Tous les ports</div></div>
            <div class="icon-btn" onclick="swCall('/api/switch/mac/table_port',{port:swPort()},'MACs sur port')">
              <div class="ib-icon">🔍</div><div class="ib-label">MACs du port</div></div>
            <div class="icon-btn" onclick="swCall('/api/switch/vlan/port_info',{port:swPort()},'VLANs du port')">
              <div class="ib-icon">🏷</div><div class="ib-label">VLANs du port</div></div>
          </div>
        </div>

        <!-- Gestion des VLANs -->
        <div class="dash-col dash-col-blue">
          <div class="dash-title">🏷 Gestion des VLANs</div>
          <div class="icon-grid" style="grid-template-columns:repeat(3,1fr)">
            <div class="icon-btn" onclick="swGet('/api/switch/vlan/list','Liste VLANs')">
              <div class="ib-icon">📋</div><div class="ib-label">Lister VLANs</div></div>
            <div class="icon-btn" onclick="swCall('/api/switch/vlan/create',{vlan_id:swVlan(),name:document.getElementById('sw-name').value},'Créer VLAN')">
              <div class="ib-icon">➕</div><div class="ib-label">Créer VLAN</div></div>
            <div class="icon-btn" onclick="swCall('/api/switch/vlan/delete',{vlan_id:swVlan()},'Supprimer VLAN')">
              <div class="ib-icon">🗑</div><div class="ib-label">Supprimer VLAN</div></div>
            <div class="icon-btn" onclick="swCall('/api/switch/vlan/assign',{port:swPort(),vlan_id:swVlan(),mode:'untagged',set_pvid:true},'Assigner port→VLAN')">
              <div class="ib-icon">🔗</div><div class="ib-label">Assigner Port</div></div>
            <div class="icon-btn" onclick="swCall('/api/switch/vlan/assign',{port:swPort(),vlan_id:swVlan(),mode:'tagged',set_pvid:false},'Port tagged VLAN')">
              <div class="ib-icon">🔖</div><div class="ib-label">Port Tagged</div></div>
            <div class="icon-btn" onclick="swCall('/api/switch/vlan/remove',{port:swPort(),vlan_id:swVlan()},'Retirer port de VLAN')">
              <div class="ib-icon">✂</div><div class="ib-label">Retirer Port</div></div>
          </div>
        </div>

        <!-- Sécurité Switch -->
        <div class="dash-col dash-col-red">
          <div class="dash-title">🔒 Sécurité Switch</div>
          <div class="icon-grid" style="grid-template-columns:repeat(3,1fr)">
            <div class="icon-btn" onclick="swGet('/api/switch/mac/table','Table MAC globale')">
              <div class="ib-icon">📋</div><div class="ib-label">Table MAC</div></div>
            <div class="icon-btn" onclick="swGet('/api/switch/mac/filters','Filtres MAC actifs')">
              <div class="ib-icon">⛔</div><div class="ib-label">Filtres MAC</div></div>
            <div class="icon-btn" onclick="swCall('/api/switch/mac/clear',{},'Vider table MAC')">
              <div class="ib-icon">🧹</div><div class="ib-label">Vider MAC</div></div>
            <div class="icon-btn" onclick="swCall('/api/switch/storm',{port:swPort(),action:'enable',rate:'256'},'Storm control ON')">
              <div class="ib-icon">🌪</div><div class="ib-label">Storm ON</div></div>
            <div class="icon-btn" onclick="swCall('/api/switch/storm',{port:swPort(),action:'disable'},'Storm control OFF')">
              <div class="ib-icon">☀</div><div class="ib-label">Storm OFF</div></div>
            <div class="icon-btn" onclick="swCall('/api/switch/port_security',{port:swPort(),action:'enable',max_mac:'3'},'Port Security ON')">
              <div class="ib-icon">🔐</div><div class="ib-label">Port Sec. ON</div></div>
            <div class="icon-btn" onclick="swCall('/api/switch/port_security',{port:swPort(),action:'disable'},'Port Security OFF')">
              <div class="ib-icon">🔓</div><div class="ib-label">Port Sec. OFF</div></div>
            <div class="icon-btn" onclick="swGet('/api/switch/stp','Spanning Tree')">
              <div class="ib-icon">🌳</div><div class="ib-label">Spanning Tree</div></div>
            <div class="icon-btn" onclick="swGet('/api/switch/arp','Table ARP')">
              <div class="ib-icon">🗺</div><div class="ib-label">Table ARP</div></div>
          </div>
        </div>

        <!-- Diagnostic & Système -->
        <div class="dash-col" style="background:var(--orange-l);border-color:var(--orange-b)">
          <div class="dash-title" style="color:var(--orange)">🔬 Diagnostic &amp; Syst&#232;me</div>
          <div class="icon-grid" style="grid-template-columns:repeat(3,1fr)">
            <div class="icon-btn" onclick="swCall('/api/switch/ping',{target:document.getElementById('sw-target').value,count:5},'Ping depuis switch')">
              <div class="ib-icon">🏓</div><div class="ib-label">Ping</div></div>
            <div class="icon-btn" onclick="swCall('/api/switch/traceroute',{target:document.getElementById('sw-target').value},'Traceroute')">
              <div class="ib-icon">🛤</div><div class="ib-label">Traceroute</div></div>
            <div class="icon-btn" onclick="swGet('/api/switch/lldp','Voisins LLDP')">
              <div class="ib-icon">🔭</div><div class="ib-label">LLDP Voisins</div></div>
            <div class="icon-btn" onclick="swGet('/api/switch/system/version','Version firmware')">
              <div class="ib-icon">ℹ</div><div class="ib-label">Version</div></div>
            <div class="icon-btn" onclick="swGet('/api/switch/system/info','Infos système')">
              <div class="ib-icon">🖥</div><div class="ib-label">Infos système</div></div>
            <div class="icon-btn" onclick="swGet('/api/switch/system/cpu','CPU switch')">
              <div class="ib-icon">⚙</div><div class="ib-label">CPU</div></div>
            <div class="icon-btn" onclick="swGet('/api/switch/system/memory','Mémoire switch')">
              <div class="ib-icon">💾</div><div class="ib-label">Mémoire</div></div>
            <div class="icon-btn" onclick="swGet('/api/switch/system/logs','Logs switch')">
              <div class="ib-icon">📜</div><div class="ib-label">Logs Switch</div></div>
            <div class="icon-btn" onclick="swGet('/api/switch/system/config','Running config')">
              <div class="ib-icon">📄</div><div class="ib-label">Running Config</div></div>
            <div class="icon-btn" onclick="swGet('/api/switch/system/startup','Startup config')">
              <div class="ib-icon">📑</div><div class="ib-label">Startup Config</div></div>
            <div class="icon-btn" onclick="swPost('/api/switch/system/save',{},'Sauvegarder config')">
              <div class="ib-icon">💿</div><div class="ib-label">Sauvegarder</div></div>
            <div class="icon-btn" onclick="swCustomCmd()">
              <div class="ib-icon">⌨</div><div class="ib-label">Cmd perso</div></div>
          </div>
        </div>
      </div>

      <!-- Zone de sortie -->
      <div class="sec">
        <div class="sec-title" id="sw-out-title">📟 Sortie switch</div>
        <div id="sw-output" style="background:#1e293b;border-radius:8px;padding:14px;min-height:80px;font-family:monospace;font-size:.74rem;color:#86efac;white-space:pre-wrap;overflow-x:auto;border:1px solid rgba(0,0,0,.15);max-height:400px;overflow-y:auto">
          Cliquez sur un bouton pour envoyer une commande au switch...</div>
      </div>
    </div>

    <!-- ═══ PAGE : ADMIN ══════════════════════════════════════════ -->
    <div id="page-admin" class="page">
      <div class="sec">
        <div class="sec-title">⚙️ Contr&#244;le Manuel — Admin</div>
        <div class="input-row">
          <label>MAC</label><input id="m-mac" placeholder="aa:bb:cc:dd:ee:ff">
          <label>Port</label><input id="m-port" placeholder="1/0/X">
          <label>IP</label><input id="m-ip" placeholder="192.168.0.X">
        </div>
        <div class="ctrls">
          <button class="btn btn-blue" onclick="findPort()">🔍 Chercher Port</button>
          <button class="btn btn-ora"  onclick="manualQuar()">🔒 Quarantaine VLAN {{ config.vlan }}</button>
          <button class="btn btn-red"  onclick="manualBlockMac()">⛔ Bloquer MAC Global</button>
          <button class="btn btn-grn"  onclick="manualRestore()">✅ Restaurer Port</button>
          <button class="btn btn-grn"  onclick="manualUnblock()">🔓 D&#233;bloquer MAC</button>
          <button class="btn btn-blue" onclick="scanMachine()">🖥 Scanner Machine</button>
        </div>
        <div class="ctrls" style="margin-top:0">
          <button class="btn btn-red" onclick="blockPing()">🏓 Bloquer ICMP Global</button>
          <button class="btn btn-grn" style="font-weight:700" onclick="restoreAll()">♻️ Restaurer TOUT (ports + MACs)</button>
        </div>
        <div id="m-res" style="margin-top:12px;padding:13px;background:#1e293b;border-radius:8px;font-family:monospace;font-size:.78rem;min-height:40px;border:1px solid rgba(0,0,0,.15);white-space:pre-wrap;color:#86efac"></div>
      </div>
    </div>

    <!-- ═══ PAGE : CONFIG ══════════════════════════════════════════ -->
    <div id="page-cfg" class="page">
      <div class="sec">
        <div class="sec-title">🔧 Configuration Switch</div>
        <div class="input-row"><label>IP Switch</label>       <input id="c-host" value="{{ config.host }}"></div>
        <div class="input-row"><label>Username</label>        <input id="c-user" value="{{ config.username }}"></div>
        <div class="input-row"><label>Password</label>        <input id="c-pass" type="password" value="{{ config.password }}"></div>
        <div class="input-row"><label>VLAN Quarantaine</label><input id="c-vlan" type="number" value="{{ config.vlan }}"></div>
        <div class="input-row"><label>Port Monitoring</label> <input id="c-port" value="{{ config.port_monitoring }}"></div>
        <div class="input-row"><label>HOME_NET</label>        <input id="c-home" value="{{ config.home_net }}"></div>
        <div class="input-row"><label>IPs Prot&#233;g&#233;es</label><input id="c-prot" value="{{ config.protected_ips }}" style="min-width:280px"></div>
        <div class="ctrls">
          <button class="btn btn-on"   onclick="saveConfig()">💾 Sauvegarder</button>
          <button class="btn btn-blue" onclick="testConn()">🔗 Tester Connexion</button>
        </div>
      </div>

      <!-- Telegram -->
      <div class="sec">
        <div class="sec-title">📱 Bot Telegram — @sdnquarantaine_bot</div>
        <p style="color:var(--tx2);font-size:.74rem;margin-bottom:14px">
          &#201;tape 1 : Envoyez <strong>/start</strong> au bot dans Telegram.<br>
          &#201;tape 2 : Cliquez <em>Auto-D&#233;tecter</em> ou entrez le Chat ID manuellement.
        </p>
        <div class="input-row">
          <label>Chat ID</label>
          <input id="tg-chat" placeholder="123456789" value="{{ config.telegram_chat_id }}" style="min-width:180px">
          <button class="btn btn-blue" onclick="tgSetChat()">💾 D&#233;finir</button>
          <button class="btn btn-grn"  onclick="tgAutoDetect()">🔍 Auto-D&#233;tecter</button>
          <button class="btn btn-ora"  onclick="tgTest()">📨 Test</button>
        </div>
        <div id="tg-res" style="margin-top:10px;font-family:monospace;font-size:.74rem;color:var(--green)"></div>
      </div>
    </div>

  </div><!-- /content -->
</div><!-- /main -->
</div><!-- /app -->

<script>
// ── Navigation ───────────────────────────────────────────────────────
const PAGE_TITLES={dashboard:'Tableau de bord',quar:'Quarantaine',restore:'Restaurer Ports',macs:'MACs Bloqués',alerts:'Alertes',cmds:'Commandes Switch',hist:'Historique MAC',switch:'Contrôle Switch — T1600G-28PS',admin:'Administration',cfg:'Configuration'};
function showPage(id){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.sb-item').forEach(i=>i.classList.remove('active'));
  const pg=document.getElementById('page-'+id);
  if(pg) pg.classList.add('active');
  const btn=document.querySelector('.sb-item[data-page="'+id+'"]');
  if(btn) btn.classList.add('active');
  document.getElementById('tb-title').textContent=PAGE_TITLES[id]||id;
}

// ── Clock ────────────────────────────────────────────────────────────
function updateClock(){
  document.getElementById('clock').textContent=new Date().toLocaleTimeString('fr-FR',{hour12:false});
}
setInterval(updateClock,1000); updateClock();

// ── Helpers UI ───────────────────────────────────────────────────────
function badge(cls,txt){return '<span class="badge '+cls+'">'+txt+'</span>';}
function modeBadge(mode){
  const m={
    DUAL_QUARANTINE:    ['b-pur','💜 DUAL'],
    PROTECT_VICTIM:     ['b-ora','🛡 Victime'],
    ISOLATE_ATTACKER:   ['b-red','⚔ Attaquant'],
    SERVER_LOCAL_ATTACK:['b-srv','🖥 SERVEUR'],
    SERVER_EXTERNAL_ATTACK:['b-cyan','🌐 Externe'],
    EXTERNAL_ONLY:      ['b-cyan','🌐 Externe'],
    MANUAL:             ['b-grn','⚙️ Manuel'],
  };
  const [c,t]=m[mode]||['b-cyan',mode];
  return badge(c,t);
}
function mcard(title,color,info,ip,port,isAtk,isBlocked){
  info=info||{};
  const f=k=>info[k]&&info[k]!=='Unknown'?info[k]:'—';
  const portCls=isAtk?'atk':port&&port!=='N/A'?'vic':'na';
  const portLabel=port&&port!=='N/A'?'GE&nbsp;'+port:'N/A';
  const ports=(info.open_ports||[]).slice(0,5).join(' | ')||'—';
  return '<div class="mcard" style="border:1px solid '+color+'30">'+
    '<div class="mcard-title" style="color:'+color+'">'+title+'</div>'+
    '<div class="mcard-port '+portCls+'">PORT&nbsp;'+portLabel+'</div>'+
    '<div class="mcard-row"><span class="mcard-label">IP</span><span class="mcard-val" style="color:'+color+';font-weight:700">'+(ip||'?')+'</span></div>'+
    '<div class="mcard-row"><span class="mcard-label">Hostname</span><span class="mcard-val">'+f('hostname')+'</span></div>'+
    '<div class="mcard-row"><span class="mcard-label">MAC</span><span class="mcard-val">'+f('mac')+'</span></div>'+
    '<div class="mcard-row"><span class="mcard-label">Fabricant</span><span class="mcard-val">'+f('vendor')+'</span></div>'+
    '<div class="mcard-row"><span class="mcard-label">Modèle</span><span class="mcard-val" style="font-weight:600">'+f('model').substring(0,50)+'</span></div>'+
    '<div class="mcard-row"><span class="mcard-label">OS</span><span class="mcard-val">'+f('os').substring(0,50)+'</span></div>'+
    '<div class="mcard-row"><span class="mcard-label">N° Série</span><span class="mcard-val serial" style="font-family:monospace;font-size:.7rem">'+f('serial')+'</span></div>'+
    '<div class="mcard-row"><span class="mcard-label">Ports ouverts</span><span class="mcard-val" style="font-size:.6rem">'+ports+'</span></div>'+
    (isAtk&&isBlocked?'<div style="margin-top:8px">'+badge('b-red','⛔ MAC BLOQUÉ — tous ports')+'</div>':'')+
  '</div>';
}

// ── Refresh ──────────────────────────────────────────────────────────
async function refreshData(){
  let d;
  try{const r=await fetch('/api/status');d=await r.json();}catch(e){return;}

  // ── Alarme sonore ──
  const newCount=d.alert_count||0;
  const activeQ=(d.quarantined||[]).filter(q=>!q.restored);
  if(newCount>_lastAlertCount && activeQ.length>0) startAlarm();
  if(activeQ.length===0) stopAlarm();
  _lastAlertCount=newCount;

  // ── Mise à jour charts ──
  _updateCharts(d.alerts||[], d.quarantined||[], d.stats||{});

  const st=d.stats||{};
  document.getElementById('s-alerts').textContent=st.alerts??0;
  document.getElementById('s-quar').textContent  =st.quarantine??0;
  document.getElementById('s-block').textContent =st.blocked??0;
  document.getElementById('s-hist').textContent  =st.history??0;

  const active=(d.quarantined||[]).filter(q=>!q.restored);
  const done  =(d.quarantined||[]).filter(q=>q.restored);

  // ── Machines suspectes ──
  const suspects=d.suspects||{};
  const threshold=d.alert_threshold||3;
  const suspectIPs=Object.keys(suspects);
  const suspPanel=document.getElementById('suspect-panel');
  const suspList =document.getElementById('suspect-list');
  if(suspPanel){
    if(suspectIPs.length>0){
      suspPanel.style.display='';
      suspList.innerHTML=suspectIPs.map(ip=>{
        const s=suspects[ip];
        const pct=Math.min(100,Math.round(s.count/threshold*100));
        const danger=s.count>=threshold;
        return '<div class="suspect-card">'+
          '<div class="suspect-count">'+(s.icon||'⚠️')+'&nbsp;'+s.count+'</div>'+
          '<div style="flex:1">'+
            '<div class="suspect-ip">'+ip+'</div>'+
            '<div class="suspect-dst">→ '+s.dst+'</div>'+
            '<div class="suspect-bar-wrap">'+
              '<div class="suspect-bar-track">'+
                '<div class="suspect-bar-fill'+(danger?' danger':'')
                  +'" style="width:'+pct+'%"></div>'+
              '</div>'+
              '<div class="suspect-label">'+s.count+' / '+threshold+' alertes &nbsp;·&nbsp; fenêtre '+d.alert_window+'s</div>'+
            '</div>'+
          '</div>'+
        '</div>';
      }).join('');
    } else {
      suspPanel.style.display='none';
    }
  }

  // ── Sidebar counts ──
  const updateCount=(id,n)=>{const el=document.getElementById(id);el.style.display=n>0?'':'none';el.textContent=n;};
  updateCount('sb-quar',active.length);
  updateCount('sb-restore',active.length);
  updateCount('sb-macs',(d.mac_blacklist||[]).length);

  // ── Dashboard ──
  document.getElementById('dash-quar-count').textContent=active.length;
  document.getElementById('dash-mac-blocked').textContent=(d.mac_blacklist||[]).length;
  document.getElementById('dash-al-count').textContent=d.stats.alerts;
  document.getElementById('dash-mac-count').textContent=d.stats.history;
  document.getElementById('dash-port-count').textContent=active.length+' isolés';
  const bact=d.backup_ports_active||{};
  document.getElementById('dash-backup-count').textContent=Object.keys(bact).length;
  // backup mini grid on dashboard
  const bmap=d.backup_map||{};
  document.getElementById('dash-bp-mini').innerHTML=Object.keys(bmap).sort((a,b)=>parseInt(a)-parseInt(b)).map(p=>{
    const bp='1/0/'+bmap[p];
    const on=bact.hasOwnProperty(bp);
    return '<div class="dash-bp'+(on?' active':'')+'" title="Backup de 1/0/'+p+'">'+bmap[p]+(on?' &#9679;':'')+'</div>';
  }).join('');
  // recent alerts on dashboard
  const ral=document.getElementById('dash-recent-alerts');
  const last5=(d.alerts||[]).slice(-5).reverse();
  ral.innerHTML=last5.length===0?'<div style="color:var(--tx3);font-size:.72rem;padding:8px">Aucune alerte récente</div>':
    last5.map(a=>'<div class="dash-alert-item"><span>'+(a.attack_icon||'⚠️')+'</span><div style="flex:1;min-width:0"><div style="font-weight:600;font-size:.72rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+a.alert.substring(0,50)+'</div><div style="color:var(--tx3);font-size:.62rem;font-family:monospace">'+a.ip_src+' → '+a.ip_dst+'</div></div><span style="color:var(--tx3);font-size:.62rem;font-family:monospace;flex-shrink:0">'+a.time+'</span></div>').join('');
  // threats on dashboard
  const thr=document.getElementById('dash-threats');
  thr.innerHTML=active.length===0?'<div style="color:var(--tx3);font-size:.72rem;padding:8px">✅ Aucune menace active</div>':
    active.slice(0,4).map(q=>'<div class="dash-threat"><span>'+(q.attack_icon||'⚠️')+'</span><div style="flex:1"><div style="font-weight:600;font-size:.72rem">'+q.attack_desc+'</div><div style="color:var(--tx3);font-size:.62rem;font-family:monospace">'+(q.attacker_ip||'?')+' • GE '+(q.attacker_port||'N/A')+'</div></div>'+badge('b-act','🔒 VLAN 666')+'</div>').join('');

  // ── Quarantaine ──
  const ql=document.getElementById('quar-list');
  if(active.length===0&&done.length===0){
    ql.innerHTML='<div class="empty-state"><div class="es-icon">✅</div><div class="es-text">Aucune machine en quarantaine</div></div>';
  } else {
    ql.innerHTML=[...active,...done].map(q=>{
      const bl=q.mac_blocked&&!q.restored;
      return '<div class="qcard'+(q.restored?' restored':'')+'">'+
        '<div class="qcard-head">'+
          '<div class="qcard-title">'+
            '<span style="font-size:1.3rem">'+(q.attack_icon||'⚠️')+'</span>'+
            '<strong style="color:'+q.attack_color+'">'+q.attack_desc+'</strong>'+
            '<span style="color:var(--tx2);font-size:.73rem">'+q.time+'</span>'+
            (q.sid?'<span style="color:var(--tx3);font-size:.7rem;font-family:monospace">SID:'+q.sid+'</span>':'')+'</div>'+
          '<div class="qcard-badges">'+modeBadge(q.mode)+(q.restored?badge('b-done','✅ Restaurée'):badge('b-act','🔒 VLAN 666'))+(bl?badge('b-red','⛔ MAC Bloqué'):'')+'</div>'+
        '</div>'+
        '<div class="qcard-sig">'+(q.signature||'')+'</div>'+
        '<div class="port-bar">'+
          '<div class="port-bar-item"><span class="port-bar-label">⚔ Attaquant</span>'+
            '<span class="port-badge atk">'+(q.attacker_port&&q.attacker_port!=='N/A'?'GE '+q.attacker_port:'N/A')+'</span>'+
            (q.attacker_backup_port?'<span class="backup-badge">🔄 Backup GE&nbsp;'+q.attacker_backup_port+'</span>':'')+'</div>'+
          '<div style="color:var(--tx3);font-size:1.1rem;align-self:center">→</div>'+
          '<div class="port-bar-item"><span class="port-bar-label">'+(q.mode==='SERVER_LOCAL_ATTACK'||q.mode==='SERVER_EXTERNAL_ATTACK'?'🛡 Serveur':'🎯 Victime')+'</span>'+
            '<span class="port-badge '+(q.victim_port&&q.victim_port!=='N/A'?'vic':'na')+'">'+(q.victim_port&&q.victim_port!=='N/A'?'GE '+q.victim_port:'N/A')+'</span>'+
            (q.victim_backup_port?'<span class="backup-badge">🔄 Backup GE&nbsp;'+q.victim_backup_port+'</span>':'')+'</div>'+
          (bl?'<div class="port-bar-item" style="margin-left:auto"><span class="port-badge atk" style="font-size:.7rem">⛔ MAC '+(q.attacker_mac||'')+'</span></div>':'')+
        '</div>'+
        '<div class="machines">'+mcard('⚔ Attaquant','#dc2626',q.attacker_info,q.attacker_ip,q.attacker_port,true,bl)+mcard('🎯 Victime','#ea580c',q.victim_info,q.victim_ip,q.victim_port,false,false)+'</div>'+
        (!q.restored?'<div style="margin-top:10px;padding:9px 13px;background:var(--blue-l);border-radius:6px;border:1px solid var(--blue-b);font-size:.68rem;color:var(--blue);font-family:monospace">💡 Restaurer ou débloquer le MAC → onglets <strong>Restaurer Ports</strong> / <strong>MACs Bloqués</strong></div>':'')+
      '</div>';
    }).join('');
  }

  // ── Backup panel (page quarantaine) ──
  const panel=document.getElementById('backup-panel');
  const bgrid=document.getElementById('backup-grid');
  const bcnt =document.getElementById('backup-active-count');
  const bkeys=Object.keys(bmap);
  if(bkeys.length>0){
    panel.style.display='';
    const ac=Object.keys(bact).length;
    bcnt.textContent=ac>0?'— '+ac+' actif'+(ac>1?'s':''):'— tous en veille';
    bgrid.innerHTML=bkeys.sort((a,b)=>parseInt(a)-parseInt(b)).map(primary=>{
      const backupNum=bmap[primary];
      const backupPort='1/0/'+backupNum;
      const isOn=bact.hasOwnProperty(backupPort);
      return '<div class="bp-slot'+(isOn?' active':'')+'"><span class="bp-slot-label">1/0/'+primary+'</span><span class="bp-slot-port">GE&nbsp;'+backupPort+'</span><span class="bp-slot-status '+(isOn?'on':'off')+'">'+(isOn?'● ACTIF':'○ veille')+'</span></div>';
    }).join('');
  } else { panel.style.display='none'; }

  // ── Restaurer Ports ──
  const ra=document.getElementById('restore-active');
  const rd=document.getElementById('restore-done');
  if(active.length===0){
    ra.innerHTML='<div class="empty-state"><div class="es-icon">✅</div><div class="es-text">Aucun port à restaurer</div></div>';
  } else {
    ra.innerHTML=active.map(q=>{
      const hasAtk=q.attacker_port&&q.attacker_port!=='N/A';
      const hasVic=q.victim_port&&q.victim_port!=='N/A';
      let cards='';
      if(hasAtk) cards+='<div class="action-card card-atk">'+
        '<div class="ac-info">'+
          '<div class="ac-title">⚔ <strong>Attaquant</strong> '+badge('b-red','ISOLÉ VLAN 666')+(q.mac_blocked?badge('b-pur','MAC BLOQUÉ'):'')+'</div>'+
          '<div class="ac-sub"><span>🖥 IP : <strong>'+q.attacker_ip+'</strong></span><span>🔌 GE '+q.attacker_port+'</span>'+(q.attacker_backup_port?'<span>🔄 Backup : GE '+q.attacker_backup_port+'</span>':'')+'<span>🕐 '+q.time+'</span></div>'+
          '<div class="ac-sub" style="margin-top:3px"><span>🦠 '+q.attack_desc+'</span></div>'+
        '</div>'+
        '<div class="ac-btns">'+
          '<button class="btn btn-grn" onclick="restPort(&#39;'+q.attacker_port+'&#39;,&#39;'+q.id+'&#39;,&#39;attacker&#39;)">🔌 Restaurer Port</button>'+
          '<button class="btn btn-pur" onclick="unblockMacOnly(&#39;'+q.attacker_mac+'&#39;)">🔓 Débloquer MAC</button>'+
        '</div>'+
      '</div>';
      if(hasVic&&q.mode==='DUAL_QUARANTINE') cards+='<div class="action-card card-vic">'+
        '<div class="ac-info">'+
          '<div class="ac-title">🎯 <strong>Victime</strong> '+badge('b-ora','ISOLÉE VLAN 666')+'</div>'+
          '<div class="ac-sub"><span>🖥 IP : <strong>'+q.victim_ip+'</strong></span><span>🔌 GE '+q.victim_port+'</span>'+(q.victim_backup_port?'<span>🔄 Backup : GE '+q.victim_backup_port+'</span>':'')+'</div>'+
        '</div>'+
        '<div class="ac-btns">'+
          '<button class="btn btn-grn" onclick="restPort(&#39;'+q.victim_port+'&#39;,&#39;'+q.id+'&#39;,&#39;victim&#39;)">✅ Restaurer Victime</button>'+
          '<button class="btn btn-blue" onclick="restBoth(&#39;'+q.attacker_port+'&#39;,&#39;'+q.victim_port+'&#39;,&#39;'+q.attacker_mac+'&#39;,&#39;'+q.id+'&#39;)">✅ Restaurer Les Deux</button>'+
        '</div>'+
      '</div>';
      return cards;
    }).join('');
  }
  if(done.length===0){
    rd.innerHTML='<div class="empty-state" style="padding:20px"><div class="es-text">Aucune restauration dans l&#39;historique</div></div>';
  } else {
    rd.innerHTML='<div style="border-radius:8px;border:1px solid var(--border);overflow:hidden;background:var(--bg2)">'+done.slice().reverse().map(q=>
      '<div class="hist-row"><span style="font-size:.95rem">'+(q.attack_icon||'⚠️')+'</span>'+
      '<span style="font-weight:600;color:var(--tx)">'+q.attack_desc+'</span>'+
      '<span style="font-family:monospace;font-size:.68rem">⚔ GE '+(q.attacker_port||'N/A')+' &nbsp;→&nbsp; 🎯 GE '+(q.victim_port||'N/A')+'</span>'+
      '<span style="font-family:monospace;font-size:.66rem;color:var(--tx3)">'+q.time+'</span>'+
      badge('b-done','✅ Restaurée')+'</div>').join('')+'</div>';
  }

  // ── MACs Bloqués ──
  const ma=document.getElementById('macs-active');
  const mh=document.getElementById('macs-hist');
  const macs=d.mac_blacklist||[];
  if(macs.length===0){
    ma.innerHTML='<div class="empty-state"><div class="es-icon">🔓</div><div class="es-text">Aucun MAC bloqué actuellement</div></div>';
  } else {
    ma.innerHTML=macs.map(mac=>{
      const qe=(d.quarantined||[]).find(q=>q.attacker_mac&&q.attacker_mac.toLowerCase()===mac.toLowerCase());
      return '<div class="action-card card-mac">'+
        '<div class="ac-info">'+
          '<div class="ac-title">⛔ <strong style="font-family:monospace">'+mac+'</strong> '+badge('b-pur','BLOQUÉ VLANs 1,10,666')+'</div>'+
          '<div class="ac-sub">'+(qe?'<span>🖥 '+qe.attacker_ip+'</span><span>🔌 GE '+(qe.attacker_port||'N/A')+'</span><span>🦠 '+qe.attack_desc+'</span>':'<span>Blocage manuel</span>')+'</div>'+
        '</div>'+
        '<div class="ac-btns"><button class="btn btn-grn" onclick="unblockMacOnly(&#39;'+mac+'&#39;)">🔓 Débloquer</button></div>'+
      '</div>';
    }).join('');
  }
  const macHist=(d.quarantined||[]).filter(q=>q.attacker_mac);
  if(macHist.length===0){
    mh.innerHTML='<div class="empty-state" style="padding:20px"><div class="es-text">Aucun historique MAC</div></div>';
  } else {
    mh.innerHTML='<div style="border-radius:8px;border:1px solid var(--border);overflow:hidden;background:var(--bg2)">'+macHist.slice().reverse().map(q=>
      '<div class="hist-row '+(q.restored?'':'')+'">'+
      '<span style="font-family:monospace;font-weight:700;font-size:.76rem">'+(q.attacker_mac||'?')+'</span>'+
      '<span style="color:var(--tx2);font-size:.68rem">'+(q.attacker_ip||'?')+' — GE '+(q.attacker_port||'N/A')+'</span>'+
      '<span style="font-size:.68rem">'+q.attack_desc+'</span>'+
      '<span style="font-family:monospace;font-size:.64rem;color:var(--tx3)">'+q.time+'</span>'+
      (q.mac_blocked&&!q.restored?badge('b-red','⛔ Actif'):badge('b-done','✓ Libéré'))+'</div>').join('')+'</div>';
  }

  // ── Alertes ──
  document.getElementById('alerts-tb').innerHTML=(d.alerts||[]).map(a=>
    '<tr><td style="font-size:1rem">'+(a.attack_icon||'⚠️')+'</td>'+
    '<td style="font-family:monospace;font-size:.72rem">'+a.time+'</td>'+
    '<td style="color:var(--tx2);font-family:monospace;font-size:.7rem">'+(a.sid||'—')+'</td>'+
    '<td>'+a.ip_src+'</td><td>'+a.ip_dst+'</td>'+
    '<td style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:.72rem" title="'+a.alert+'">'+a.alert+'</td>'+
    '<td><span style="color:'+(a.severity>=2?'var(--red)':a.severity>=1?'var(--orange)':'var(--green)')+'">'+a.severity+'</span></td></tr>').join('');

  // ── Commandes switch ──
  const cl=document.getElementById('cmd-list');
  if(!d.switch_cmds||d.switch_cmds.length===0){
    cl.innerHTML='<p style="color:var(--tx2);padding:20px;text-align:center;">Aucune commande envoyée</p>';
  } else {
    cl.innerHTML=d.switch_cmds.map(c=>
      '<div class="cmd-block">'+
        '<div class="cmd-header">'+
          '<span><span class="cmd-port">Port '+(c.port||'—')+'</span></span>'+
          '<span class="cmd-reason">'+(c.reason||'')+'</span>'+
          '<span class="cmd-time">'+c.time+'</span>'+
        '</div>'+
        '<div class="cmd-body">'+(c.commands||[]).map(cmd=>'<div class="cmd-line">'+cmd+'</div>').join('')+'</div>'+
      '</div>').join('');
  }

  // ── Historique MAC ──
  document.getElementById('hist-tb').innerHTML=(d.mac_history||[]).map(m=>
    '<tr><td style="font-family:monospace;font-weight:700">'+m.mac+'</td>'+
    '<td style="font-family:monospace">'+m.port+'</td>'+
    '<td style="font-family:monospace;font-size:.7rem">'+m.first_seen+'</td>'+
    '<td style="font-family:monospace;font-size:.7rem">'+m.last_seen+'</td>'+
    '<td style="font-size:.7rem">'+(m.last_attack||'—')+'</td>'+
    '<td style="font-family:monospace;color:'+(m.violations>0?'var(--red)':'var(--tx)')+'">'+m.violations+'</td>'+
    '<td>'+(d.mac_blacklist||[]).includes(m.mac.toLowerCase())?badge('b-red','⛔ Bloqué'):badge('b-grn','✅ Libre')+'</td></tr>').join('');

  // ── Terminal ──
  document.getElementById('term').innerHTML=(d.logs||[]).map(l=>
    '<div class="log-line log-'+l.level+'"><span class="log-t">'+l.time+'</span><span class="log-m">'+l.message+'</span></div>').join('');
}

// ── API calls ────────────────────────────────────────────────────────
async function startMon(){await fetch('/api/start',{method:'POST'});location.reload();}
async function stopMon(){await fetch('/api/stop',{method:'POST'});location.reload();}
async function restPort(port,qid,role){
  if(!confirm('Restaurer port '+port+' → VLAN 1 ?'))return;
  const r=await fetch('/api/admin/restore_port',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({port,qid,role})});
  const d=await r.json();
  if(d.restored){refreshData();setTimeout(refreshData,3000);}
  else{alert('Erreur restauration — vérifiez les logs');}
}
async function restFull(port,mac,qid){
  if(!confirm('Restaurer port '+port+' + débloquer MAC '+mac+' ?'))return;
  const r=await fetch('/api/admin/restore_full',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({port,mac,qid})});
  const d=await r.json();
  if(d.restored){refreshData();setTimeout(refreshData,3000);}
  else{alert('Erreur restauration — vérifiez les logs');}
}
async function restBoth(ap,vp,am,qid){
  if(!confirm('Restaurer ATTAQUANT ('+ap+') + VICTIME ('+vp+') + débloquer '+am+' ?'))return;
  const r=await fetch('/api/admin/restore_both',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({attacker_port:ap,victim_port:vp,attacker_mac:am,qid})});
  const d=await r.json();
  if(d.restored){refreshData();setTimeout(refreshData,3000);}
  else{alert('Erreur restauration — vérifiez les logs');}
}
async function findPort(){
  const r=await fetch('/api/find_port?mac='+encodeURIComponent(document.getElementById('m-mac').value));
  document.getElementById('m-res').textContent=(await r.json()).result;
}
async function manualQuar(){
  const port=document.getElementById('m-port').value;
  if(!port||!confirm('Quarantaine port '+port+' → VLAN {{ config.vlan }} ?'))return;
  const r=await fetch('/api/admin/manual_quarantine',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({port,ip:document.getElementById('m-ip').value})});
  document.getElementById('m-res').textContent=(await r.json()).result;
  refreshData();
}
async function manualBlockMac(){
  const mac=document.getElementById('m-mac').value;
  if(!mac||!confirm('Bloquer MAC '+mac+' sur tous les ports ?'))return;
  const r=await fetch('/api/admin/block_mac',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mac})});
  document.getElementById('m-res').textContent=(await r.json()).result;
  refreshData();
}
async function manualRestore(){
  const port=document.getElementById('m-port').value;
  if(!port||!confirm('Restaurer port '+port+' → VLAN 1 ?'))return;
  await fetch('/api/admin/restore_port',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({port})});
  document.getElementById('m-res').textContent='Port '+port+' restauré → VLAN 1';
  refreshData();
}
async function manualUnblock(){
  const mac=document.getElementById('m-mac').value;
  if(!mac||!confirm('Débloquer MAC '+mac+' ?'))return;
  const r=await fetch('/api/admin/unblock_mac',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mac})});
  document.getElementById('m-res').textContent=(await r.json()).result;
  refreshData();
}
async function restoreAll(){
  if(!confirm('Restaurer TOUS les ports et débloquer TOUS les MACs bloqués ?'))return;
  const r=await fetch('/api/admin/restore_all',{method:'POST'});
  const d=await r.json();
  const msg='✅ Restauration globale effectuée\\n• Ports : '+(d.restored_ports||[]).join(', ')+'\\n• MACs : '+(d.unblocked_macs||[]).join(', ');
  alert(msg);
  refreshData();setTimeout(refreshData,4000);
}
async function unblockMacOnly(mac){
  if(!confirm('Débloquer le MAC '+mac+' sur tous les VLANs ?'))return;
  await fetch('/api/admin/unblock_mac',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mac})});
  refreshData();setTimeout(refreshData,3000);
}
async function scanMachine(){
  const ip=document.getElementById('m-ip').value;
  if(!ip){alert('Entrez une IP');return;}
  document.getElementById('m-res').textContent='Scan en cours (30-45s)...';
  const r=await fetch('/api/scan_machine',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip})});
  document.getElementById('m-res').textContent=JSON.stringify((await r.json()).info,null,2);
}
async function blockPing(){
  if(!confirm('Bloquer ICMP sur TOUS les ports ?'))return;
  await fetch('/api/block_ping',{method:'POST'});
  document.getElementById('m-res').textContent='Ping ICMP bloqué sur {{ config.port_count }} ports.';
}
async function saveConfig(){
  await fetch('/api/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({
    host:document.getElementById('c-host').value,
    username:document.getElementById('c-user').value,
    password:document.getElementById('c-pass').value,
    vlan:parseInt(document.getElementById('c-vlan').value),
    port_monitoring:document.getElementById('c-port').value,
    home_net:document.getElementById('c-home').value,
    protected_ips:document.getElementById('c-prot').value,
  })});
  alert('Configuration sauvegardée.');
  location.reload();
}
async function testConn(){
  const r=await fetch('/api/test');
  alert((await r.json()).result);
}

// ── Telegram ─────────────────────────────────────────────────────────
async function tgSetChat(){
  const cid=document.getElementById('tg-chat').value.trim();
  if(!cid){alert('Entrez un Chat ID');return;}
  await fetch('/api/telegram/set_chat_id',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({chat_id:cid})});
  document.getElementById('tg-res').textContent='✅ Chat ID défini : '+cid;
}
async function tgAutoDetect(){
  document.getElementById('tg-res').textContent='⏳ Détection en cours…';
  const r=await fetch('/api/telegram/auto_detect');
  const d=await r.json();
  if(d.status==='ok'){
    document.getElementById('tg-chat').value=d.chat_id;
    document.getElementById('tg-res').textContent='✅ Chat ID détecté : '+d.chat_id;
  } else {
    document.getElementById('tg-res').style.color='var(--red)';
    document.getElementById('tg-res').textContent='❌ '+d.message;
  }
}
async function tgTest(){
  document.getElementById('tg-res').textContent='⏳ Envoi du message test…';
  const r=await fetch('/api/telegram/test',{method:'POST'});
  const d=await r.json();
  document.getElementById('tg-res').style.color=d.status==='sent'?'var(--green)':'var(--red)';
  document.getElementById('tg-res').textContent=d.status==='sent'?'✅ Message envoyé sur chat '+d.chat_id:'❌ '+d.message;
}

// ── Machines connectées ──────────────────────────────────────────────
async function scanConnected(){
  const list=document.getElementById('dash-machines-list');
  const cnt =document.getElementById('dash-connected-count');
  list.innerHTML='<div style="color:var(--tx3);font-size:.72rem;text-align:center;padding:16px">⏳ Connexion au switch...</div>';
  cnt.textContent='...';
  try{
    const r=await fetch('/api/switch/connected_machines');
    const d=await r.json();
    cnt.textContent=d.count||0;
    if(!d.machines||d.machines.length===0){
      list.innerHTML='<div style="color:var(--tx3);font-size:.72rem;text-align:center;padding:16px">Aucune machine détectée</div>';
      return;
    }
    list.innerHTML=d.machines.map(m=>{
      const isQ=m.quarantined;
      const isBl=m.blocked;
      const hn=m.hostname&&m.hostname!=='—'?'<span class="mr-hostname" style="color:var(--tx2);font-size:.62rem;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+m.hostname+'">'+m.hostname+'</span>':'';
      return '<div class="machine-row'+(isQ?' quar':isBl?' blocked':'')+'">'+
        '<span class="mr-port'+(isQ?' quar':'')+'">GE '+m.port+'</span>'+
        '<span class="mr-ip" style="font-weight:600;min-width:100px">'+(m.ip||'—')+'</span>'+
        hn+
        '<span class="mr-mac" style="font-family:monospace;font-size:.6rem;color:var(--tx3)">'+m.mac+'</span>'+
        '<span class="mr-vlan">VLAN '+m.vlan+'</span>'+
        (isQ?'<span class="mr-badge" style="background:var(--red-l);color:var(--red);border:1px solid var(--red-b)">🔒 ISOLÉ</span>':'')+
        (isBl?'<span class="mr-badge" style="background:var(--purple-l);color:var(--purple);border:1px solid var(--purple-b)">⛔ BLOQUÉ</span>':'')+
        '<div class="mr-actions">'+
          '<button class="btn btn-sm btn-red" style="padding:3px 7px;font-size:.58rem" onclick="quickQuar(&#39;'+m.port+'&#39;,&#39;'+m.ip+'&#39;)" title="Mettre en quarantaine">🔒</button>'+
          '<button class="btn btn-sm btn-blue" style="padding:3px 7px;font-size:.58rem" onclick="document.getElementById(&#39;sw-port&#39;).value=&#39;'+m.port+'&#39;;showPage(&#39;switch&#39;)" title="Contr&#244;ler ce port">⚙</button>'+
        '</div>'+
      '</div>';
    }).join('');
  }catch(e){
    list.innerHTML='<div style="color:var(--red);font-size:.72rem;padding:16px">Erreur: '+e+'</div>';
    cnt.textContent='!';
  }
}
async function quickQuar(port,ip){
  if(!confirm('Mettre en quarantaine le port GE '+port+' ('+ip+') → VLAN {{ config.vlan }} ?'))return;
  const r=await fetch('/api/admin/manual_quarantine',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({port,ip})});
  await r.json();
  refreshData();
  scanConnected();
}

// ── Switch Control ────────────────────────────────────────────────────
function swPort(){return document.getElementById('sw-port').value.trim();}
function swVlan(){return document.getElementById('sw-vlan').value.trim();}
function swOut(title,txt){
  document.getElementById('sw-out-title').textContent='📟 '+title;
  document.getElementById('sw-output').textContent=txt;
}
async function swGet(url,label){
  swOut(label+' — chargement...','⏳ Connexion au switch...');
  try{
    const r=await fetch(url);
    const d=await r.json();
    swOut(label,d.result||d.status||JSON.stringify(d));
  }catch(e){swOut(label,'ERREUR: '+e);}
}
async function swPost(url,body,label){
  swOut(label+' — envoi...','⏳ Envoi commande...');
  try{
    const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const d=await r.json();
    swOut(label,d.result||d.status||JSON.stringify(d));
    refreshData();
  }catch(e){swOut(label,'ERREUR: '+e);}
}
async function swCall(url,body,label){
  if(!body||Object.keys(body).length===0){
    await swGet(url,label);
  } else {
    await swPost(url,body,label);
  }
}
async function swCustomCmd(){
  const cmd=document.getElementById('sw-target').value.trim();
  if(!cmd){alert('Entrez une commande dans le champ "IP cible / Commande"');return;}
  await swPost('/api/switch/cmd/custom',{command:cmd},'Commande: '+cmd);
}

// ── Alarme sonore ────────────────────────────────────────────────────
let _audioCtx=null, _alarmActive=false, _alarmTimer=null, _lastAlertCount=0;
function _initAudio(){
  if(_audioCtx)return;
  try{_audioCtx=new(window.AudioContext||window.webkitAudioContext)();}catch(e){}
}
async function _resumeCtx(){
  if(_audioCtx&&_audioCtx.state==='suspended') await _audioCtx.resume();
}
document.addEventListener('click',function(){_initAudio();_resumeCtx();},{once:true});
function _beepOnce(){
  if(!_audioCtx||!_alarmActive)return;
  const osc=_audioCtx.createOscillator();
  const gain=_audioCtx.createGain();
  osc.connect(gain); gain.connect(_audioCtx.destination);
  osc.type='square';
  osc.frequency.setValueAtTime(1320,_audioCtx.currentTime);
  osc.frequency.exponentialRampToValueAtTime(660,_audioCtx.currentTime+0.15);
  gain.gain.setValueAtTime(0.35,_audioCtx.currentTime);
  gain.gain.exponentialRampToValueAtTime(0.001,_audioCtx.currentTime+0.45);
  osc.start(_audioCtx.currentTime);
  osc.stop(_audioCtx.currentTime+0.45);
  _alarmTimer=setTimeout(_beepOnce,900);
}
function startAlarm(){
  if(_alarmActive)return;
  _initAudio();
  _alarmActive=true;
  document.getElementById('btn-sound').style.display='';
  _beepOnce();
}
function stopAlarm(){
  _alarmActive=false;
  if(_alarmTimer){clearTimeout(_alarmTimer);_alarmTimer=null;}
  document.getElementById('btn-sound').style.display='none';
}
async function testAlarm(){
  _initAudio();
  await _resumeCtx();
  _alarmActive=false;
  startAlarm();
  setTimeout(stopAlarm,3000);
}

// ── Charts Chart.js PREMIUM ──────────────────────────────────────────
let _chartTypes=null,_chartTimeline=null,_chartTop=null;
const CHART_COLORS={
  PING_SCAN:'#00d4aa',DDOS_FLOOD:'#ef4444',NETWORK_SCAN:'#f97316',
  BRUTE_FORCE:'#a855f7',C2_MALWARE:'#8b5cf6',RANSOMWARE:'#06b6d4',UNKNOWN:'#6b7280'
};
const CHART_LABELS={
  PING_SCAN:'Ping/ICMP',DDOS_FLOOD:'DDoS',NETWORK_SCAN:'Scan',
  BRUTE_FORCE:'Brute Force',C2_MALWARE:'C2/Malware',RANSOMWARE:'Ransomware',UNKNOWN:'Autre'
};
function _mkGrad(ctx,c1,c2){
  const g=ctx.createLinearGradient(0,0,0,ctx.canvas.height);
  g.addColorStop(0,c1); g.addColorStop(1,c2); return g;
}
function _initCharts(){
  if(!window.Chart) return;
  Chart.defaults.font.family='JetBrains Mono,monospace';
  const grid={color:'rgba(148,163,184,.07)',drawBorder:false};
  const tick={color:'#475569',font:{size:9}};

  // ── Donut ──
  const ctxT=document.getElementById('chart-types');
  if(ctxT&&!_chartTypes){
    _chartTypes=new Chart(ctxT,{
      type:'doughnut',
      data:{labels:[],datasets:[{data:[],backgroundColor:[],borderWidth:0,hoverOffset:8,borderRadius:4}]},
      options:{responsive:true,maintainAspectRatio:false,cutout:'72%',
        animation:{animateRotate:true,duration:800},
        plugins:{legend:{display:false},tooltip:{
          callbacks:{label:c=>' '+c.label+' : '+c.raw+' alertes'},
          backgroundColor:'#1e293b',borderColor:'#334155',borderWidth:1,
          titleColor:'#94a3b8',bodyColor:'#f1f5f9',padding:10,cornerRadius:8
        }}}
    });
  }

  // ── Line timeline ──
  const ctxL=document.getElementById('chart-timeline');
  if(ctxL&&!_chartTimeline){
    const grad=_mkGrad(ctxL.getContext('2d'),'rgba(59,130,246,.35)','rgba(59,130,246,.02)');
    _chartTimeline=new Chart(ctxL,{
      type:'line',
      data:{labels:[],datasets:[{label:'Alertes',data:[],
        backgroundColor:grad,borderColor:'#3b82f6',borderWidth:2,
        pointBackgroundColor:'#3b82f6',pointRadius:3,pointHoverRadius:6,
        fill:true,tension:.4}]},
      options:{responsive:true,maintainAspectRatio:false,
        scales:{x:{ticks:{...tick,maxRotation:0},grid},
                y:{ticks:{...tick,stepSize:1},grid,beginAtZero:true}},
        plugins:{legend:{display:false},tooltip:{
          backgroundColor:'#1e293b',borderColor:'#334155',borderWidth:1,
          titleColor:'#94a3b8',bodyColor:'#f1f5f9',padding:10,cornerRadius:8
        }}}
    });
  }

  // ── Barres horizontales ──
  const ctxB=document.getElementById('chart-top');
  if(ctxB&&!_chartTop){
    _chartTop=new Chart(ctxB,{
      type:'bar',
      data:{labels:[],datasets:[{data:[],
        backgroundColor:Object.values(CHART_COLORS).map(c=>c+'bb'),
        borderColor:Object.values(CHART_COLORS),
        borderWidth:1,borderRadius:4,borderSkipped:false}]},
      options:{indexAxis:'y',responsive:true,maintainAspectRatio:false,
        scales:{x:{ticks:{...tick,stepSize:1},grid,beginAtZero:true},
                y:{ticks:{...tick},grid:{display:false}}},
        plugins:{legend:{display:false},tooltip:{
          backgroundColor:'#1e293b',borderColor:'#334155',borderWidth:1,
          titleColor:'#94a3b8',bodyColor:'#f1f5f9',padding:10,cornerRadius:8
        }}}
    });
  }
}

function _ind(id,label,value,color){
  const el=document.getElementById(id);
  if(!el) return;
  el.innerHTML=
    '<div style="background:#f1f5f9;border-radius:10px;padding:12px 14px;border:1px solid rgba(0,0,0,.08);border-left:3px solid '+color+'">'+
    '<div style="color:#000000;font-size:.55rem;text-transform:uppercase;letter-spacing:1.5px;font-family:monospace">'+label+'</div>'+
    '<div style="color:'+color+';font-size:1.5rem;font-weight:700;font-family:monospace;line-height:1.2;margin-top:4px">'+value+'</div>'+
    '</div>';
}

function _updateCharts(alerts,quarantined,stats){
  if(!window.Chart) return;
  _initCharts();

  const tc={};
  (alerts||[]).forEach(a=>{const t=a.attack_type||'UNKNOWN';tc[t]=(tc[t]||0)+1;});
  const labels=Object.keys(tc);
  const total=labels.reduce((s,l)=>s+tc[l],0);

  // Donut
  if(_chartTypes){
    _chartTypes.data.labels=labels.map(l=>CHART_LABELS[l]||l);
    _chartTypes.data.datasets[0].data=labels.map(l=>tc[l]);
    _chartTypes.data.datasets[0].backgroundColor=labels.map(l=>CHART_COLORS[l]||'#6b7280');
    _chartTypes.update('none');
  }
  document.getElementById('donut-total').textContent=total||'0';

  // Légende custom
  const leg=document.getElementById('chart-legend');
  if(leg) leg.innerHTML=labels.map(l=>
    '<div style="display:flex;justify-content:space-between;align-items:center;padding:3px 0;font-size:.62rem">'+
    '<div style="display:flex;align-items:center;gap:5px"><div style="width:8px;height:8px;border-radius:2px;background:'+(CHART_COLORS[l]||'#6b7280')+'"></div>'+
    '<span style="color:#000000">'+(CHART_LABELS[l]||l)+'</span></div>'+
    '<span style="color:#f1f5f9;font-weight:700">'+tc[l]+'</span></div>'
  ).join('');

  // Line timeline
  const recent=(alerts||[]).slice(0,24).reverse();
  const bk={};
  recent.forEach(a=>{
    const h=(a.time||'').substring(11,13);
    const m=String(Math.floor(parseInt((a.time||'00:00').substring(14,16))/5)*5).padStart(2,'0');
    const t=h+'h'+m;
    bk[t]=(bk[t]||0)+1;
  });
  const bkeys=Object.keys(bk).sort();
  if(_chartTimeline){
    _chartTimeline.data.labels=bkeys.length?bkeys:['—'];
    _chartTimeline.data.datasets[0].data=bkeys.length?bkeys.map(k=>bk[k]):[0];
    _chartTimeline.update('none');
  }

  // Top menaces bar
  const sorted=labels.slice().sort((a,b)=>tc[b]-tc[a]).slice(0,6);
  if(_chartTop){
    _chartTop.data.labels=sorted.map(l=>CHART_LABELS[l]||l);
    _chartTop.data.datasets[0].data=sorted.map(l=>tc[l]);
    _chartTop.data.datasets[0].backgroundColor=sorted.map(l=>(CHART_COLORS[l]||'#6b7280')+'99');
    _chartTop.data.datasets[0].borderColor=sorted.map(l=>CHART_COLORS[l]||'#6b7280');
    _chartTop.update('none');
  }

  // Indicateurs bas
  const active=(quarantined||[]).filter(q=>!q.restored).length;
  const maxSev=Math.max(0,...(alerts||[]).map(a=>a.severity||0));
  _ind('ind-total', 'Total alertes',  total,    '#ef4444');
  _ind('ind-active','Actives VLAN666',active,   '#f97316');
  _ind('ind-mac',   'MACs bloqués',   (stats&&stats.blocked)||0, '#a855f7');
  _ind('ind-sev',   'Sévérité max',   maxSev||'—', '#0891b2');
}

setInterval(refreshData,2500);
// Scan machines connectées : au démarrage puis toutes les 30s
refreshData();
scanConnected();
setInterval(scanConnected,30000);
</script>
</body>
</html>
'''

# ---------------------------------------------------------------------------
# FLASK
# ---------------------------------------------------------------------------
app = Flask(__name__)


@app.route('/')
def index():
    stats  = {
        'alerts':     len(alerts_list),
        'quarantine': sum(1 for q in quarantined_list if not q.get('restored')),
        'blocked':    len(mac_blacklist),
        'history':    len(mac_history),
    }
    config = {
        'host': SWITCH_PARAMS['host'], 'username': SWITCH_PARAMS['username'],
        'password': SWITCH_PARAMS['password'], 'vlan': VLAN_QUARANTAINE,
        'port_monitoring': PORT_MONITORING, 'home_net': HOME_NET,
        'port_count': SWITCH_PORT_COUNT,
        'protected_ips': ', '.join(sorted(PROTECTED_IPS)),
        'delay': QUARANTINE_DELAY_SEC,
        'trusted_vlans': TRUSTED_VLANS,
        'vlan_normal': VLAN_NORMAL,
        'telegram_chat_id': TELEGRAM_CHAT_ID,
    }
    return render_template_string(HTML_TEMPLATE, monitoring=monitoring_active,
                                  stats=stats, config=config)


@app.route('/api/status')
def api_status():
    return jsonify({
        'monitoring':    monitoring_active,
        'stats': {
            'alerts':     len(alerts_list),
            'quarantine': sum(1 for q in quarantined_list if not q.get('restored')),
            'blocked':    len(mac_blacklist),
            'history':    len(mac_history),
        },
        'alerts':        alerts_list[:50],
        'quarantined':   quarantined_list[:100],
        'mac_history':   [{'mac': m, **info} for m, info in mac_history.items()],
        'mac_blacklist': list(mac_blacklist),
        'alert_count':   len(alerts_list),
        'switch_cmds':        switch_cmd_log[:50],
        'logs':               logs_list[:60],
        'delay':              QUARANTINE_DELAY_SEC,
        'backup_ports_active': backup_ports_active,
        'backup_map':          PORT_BACKUP_MAP,
        'suspects':           {
            ip: {**s, 'first_ts': s['first_ts'], 'last_ts': s['last_ts']}
            for ip, s in _suspects.items()
            if time.time() - s['last_ts'] < ALERT_WINDOW_SEC
        },
        'alert_threshold':    ALERT_THRESHOLD,
        'alert_window':       ALERT_WINDOW_SEC,
    })


@app.route('/api/start', methods=['POST'])
def api_start():
    global monitoring_active
    if not os.path.exists(SURICATA_LOG):
        add_log(f"[!] {SURICATA_LOG} introuvable", "error")
        return jsonify({'error': 'log not found'})
    monitoring_active = True
    _persist_state()
    add_log("[INFO] Surveillance démarrée — quarantaine automatique VLAN 666", "success")
    threading.Thread(target=monitor_loop,        daemon=True).start()
    threading.Thread(target=mac_watchdog_loop,   daemon=True).start()
    threading.Thread(target=sw_table_cache_loop, daemon=True).start()
    # Déploiement automatique de l'agent sur tous les PCs connectés
    threading.Thread(target=deploy_agent_all,    daemon=True).start()
    return jsonify({'status': 'started'})


@app.route('/api/stop', methods=['POST'])
def api_stop():
    global monitoring_active
    monitoring_active = False
    _persist_state()
    add_log("[INFO] Surveillance arrêtée", "warning")
    return jsonify({'status': 'stopped'})


# ---------------------------------------------------------------------------
# RESTAURATION — ADMIN SEULEMENT
# ---------------------------------------------------------------------------

@app.route('/api/admin/restore_port', methods=['POST'])
def api_restore_port():
    """Restaure UN port en VLAN 1 (victime ou attaquant sans déblocage MAC)."""
    data = request.json
    port = data.get('port')
    qid  = data.get('qid', '')
    role = data.get('role', '')

    # Récupérer le MAC avant de marquer restauré
    attacker_mac = None
    if qid and role == 'attacker':
        with _lock:
            q = next((q for q in quarantined_list if q.get('id') == qid), None)
            if q:
                attacker_mac = q.get('attacker_mac', '')

    # Marquer restauré en mémoire IMMÉDIATEMENT (décision admin irréversible)
    if qid and role:
        _mark_restored(qid, role)

    # Retirer le MAC de la blacklist mémoire immédiatement pour bloquer le watchdog
    if attacker_mac and attacker_mac not in ('N/A', ''):
        with _lock:
            mac_blacklist.discard(_norm_mac(attacker_mac))

    add_log(f"[ADMIN] Restauration port {port} ({role}) → VLAN 1 (mémoire OK)", "info")

    def task():
        global _admin_op_pending
        _admin_op_pending = True  # suspend cache/watchdog pour libérer le sémaphore
        time.sleep(0.5)           # laisse les opérations en cours terminer
        try:
            for attempt in range(3):
                nc = None
                try:
                    nc = _connect()
                    do_restore_port(nc, port)
                    if attacker_mac and attacker_mac not in ('N/A', ''):
                        do_unblock_mac(attacker_mac, nc)
                    _save(nc)
                    nc.disconnect(); nc = None
                    add_log(f"[SUCCESS] Port {port} restauré en VLAN 1 (switch OK)", "success")
                    return
                except Exception as e:
                    if nc:
                        try: nc.disconnect()
                        except: pass
                    if attempt < 2:
                        add_log(f"[RETRY {attempt+1}/3] Restauration port {port}: {e}", "warning")
                        time.sleep(2)
                    else:
                        add_log(f"[!] Switch injoignable — port {port} restauré en mémoire uniquement", "warning")
        finally:
            _admin_op_pending = False

    threading.Thread(target=task, daemon=True).start()
    return jsonify({'status': 'ok', 'restored': True})


@app.route('/api/admin/restore_full', methods=['POST'])
def api_restore_full():
    """Restaure un port ET débloque le MAC de l'attaquant."""
    data = request.json
    port = data.get('port')
    mac  = data.get('mac', '')
    qid  = data.get('qid', '')

    # Marquer restauré en mémoire IMMÉDIATEMENT
    _mark_restored(qid, 'attacker')
    if mac and mac != 'N/A':
        with _lock:
            mac_blacklist.discard(_norm_mac(mac))
    add_log(f"[ADMIN] Restauration complète — port {port} + déblocage MAC {mac} (mémoire OK)", "info")

    def task():
        global _admin_op_pending
        _admin_op_pending = True
        time.sleep(0.5)
        attacker_ip = next((q.get('attacker_ip') for q in quarantined_list if q.get('id') == qid), None)
        try:
            for attempt in range(3):
                nc = None
                try:
                    nc = _connect()
                    if port and port != 'N/A':
                        do_restore_port(nc, port)
                    if mac and mac != 'N/A':
                        do_unblock_mac(mac, nc)
                    if attacker_ip and attacker_ip != 'N/A':
                        do_unblock_ip(nc, attacker_ip)
                    _save(nc)
                    nc.disconnect(); nc = None
                    add_log(f"[SUCCESS] Port {port} restauré + MAC {mac} débloqué (switch OK)", "success")
                    return
                except Exception as e:
                    if nc:
                        try: nc.disconnect()
                        except: pass
                    if attempt < 2:
                        add_log(f"[RETRY {attempt+1}/3] Restauration complète: {e}", "warning")
                        time.sleep(2)
                    else:
                        add_log(f"[!] Switch injoignable — restauration appliquée en mémoire uniquement", "warning")
        finally:
            _admin_op_pending = False

    threading.Thread(target=task, daemon=True).start()
    return jsonify({'status': 'ok', 'restored': True})


@app.route('/api/admin/restore_both', methods=['POST'])
def api_restore_both():
    """Restaure les deux ports (attaquant + victime) et débloque le MAC attaquant."""
    data          = request.json
    attacker_port = data.get('attacker_port')
    victim_port   = data.get('victim_port')
    attacker_mac  = data.get('attacker_mac', '')
    qid           = data.get('qid', '')

    # Marquer restauré en mémoire IMMÉDIATEMENT
    with _lock:
        for q in quarantined_list:
            if q.get('id') == qid:
                q['restored'] = True
                q['status']   = 'RESTAURÉE'
                q['attacker_port_restored'] = True
                q['victim_port_restored']   = True
                q['mac_blocked'] = False
                break
    if attacker_mac and attacker_mac != 'N/A':
        with _lock:
            mac_blacklist.discard(_norm_mac(attacker_mac))
    add_log(f"[ADMIN] Restauration DUALE — ports {attacker_port}/{victim_port} + MAC {attacker_mac} (mémoire OK)", "info")

    def task():
        global _admin_op_pending
        _admin_op_pending = True
        time.sleep(0.5)
        nc = None
        try:
            nc = _connect()
            for p in filter(lambda p: p and p != 'N/A', [attacker_port, victim_port]):
                do_restore_port(nc, p)
                add_log(f"[RESTORE] Port {p} → VLAN 1", "success")
            if attacker_mac and attacker_mac != 'N/A':
                do_unblock_mac(attacker_mac, nc)
                attacker_ip_q = next((q.get('attacker_ip') for q in quarantined_list if q.get('id') == qid), None)
                if attacker_ip_q and attacker_ip_q != 'N/A':
                    do_unblock_ip(nc, attacker_ip_q)
            _save(nc)
            nc.disconnect(); nc = None
            add_log(f"[SUCCESS] Restauration duale effectuée — switch mis à jour", "success")
        except Exception as e:
            add_log(f"[!] Switch injoignable ({e}) — restauration duale en mémoire uniquement", "warning")
        finally:
            if nc:
                try: nc.disconnect()
                except: pass
            _admin_op_pending = False

    threading.Thread(target=task, daemon=True).start()
    return jsonify({'status': 'ok', 'restored': True})


@app.route('/api/admin/restore_all', methods=['POST'])
def api_restore_all():
    """Restaure TOUS les ports et débloque TOUS les MACs bloqués — reset complet."""
    with _lock:
        all_macs   = list(mac_blacklist)
        all_ports  = []
        for q in quarantined_list:
            if not q.get('restored', False):
                for pk in ('attacker_port', 'victim_port'):
                    p = q.get(pk)
                    if p and p != 'N/A' and p not in all_ports:
                        all_ports.append(p)

        # Marquer tout comme restauré en mémoire immédiatement
        mac_blacklist.clear()
        for q in quarantined_list:
            q['restored']               = True
            q['status']                 = 'RESTAURÉE'
            q['attacker_port_restored'] = True
            q['victim_port_restored']   = True
            q['mac_blocked']            = False

    add_log(f"[ADMIN] Restauration GLOBALE — {len(all_ports)} ports, {len(all_macs)} MACs (mémoire OK)", "success")

    def task():
        global _admin_op_pending
        _admin_op_pending = True
        time.sleep(0.5)
        nc = None
        try:
            nc = _connect()
            for port in all_ports:
                try:
                    do_restore_port(nc, port)
                    add_log(f"[RESTORE-ALL] Port {port} → VLAN 1", "success")
                except Exception as ep:
                    add_log(f"[!] Erreur restore port {port}: {ep}", "warning")
            for mac in all_macs:
                try:
                    do_unblock_mac(mac, nc)
                except Exception as em:
                    add_log(f"[!] Erreur unblock MAC {mac}: {em}", "warning")
            _save(nc)
            nc.disconnect(); nc = None
            add_log(f"[SUCCESS] Restauration globale — switch mis à jour", "success")
        except Exception as e:
            add_log(f"[!] Switch injoignable ({e}) — restauration globale en mémoire uniquement", "warning")
        finally:
            if nc:
                try: nc.disconnect()
                except: pass
            _admin_op_pending = False

    threading.Thread(target=task, daemon=True).start()
    return jsonify({'status': 'ok', 'restored_ports': all_ports, 'unblocked_macs': all_macs})


def _mark_restored(qid, role):
    restored_ip = None
    with _lock:
        for q in quarantined_list:
            if q.get('id') == qid:
                if role == 'victim':
                    q['victim_port_restored'] = True
                    restored_ip = q.get('victim_ip')
                elif role == 'attacker':
                    q['attacker_port_restored'] = True
                    q['mac_blocked'] = False
                    restored_ip = q.get('attacker_ip')

                # Un port est "done" s'il a été restauré OU s'il n'était pas isolé (N/A)
                atk_port = q.get('attacker_port', 'N/A')
                vic_port  = q.get('victim_port',   'N/A')
                atk_done  = q.get('attacker_port_restored', False) or not atk_port or atk_port == 'N/A'
                vic_done  = q.get('victim_port_restored',  False) or not vic_port  or vic_port  == 'N/A'

                if atk_done and vic_done:
                    q['restored'] = True
                    q['status']   = 'RESTAURÉE'
                elif role not in ('victim', 'attacker'):
                    q['restored'] = True
                    q['status']   = 'RESTAURÉE'
                break

    # Notifier l'agent que l'écran rouge peut disparaître
    if restored_ip and restored_ip != 'N/A':
        threading.Thread(target=_notify_agent_release,
                         args=(restored_ip,), daemon=True).start()


# ---------------------------------------------------------------------------
# ACTIONS MANUELLES ADMIN
# ---------------------------------------------------------------------------

@app.route('/api/admin/manual_quarantine', methods=['POST'])
def api_manual_quarantine():
    data = request.json
    port = data.get('port')
    ip   = data.get('ip', '')
    nc   = None
    try:
        add_log(f"[ADMIN MANUEL] Quarantaine port {port} ({ip})", "warning")
        do_quarantine_port(port)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        quarantined_list.insert(0, {
            'id': timestamp + '_manual_' + port,
            'time': timestamp, 'mode': 'MANUAL',
            'attack_type': 'MANUAL', 'attack_icon': '🔒',
            'attack_color': '#888', 'attack_desc': 'Action Manuelle Admin',
            'signature': 'Quarantaine manuelle', 'sid': None, 'severity': 0,
            'attacker_ip': ip, 'attacker_mac': 'N/A', 'attacker_port': port,
            'attacker_info': {}, 'mac_blocked': False,
            'victim_ip': 'N/A', 'victim_mac': 'N/A', 'victim_port': 'N/A',
            'victim_info': {}, 'status': 'QUARANTAINE ACTIVE', 'restored': False,
        })
        add_log(f"[SUCCESS] Port {port} en quarantaine VLAN {VLAN_QUARANTAINE}", "success")
        return jsonify({'result': f'Port {port} mis en quarantaine VLAN {VLAN_QUARANTAINE}'})
    except Exception as e:
        add_log(f"[!] Erreur quarantaine manuelle: {e}", "error")
        return jsonify({'result': f'Erreur: {e}'})
    finally:
        if nc:
            try: nc.disconnect()
            except: pass


@app.route('/api/admin/block_mac', methods=['POST'])
def api_block_mac():
    mac = request.json.get('mac', '')
    do_block_mac(mac)
    return jsonify({'result': f'MAC {mac} bloqué sur VLAN {VLAN_QUARANTAINE}'})


@app.route('/api/admin/unblock_mac', methods=['POST'])
def api_unblock_mac():
    mac = request.json.get('mac', '')
    try:
        do_unblock_mac(mac)
        normalized = _norm_mac(mac)
        if normalized not in mac_blacklist:
            return jsonify({'result': f'✅ MAC {mac} débloqué avec succès', 'ok': True})
        return jsonify({'result': f'⚠️ MAC {mac} : commande envoyée mais vérifiez les logs', 'ok': False})
    except Exception as e:
        return jsonify({'result': f'❌ Erreur déblocage MAC {mac} : {e}', 'ok': False})


@app.route('/api/block_ping', methods=['POST'])
def api_block_ping():
    def task():
        nc = None
        try:
            add_log("[ACTION] Blocage ICMP sur tout le switch...", "info")
            nc = _connect()
            nc.send_config_set([
                'ip access-list extended BLOCK_PING',
                'deny icmp any any echo', 'deny icmp any any echo-reply',
                'permit ip any any', 'exit',
            ])
            for i in range(1, SWITCH_PORT_COUNT + 1):
                pid = f'1/0/{i}'
                if pid not in PROTECTED_PORTS:
                    try:
                        nc.send_config_set([f'interface gigabitEthernet {pid}',
                                            'ip access-group BLOCK_PING in', 'exit'])
                    except Exception:
                        pass
            _save(nc)
            nc.disconnect(); nc = None
            add_log(f"[SUCCESS] ICMP bloqué sur {SWITCH_PORT_COUNT} ports", "success")
        except Exception as e:
            add_log(f"[!] Erreur blocage ping: {e}", "error")
        finally:
            if nc:
                try: nc.disconnect()
                except: pass
    threading.Thread(target=task, daemon=True).start()
    return jsonify({'status': 'done'})


@app.route('/api/find_port')
def api_find_port():
    mac = request.args.get('mac', '')
    try:
        nc = _connect()
        out = nc.send_command("show mac address-table")
        nc.disconnect()
        for line in out.splitlines():
            if mac.lower() in line.lower():
                return jsonify({'result': line})
        return jsonify({'result': f'MAC {mac} non trouvée'})
    except Exception as e:
        return jsonify({'result': f'Erreur: {e}'})


@app.route('/api/scan_machine', methods=['POST'])
def api_scan_machine():
    ip = request.json.get('ip')
    machine_info_cache.pop(ip, None)
    info = scan_machine_info(ip)
    return jsonify({'status': 'done', 'info': info})


@app.route('/api/telegram/set_chat_id', methods=['POST'])
def api_tg_set_chat():
    global TELEGRAM_CHAT_ID
    cid = request.json.get('chat_id', '').strip()
    TELEGRAM_CHAT_ID = cid
    _persist_state()
    add_log(f"[TELEGRAM] Chat ID défini manuellement : {cid}", "success")
    return jsonify({'status': 'ok', 'chat_id': cid})


@app.route('/api/telegram/auto_detect')
def api_tg_auto_detect():
    cid = telegram_auto_detect_chat()
    if cid:
        return jsonify({'status': 'ok', 'chat_id': cid})
    return jsonify({'status': 'error', 'message': 'Aucun message reçu — envoyez /start au bot @sdnquarantaine_bot puis réessayez'})


@app.route('/api/telegram/test', methods=['POST'])
def api_tg_test():
    send_telegram(
        "✅ <b>Test NetShield SDN</b>\n\nLe bot Telegram est correctement configuré.\n"
        f"Switch : <code>{SWITCH_PARAMS['host']}</code> | VLAN : <code>{VLAN_QUARANTAINE}</code>"
    )
    if TELEGRAM_CHAT_ID:
        return jsonify({'status': 'sent', 'chat_id': TELEGRAM_CHAT_ID})
    return jsonify({'status': 'error', 'message': 'chat_id non configuré'})


@app.route('/api/config', methods=['POST'])
def api_config():
    global SWITCH_PARAMS, VLAN_QUARANTAINE, PORT_MONITORING, HOME_NET, PROTECTED_IPS
    d = request.json
    SWITCH_PARAMS['host']     = d.get('host',            SWITCH_PARAMS['host'])
    SWITCH_PARAMS['username'] = d.get('username',        SWITCH_PARAMS['username'])
    SWITCH_PARAMS['password'] = d.get('password',        SWITCH_PARAMS['password'])
    VLAN_QUARANTAINE          = int(d.get('vlan',        VLAN_QUARANTAINE))
    PORT_MONITORING           = d.get('port_monitoring', PORT_MONITORING)
    HOME_NET                  = d.get('home_net',        HOME_NET)
    if d.get('protected_ips'):
        PROTECTED_IPS = {ip.strip() for ip in d['protected_ips'].split(',') if ip.strip()}
        # Toujours garder le switch lui-même et localhost
        PROTECTED_IPS.add(SWITCH_PARAMS['host'])
        PROTECTED_IPS.add('127.0.0.1')
    add_log(f"[SUCCESS] Configuration mise à jour — IPs protégées : {PROTECTED_IPS}", "success")
    return jsonify({'status': 'saved'})


@app.route('/api/test')
def api_test():
    try:
        nc  = _connect()
        ver = nc.send_command("show version")
        nc.disconnect()
        return jsonify({'result': f'Connexion OK !\n{ver[:400]}'})
    except Exception as e:
        return jsonify({'result': f'Connexion échouée : {e}'})


# ---------------------------------------------------------------------------
# COMMANDES SWITCH — ROUTES ÉTENDUES
# ---------------------------------------------------------------------------

def _sw_show(cmd):
    """Exécute une commande show et retourne l'output."""
    try:
        nc = _connect()
        out = nc.send_command_timing(cmd, delay_factor=2)
        nc.disconnect()
        return out or '(vide)'
    except Exception as e:
        add_log(f"[!] Erreur show '{cmd}': {e}", "error")
        return f"ERREUR: {e}"

def _sw_cfg(cmds):
    """Exécute des commandes de configuration et sauvegarde."""
    if isinstance(cmds, str):
        cmds = [cmds]
    try:
        nc = _connect()
        nc.send_config_set(cmds)
        _save(nc)
        nc.disconnect()
        log_switch_cmd('SWITCH', cmds, 'COMMANDE MANUELLE')
        return 'OK — commandes envoyées'
    except Exception as e:
        add_log(f"[!] Erreur config switch: {e}", "error")
        return f"ERREUR: {e}"

@app.route('/api/switch/connected_machines')
def sw_connected_machines():
    """Retourne toutes les machines connectées au switch avec leur port et IP."""
    try:
        nc = _connect()
        mac_table = nc.send_command("show mac address-table")
        arp_table  = nc.send_command("show arp")
        nc.disconnect()

        # Parse ARP : IP → MAC
        ip_mac = {}
        for line in arp_table.splitlines():
            m_ip  = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', line)
            m_mac = re.search(r'([0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}'
                              r'[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2})', line)
            if m_ip and m_mac:
                ip_mac[_norm_mac(m_mac.group(0))] = m_ip.group(0)

        # Parse MAC table : MAC → port + VLAN
        # Format: "78:84:3c:cc:0c:fa  1   Gi1/0/6  dynamic  aging"
        mac_port = {}
        for line in mac_table.splitlines():
            if '1/0/' not in line:
                continue
            parts = line.split()
            # Chercher le MAC dans les colonnes
            mac_col = next((p for p in parts if re.match(
                r'^[0-9A-Fa-f]{2}[:\-][0-9A-Fa-f]{2}[:\-][0-9A-Fa-f]{2}'
                r'[:\-][0-9A-Fa-f]{2}[:\-][0-9A-Fa-f]{2}[:\-][0-9A-Fa-f]{2}$', p)), None)
            port_col = next((p for p in parts if re.match(r'^(?:Gi|gi)?\d+/\d+/\d+$', p)), None)
            if not mac_col or not port_col:
                continue
            mac_n = _norm_mac(mac_col)
            port  = re.sub(r'^[Gg][Ii]', '', port_col)  # retirer "Gi"
            # VLAN = colonne juste après le MAC (ou avant le port)
            try:
                mac_idx  = parts.index(mac_col)
                vlan = parts[mac_idx + 1] if mac_idx + 1 < len(parts) else '?'
                if not vlan.isdigit():
                    vlan = '?'
            except (ValueError, IndexError):
                vlan = '?'
            if mac_n not in mac_port:
                mac_port[mac_n] = {'port': port, 'vlan': vlan}

        # Construire la liste des machines
        machines = []
        seen_ports = set()
        for mac, info in mac_port.items():
            port = info['port']
            if port == PORT_UPLINK:
                continue
            ip = ip_mac.get(mac, '')
            is_quarantined = any(
                (q.get('attacker_port') == port or q.get('victim_port') == port)
                and not q.get('restored')
                for q in quarantined_list
            )
            is_blocked = mac in mac_blacklist
            backup_port = _get_backup_port_label(port)
            # Hostname depuis cache ou DNS rapide
            hostname = '—'
            cached = machine_info_cache.get(ip, {})
            if cached.get('hostname') and cached['hostname'] != 'Unknown':
                hostname = cached['hostname']
            elif ip:
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except Exception:
                    pass
            machines.append({
                'port':         port,
                'mac':          mac,
                'ip':           ip,
                'hostname':     hostname,
                'vlan':         info['vlan'],
                'quarantined':  is_quarantined,
                'blocked':      is_blocked,
                'backup_port':  backup_port,
            })
            seen_ports.add(port)

        machines.sort(key=lambda x: [int(p) for p in x['port'].split('/')])
        add_log(f"[INFO] Scan réseau : {len(machines)} machine(s) détectée(s)", "info")
        return jsonify({'machines': machines, 'count': len(machines)})
    except Exception as e:
        add_log(f"[!] Erreur scan machines connectées: {e}", "error")
        return jsonify({'machines': [], 'count': 0, 'error': str(e)})


@app.route('/api/switch/port/shutdown', methods=['POST'])
def sw_port_shutdown():
    port = request.json.get('port','')
    if not port: return jsonify({'result':'Port requis'})
    res = _sw_cfg([f'interface gigabitEthernet {port}','shutdown','exit'])
    add_log(f"[SWITCH] Port {port} éteint (shutdown)", "warning")
    return jsonify({'result': res})

@app.route('/api/switch/port/enable', methods=['POST'])
def sw_port_enable():
    port = request.json.get('port','')
    if not port: return jsonify({'result':'Port requis'})
    res = _sw_cfg([f'interface gigabitEthernet {port}','no shutdown','exit'])
    add_log(f"[SWITCH] Port {port} allumé (no shutdown)", "success")
    return jsonify({'result': res})

@app.route('/api/switch/port/status', methods=['POST'])
def sw_port_status():
    port = request.json.get('port','')
    cmd = f'show interface gigabitEthernet {port}' if port else 'show interface status'
    return jsonify({'result': _sw_show(cmd)})

@app.route('/api/switch/port/stats', methods=['POST'])
def sw_port_stats():
    port = request.json.get('port','')
    cmd = f'show interface gigabitEthernet {port} counters' if port else 'show interface counters'
    return jsonify({'result': _sw_show(cmd)})

@app.route('/api/switch/port/speed', methods=['POST'])
def sw_port_speed():
    port  = request.json.get('port','')
    speed = request.json.get('speed','auto')
    duplex= request.json.get('duplex','auto')
    if not port: return jsonify({'result':'Port requis'})
    cmds = [f'interface gigabitEthernet {port}']
    cmds += ['speed auto' if speed == 'auto' else f'speed {speed}']
    cmds += ['duplex auto' if duplex == 'auto' else f'duplex {duplex}']
    cmds += ['exit']
    return jsonify({'result': _sw_cfg(cmds)})

@app.route('/api/switch/port/description', methods=['POST'])
def sw_port_desc():
    port = request.json.get('port','')
    desc = request.json.get('description','')
    if not port: return jsonify({'result':'Port requis'})
    cmds = [f'interface gigabitEthernet {port}', f'description {desc}', 'exit']
    return jsonify({'result': _sw_cfg(cmds)})

@app.route('/api/switch/port/all_status')
def sw_all_ports():
    return jsonify({'result': _sw_show('show interface status')})

@app.route('/api/switch/vlan/list')
def sw_vlan_list():
    return jsonify({'result': _sw_show('show vlan')})

@app.route('/api/switch/vlan/create', methods=['POST'])
def sw_vlan_create():
    vid  = request.json.get('vlan_id','')
    name = request.json.get('name','')
    if not vid: return jsonify({'result':'VLAN ID requis'})
    cmds = [f'vlan {vid}']
    if name: cmds.append(f'name {name}')
    cmds.append('exit')
    res = _sw_cfg(cmds)
    add_log(f"[SWITCH] VLAN {vid} créé ({name})", "success")
    return jsonify({'result': res})

@app.route('/api/switch/vlan/delete', methods=['POST'])
def sw_vlan_delete():
    vid = request.json.get('vlan_id','')
    if not vid: return jsonify({'result':'VLAN ID requis'})
    res = _sw_cfg([f'no vlan {vid}'])
    add_log(f"[SWITCH] VLAN {vid} supprimé", "warning")
    return jsonify({'result': res})

@app.route('/api/switch/vlan/assign', methods=['POST'])
def sw_vlan_assign():
    port  = request.json.get('port','')
    vid   = request.json.get('vlan_id','')
    mode  = request.json.get('mode','untagged')
    pvid  = request.json.get('set_pvid', False)
    if not port or not vid: return jsonify({'result':'Port et VLAN requis'})
    cmds  = [f'interface gigabitEthernet {port}',
             f'switchport general allowed vlan {vid} {mode}']
    if pvid: cmds.append(f'switchport pvid {vid}')
    cmds.append('exit')
    return jsonify({'result': _sw_cfg(cmds)})

@app.route('/api/switch/vlan/remove', methods=['POST'])
def sw_vlan_remove():
    port = request.json.get('port','')
    vid  = request.json.get('vlan_id','')
    if not port or not vid: return jsonify({'result':'Port et VLAN requis'})
    cmds = [f'interface gigabitEthernet {port}',
            f'no switchport general allowed vlan {vid}','exit']
    return jsonify({'result': _sw_cfg(cmds)})

@app.route('/api/switch/vlan/port_info', methods=['POST'])
def sw_vlan_port_info():
    port = request.json.get('port','')
    cmd = f'show interface gigabitEthernet {port} switchport' if port else 'show vlan brief'
    return jsonify({'result': _sw_show(cmd)})

@app.route('/api/switch/mac/table')
def sw_mac_table():
    return jsonify({'result': _sw_show('show mac address-table')})

@app.route('/api/switch/mac/table_port', methods=['POST'])
def sw_mac_table_port():
    port = request.json.get('port','')
    cmd = f'show mac address-table interface gigabitEthernet {port}' if port else 'show mac address-table'
    return jsonify({'result': _sw_show(cmd)})

@app.route('/api/switch/mac/filters')
def sw_mac_filters():
    return jsonify({'result': _sw_show('show mac address-table filtering')})

@app.route('/api/switch/mac/clear', methods=['POST'])
def sw_mac_clear():
    vlan = request.json.get('vlan','')
    port = request.json.get('port','')
    if vlan:
        return jsonify({'result': _sw_cfg([f'no mac address-table dynamic vlan {vlan}'])})
    elif port:
        return jsonify({'result': _sw_cfg([f'no mac address-table dynamic interface gigabitEthernet {port}'])})
    return jsonify({'result': _sw_cfg(['no mac address-table dynamic'])})

@app.route('/api/switch/arp')
def sw_arp():
    return jsonify({'result': _sw_show('show arp')})

@app.route('/api/switch/stp')
def sw_stp():
    return jsonify({'result': _sw_show('show spanning-tree')})

@app.route('/api/switch/lldp')
def sw_lldp():
    return jsonify({'result': _sw_show('show lldp neighbors')})

@app.route('/api/switch/storm', methods=['POST'])
def sw_storm():
    port    = request.json.get('port','')
    action  = request.json.get('action','enable')
    rate    = request.json.get('rate','256')
    if not port: return jsonify({'result':'Port requis'})
    if action == 'enable':
        cmds = [f'interface gigabitEthernet {port}',
                f'storm-control broadcast level {rate}',
                f'storm-control multicast level {rate}',
                'exit']
    else:
        cmds = [f'interface gigabitEthernet {port}',
                'no storm-control broadcast','no storm-control multicast','exit']
    return jsonify({'result': _sw_cfg(cmds)})

@app.route('/api/switch/port_security', methods=['POST'])
def sw_port_security():
    port    = request.json.get('port','')
    action  = request.json.get('action','enable')
    max_mac = request.json.get('max_mac','1')
    if not port: return jsonify({'result':'Port requis'})
    if action == 'enable':
        cmds = [f'interface gigabitEthernet {port}',
                'port-security',
                f'port-security max-mac-count {max_mac}',
                'port-security action discard',
                'exit']
    else:
        cmds = [f'interface gigabitEthernet {port}','no port-security','exit']
    return jsonify({'result': _sw_cfg(cmds)})

@app.route('/api/switch/system/info')
def sw_sys_info():
    return jsonify({'result': _sw_show('show system-info')})

@app.route('/api/switch/system/version')
def sw_sys_version():
    return jsonify({'result': _sw_show('show version')})

@app.route('/api/switch/system/config')
def sw_sys_config():
    return jsonify({'result': _sw_show('show running-config')})

@app.route('/api/switch/system/startup')
def sw_sys_startup():
    return jsonify({'result': _sw_show('show startup-config')})

@app.route('/api/switch/system/save', methods=['POST'])
def sw_sys_save():
    try:
        nc = _connect()
        _save(nc)
        nc.disconnect()
        add_log("[SWITCH] Configuration sauvegardée manuellement", "success")
        return jsonify({'result': 'Configuration sauvegardée (copy running-config startup-config)'})
    except Exception as e:
        return jsonify({'result': f'Erreur: {e}'})

@app.route('/api/switch/system/cpu')
def sw_sys_cpu():
    return jsonify({'result': _sw_show('show cpu')})

@app.route('/api/switch/system/memory')
def sw_sys_memory():
    return jsonify({'result': _sw_show('show memory')})

@app.route('/api/switch/system/logs')
def sw_sys_logs():
    return jsonify({'result': _sw_show('show log')})

@app.route('/api/switch/ping', methods=['POST'])
def sw_ping():
    target = request.json.get('target','')
    count  = request.json.get('count', 4)
    if not target: return jsonify({'result':'IP cible requise'})
    return jsonify({'result': _sw_show(f'ping {target} repeat {count}')})

@app.route('/api/switch/traceroute', methods=['POST'])
def sw_traceroute():
    target = request.json.get('target','')
    if not target: return jsonify({'result':'IP cible requise'})
    return jsonify({'result': _sw_show(f'traceroute {target}')})

@app.route('/api/switch/cmd/custom', methods=['POST'])
def sw_custom_cmd():
    """Exécute une commande personnalisée (show uniquement pour la sécurité)."""
    cmd     = request.json.get('command','').strip()
    is_show = cmd.lower().startswith('show')
    if not cmd: return jsonify({'result':'Commande requise'})
    add_log(f"[SWITCH CMD] {cmd}", "info")
    if is_show:
        return jsonify({'result': _sw_show(cmd)})
    return jsonify({'result': _sw_cfg([cmd])})


@app.route('/quarantine')
@app.route('/quarantine/<path:dummy>')
def quarantine_page():
    ip          = request.args.get('ip', request.remote_addr)
    attack_type = request.args.get('type', 'ATTAQUE DÉTECTÉE')
    return render_template_string(QUARANTINE_PAGE, ip=ip, attack_type=attack_type,
                                  delay=WARN_DURATION_SEC)


QUARANTINE_PAGE = '''<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ACCÈS BLOQUÉ — NetShield SDN</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=JetBrains+Mono:wght@400;700&display=swap');
body{
  background:#0a0000;
  color:#ff2222;
  font-family:monospace;
  min-height:100vh;
  display:flex;align-items:center;justify-content:center;
  overflow:hidden;
}
/* Scanlines effect */
body::before{
  content:'';
  position:fixed;inset:0;
  background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(255,0,0,.03) 2px,rgba(255,0,0,.03) 4px);
  pointer-events:none;z-index:10;
}
/* Vignette */
body::after{
  content:'';
  position:fixed;inset:0;
  background:radial-gradient(ellipse at center,transparent 40%,rgba(0,0,0,.85) 100%);
  pointer-events:none;z-index:9;
}
.container{
  text-align:center;
  padding:40px;
  max-width:900px;
  width:100%;
  position:relative;z-index:20;
  animation:glitch-shift .08s infinite;
}
@keyframes glitch-shift{
  0%,100%{transform:none}
  92%{transform:none}
  93%{transform:translate(-2px,0) skewX(-1deg)}
  94%{transform:translate(2px,0) skewX(1deg)}
  95%{transform:none}
}
.skull{
  font-size:8rem;
  line-height:1;
  margin-bottom:20px;
  display:block;
  filter:drop-shadow(0 0 30px #ff0000);
  animation:pulse-skull 1s infinite;
}
@keyframes pulse-skull{
  0%,100%{filter:drop-shadow(0 0 30px #ff0000);transform:scale(1)}
  50%{filter:drop-shadow(0 0 60px #ff4400);transform:scale(1.05)}
}
.title{
  font-family:'Share Tech Mono',monospace;
  font-size:3.5rem;
  font-weight:700;
  letter-spacing:6px;
  text-transform:uppercase;
  text-shadow:0 0 20px #ff0000,0 0 40px #ff0000;
  margin-bottom:10px;
  animation:flicker 3s infinite;
}
@keyframes flicker{
  0%,19%,21%,23%,25%,54%,56%,100%{opacity:1;text-shadow:0 0 20px #ff0000,0 0 40px #ff0000}
  20%,22%,24%,55%{opacity:.6;text-shadow:none}
}
.subtitle{
  font-size:1.1rem;
  color:#ff6666;
  letter-spacing:3px;
  text-transform:uppercase;
  margin-bottom:40px;
}
.info-box{
  border:2px solid #ff2222;
  border-radius:4px;
  padding:24px 32px;
  margin:30px auto;
  max-width:600px;
  background:rgba(255,0,0,.05);
  box-shadow:0 0 30px rgba(255,0,0,.2), inset 0 0 30px rgba(255,0,0,.05);
}
.info-row{
  display:flex;justify-content:space-between;align-items:center;
  padding:10px 0;border-bottom:1px solid rgba(255,34,34,.3);
  font-size:.9rem;
}
.info-row:last-child{border-bottom:none}
.info-label{color:#ff4444;letter-spacing:1px;text-transform:uppercase;font-size:.75rem}
.info-val{color:#ffaaaa;font-weight:700;font-size:.95rem}
.warn-msg{
  font-size:1rem;
  color:#ff8888;
  line-height:1.8;
  margin:30px 0;
  padding:20px;
  border-left:4px solid #ff2222;
  text-align:left;
  background:rgba(255,0,0,.03);
}
.countdown-wrap{margin-top:30px}
.countdown-label{font-size:.75rem;color:#ff4444;letter-spacing:2px;text-transform:uppercase;margin-bottom:10px}
.countdown-bar{height:4px;background:rgba(255,34,34,.2);border-radius:2px;overflow:hidden;margin-bottom:12px}
.countdown-fill{height:100%;background:#ff2222;border-radius:2px;box-shadow:0 0 10px #ff0000;
  transition:width 1s linear;width:100%}
.countdown-num{font-size:2rem;color:#ff2222;text-shadow:0 0 10px #ff0000;font-weight:700}
.blink{animation:blink .5s infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:0}}
.corner{position:fixed;font-size:.65rem;color:rgba(255,34,34,.4);letter-spacing:2px}
.corner.tl{top:16px;left:16px}
.corner.tr{top:16px;right:16px}
.corner.bl{bottom:16px;left:16px}
.corner.br{bottom:16px;right:16px}
</style>
</head>
<body>
<div class="corner tl">NetShield SDN // T1600G-28PS</div>
<div class="corner tr" id="ts"></div>
<div class="corner bl">VLAN_666 // QUARANTAINE</div>
<div class="corner br">INCIDENT_LOG // ACTIVE</div>

<div class="container">
  <span class="skull">&#9760;</span>
  <div class="title">ACCÈS BLOQUÉ</div>
  <div class="subtitle">Activité suspecte détectée sur ce poste</div>

  <div class="info-box">
    <div class="info-row">
      <span class="info-label">Adresse IP</span>
      <span class="info-val">{{ ip }}</span>
    </div>
    <div class="info-row">
      <span class="info-label">Type d'incident</span>
      <span class="info-val" style="color:#ff4444">{{ attack_type }}</span>
    </div>
    <div class="info-row">
      <span class="info-label">Statut</span>
      <span class="info-val blink" style="color:#ff0000">&#9632; PORT EN COURS D&#39;ISOLATION</span>
    </div>
    <div class="info-row">
      <span class="info-label">VLAN</span>
      <span class="info-val">666 — QUARANTAINE</span>
    </div>
    <div class="info-row">
      <span class="info-label">Horodatage</span>
      <span class="info-val" id="ts2">--</span>
    </div>
  </div>

  <div class="warn-msg">
    &#9888;&nbsp; Votre activité réseau a été identifiée comme malveillante.<br>
    &#9888;&nbsp; Ce poste est en cours d&#39;isolation du réseau.<br>
    &#9888;&nbsp; L&#39;incident a été enregistré et l&#39;administrateur a été notifié.<br>
    &#9888;&nbsp; Toute tentative de reconnexion sera automatiquement bloquée.
  </div>

  <div class="countdown-wrap">
    <div class="countdown-label">Isolation dans</div>
    <div class="countdown-bar"><div class="countdown-fill" id="bar"></div></div>
    <div class="countdown-num" id="cnt">{{ delay }}</div>
  </div>
</div>

<script>
const delay = {{ delay }};
let remaining = delay;
const bar = document.getElementById('bar');
const cnt = document.getElementById('cnt');
const ts  = document.getElementById('ts');
const ts2 = document.getElementById('ts2');

function tick(){
  const now = new Date().toLocaleString('fr-FR');
  ts.textContent  = now;
  ts2.textContent = now;
  if(remaining > 0){
    remaining--;
    cnt.textContent = remaining;
    bar.style.width = (remaining / delay * 100) + '%';
  }
}
setInterval(tick, 1000);
tick();
</script>
</body>
</html>'''


def init_backup_ports():
    """Au démarrage : éteint tous les ports backup (15-27) pour état propre."""
    cmds = []
    for backup_num in PORT_BACKUP_MAP.values():
        backup_port = f'1/0/{backup_num}'
        cmds += [f'interface gigabitEthernet {backup_port}', 'shutdown', 'exit']
    try:
        nc = _connect()
        nc.send_config_set(cmds)
        _save(nc)
        nc.disconnect()
        add_log(f"[INIT] Ports backup {list(PORT_BACKUP_MAP.values())} mis en veille (shutdown)", "info")
    except Exception as e:
        add_log(f"[!] Erreur init ports backup: {e}", "error")


# ---------------------------------------------------------------------------
# ROUTES DE TEST (injectent des données sans connexion switch)
# ---------------------------------------------------------------------------

@app.route('/api/test/inject_quarantine', methods=['POST'])
def api_test_inject():
    """Injecte une entrée de quarantaine fictive — test sans switch."""
    data = request.json or {}
    ts   = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    ip   = data.get('ip',   '192.168.0.99')
    mac  = data.get('mac',  'aa:bb:cc:dd:ee:ff')
    port = data.get('port', '1/0/5')
    mode = data.get('mode', 'ISOLATE_ATTACKER')
    acfg = ATTACK_PATTERNS.get('DDOS_FLOOD', {'icon':'💥','color':'#ef4444','description':'DDoS / Flooding'})
    entry = {
        'id':            ts + '_' + ip,
        'time':          ts,
        'mode':          mode,
        'attack_type':   'DDOS_FLOOD',
        'attack_icon':   acfg['icon'],
        'attack_color':  acfg['color'],
        'attack_desc':   acfg['description'],
        'signature':     '[TEST] FLOOD DETECTE — simulation',
        'sid':           1000002, 'severity': 2,
        'attacker_ip':   ip,
        'attacker_mac':  _norm_mac(mac),
        'attacker_port': port,
        'attacker_backup_port': None,
        'attacker_info': {
            'ip': ip, 'hostname': 'PC-TEST-ATTAQUE',
            'serial': 'SN-TEST-2026-001',
            'os': 'Kali Linux 2024.1 (simulé)',
            'mac': _norm_mac(mac), 'vendor': 'Test Vendor Inc.',
            'open_ports': ['22/tcp open ssh', '80/tcp open http', '443/tcp open https'],
        },
        'mac_blocked':   True,
        'victim_ip':     'N/A', 'victim_mac': 'N/A', 'victim_port': 'N/A',
        'victim_backup_port': None, 'victim_info': {},
        'status':        'QUARANTAINE ACTIVE', 'restored': False,
    }
    with _lock:
        quarantined_list.insert(0, entry)
        mac_blacklist.add(_norm_mac(mac))
    add_log(f"[TEST] Entrée fictive injectée — port {port} | MAC {mac}", "warning")
    # Envoyer l'alerte Telegram avec toutes les infos (hostname + numéro de série)
    threading.Thread(target=_telegram_alert_quarantine, args=(entry,), daemon=True).start()
    return jsonify({'status': 'injected', 'id': entry['id'], 'port': port, 'mac': _norm_mac(mac)})


@app.route('/api/test/restore_memory', methods=['POST'])
def api_test_restore_memory():
    """Restaure une entrée en mémoire uniquement (sans sw1111411itch) — test."""
    data  = request.json or {}
    qid   = data.get('qid', '')
    role  = data.get('role', 'attacker')
    mac   = data.get('mac', '')
    _mark_restored(qid, role)
    if mac:
        with _lock:
            mac_blacklist.discard(_norm_mac(mac))
        add_log(f"[TEST] MAC {mac} retiré de la blacklist (mémoire uniquement)", "success")
    add_log(f"[TEST] Restauration mémoire — qid={qid} role={role}", "success")
    # Vérifier le résultat
    with _lock:
        q = next((q for q in quarantined_list if q.get('id') == qid), None)
    restored = q.get('restored', False) if q else False
    return jsonify({'status': 'ok', 'restored': restored, 'qid': qid})


@app.route('/download/agent')
def download_agent():
    """Sert le binaire NetShield_Agent pour déploiement HTTP fallback."""
    if os.path.exists(AGENT_EXE):
        return send_file(AGENT_EXE, as_attachment=True, download_name='NetShield_Agent')
    return jsonify({'error': 'Agent introuvable sur le serveur'}), 404


if __name__ == '__main__':
    _load_state()
    add_log("[INFO] NetShield SDN démarré", "info")
    add_log(f"[INFO] Switch : {SWITCH_PARAMS['host']} | HOME_NET : {HOME_NET} | VLAN Quarantaine : {VLAN_QUARANTAINE}", "info")
    add_log(f"[INFO] Mode : quarantaine DIRECTE en VLAN {VLAN_QUARANTAINE} + blocage MAC attaquant", "info")
    if TELEGRAM_CHAT_ID:
        add_log(f"[TELEGRAM] Chat ID restauré : {TELEGRAM_CHAT_ID}", "success")
    threading.Thread(target=init_backup_ports, daemon=True).start()
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
