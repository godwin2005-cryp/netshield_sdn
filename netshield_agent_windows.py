"""
NetShield SDN — Agent Windows
==============================
- Écoute port 9999
- Reçoit POST /quarantine → affiche écran rouge plein écran
- Reçoit POST /release    → ferme l'écran rouge
- Tourne en arrière-plan (pas de fenêtre console)
- Compatible Windows 7 / 8 / 10 / 11

Compilation en .exe standalone (depuis Windows) :
    pip install pyinstaller flask
    pyinstaller --onefile --windowed --name NetShield_Agent netshield_agent_windows.py
    → dist/NetShield_Agent.exe
"""

import threading
import tkinter as tk
import sys
import socket
import ctypes
from datetime import datetime
from flask import Flask, request, jsonify
import logging

# ── Silence total de Flask/Werkzeug (pas de console) ─────────────
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
cli = logging.getLogger('flask.app')
cli.setLevel(logging.ERROR)

# ── Config ────────────────────────────────────────────────────────
LISTEN_PORT = 9999
app = Flask(__name__)

# ── État global ───────────────────────────────────────────────────
_root       = None
_alert_win  = None
_queue_lock = threading.Lock()
_show_queue = []


# ════════════════════════════════════════════════════════════════════
#  ROUTES HTTP
# ════════════════════════════════════════════════════════════════════

@app.route('/quarantine', methods=['POST'])
def route_quarantine():
    data = {}
    try:
        data = request.get_json(force=True, silent=True) or {}
    except Exception:
        pass

    ip          = (data.get('attacker_ip')
                   or data.get('ip')
                   or _get_local_ip())
    mac         = (data.get('attacker_mac')
                   or data.get('mac')
                   or _get_local_mac())
    attack      = (data.get('attack_desc')
                   or data.get('attack_type')
                   or 'Attaque détectée')
    heure       = data.get('time') or datetime.now().strftime('%H:%M:%S')

    with _queue_lock:
        _show_queue.append({
            'ip': ip, 'mac': mac,
            'attack': attack, 'heure': heure,
        })

    if _root:
        _root.after(0, _process_queue)

    return jsonify({'status': 'ok'}), 200


@app.route('/release', methods=['POST'])
def route_release():
    if _root:
        _root.after(0, _close_alert)
    return jsonify({'status': 'released'}), 200


@app.route('/ping', methods=['GET'])
def route_ping():
    return jsonify({'status': 'alive', 'port': LISTEN_PORT}), 200


# ════════════════════════════════════════════════════════════════════
#  ÉCRAN ROUGE TKINTER
# ════════════════════════════════════════════════════════════════════

class EcranRouge:
    BG      = "#8B0000"
    GRID    = "#9B0000"
    INFO_BG = "#5A0000"
    WHITE   = "#FFFFFF"
    YELLOW  = "#FFD700"
    GRAY    = "#CCCCCC"
    BLINK   = "#FF4444"

    def __init__(self, parent, ip, mac, attack, heure):
        self.parent = parent
        self.ip     = ip
        self.mac    = mac
        self.attack = attack
        self.heure  = heure
        self._blink = True

        self.win = tk.Toplevel(parent)
        self.win.configure(bg=self.BG)
        self.win.attributes('-fullscreen', True)
        self.win.attributes('-topmost', True)
        self.win.configure(cursor='none')
        # Empêche fermeture par l'utilisateur
        self.win.protocol("WM_DELETE_WINDOW", lambda: None)
        # Empêche Alt+F4 sur Windows
        self.win.bind('<Alt-F4>', lambda e: 'break')

        self._build()
        self._blink_loop()

    def _build(self):
        W  = self.win.winfo_screenwidth()
        H  = self.win.winfo_screenheight()
        cx = W // 2
        c  = tk.Canvas(self.win, bg=self.BG,
                       highlightthickness=0, width=W, height=H)
        c.pack(fill='both', expand=True)
        self.canvas = c

        # ── Grille de fond ────────────────────────────────────────
        for x in range(0, W, 42):
            c.create_line(x, 0, x, H, fill=self.GRID, width=1)
        for y in range(0, H, 42):
            c.create_line(0, y, W, y, fill=self.GRID, width=1)

        # ── Triangle d'avertissement ──────────────────────────────
        ty  = int(H * 0.10)
        th  = int(H * 0.20)
        tw  = int(th * 1.15)
        pts = [cx, ty,
               cx - tw//2, ty + th,
               cx + tw//2, ty + th]
        c.create_polygon(pts, fill=self.YELLOW, outline=self.YELLOW)
        bw = int(tw * 0.09)
        c.create_rectangle(cx-bw, ty+int(th*.22),
                           cx+bw, ty+int(th*.68),
                           fill=self.INFO_BG, outline='')
        c.create_oval(cx-bw, ty+int(th*.78),
                      cx+bw, ty+int(th*.90),
                      fill=self.INFO_BG, outline='')

        # ── Titre principal ───────────────────────────────────────
        fs_t = max(20, int(H * 0.068))
        self._title = c.create_text(
            cx, int(H * 0.525),
            text="!!! ALERTE DE SÉCURITÉ !!!",
            fill=self.WHITE,
            font=('Arial Black', fs_t, 'bold'),
            anchor='center'
        )

        # ── Sous-titres ───────────────────────────────────────────
        fs_b = max(12, int(H * 0.028))
        c.create_text(cx, int(H * 0.625),
            text="Votre machine a été compromise et isolée du réseau.",
            fill=self.WHITE, font=('Arial', fs_b), anchor='center')
        c.create_text(cx, int(H * 0.685),
            text="Contactez immédiatement votre administrateur réseau.",
            fill=self.WHITE, font=('Arial', fs_b), anchor='center')

        # ── Bandeau informations ──────────────────────────────────
        bw2 = int(W * 0.50)
        bh  = int(H * 0.125)
        bx  = cx - bw2 // 2
        by  = int(H * 0.77)
        c.create_rectangle(bx, by, bx+bw2, by+bh,
                           fill=self.INFO_BG, outline='')
        fs_i = max(10, int(H * 0.023))
        c.create_text(cx, by + int(bh * 0.28),
            text=f"IP: {self.ip}  |  MAC: {self.mac}",
            fill=self.GRAY, font=('Courier New', fs_i), anchor='center')
        c.create_text(cx, by + int(bh * 0.68),
            text=f"Attaque détectée: {self.attack}  |  {self.heure}",
            fill=self.GRAY, font=('Courier New', fs_i), anchor='center')

    def _blink_loop(self):
        color = self.WHITE if self._blink else self.BLINK
        self.canvas.itemconfig(self._title, fill=color)
        self._blink = not self._blink
        try:
            self.win.after(800, self._blink_loop)
        except Exception:
            pass

    def destroy(self):
        try:
            self.win.destroy()
        except Exception:
            pass


# ════════════════════════════════════════════════════════════════════
#  CALLBACKS THREAD-SAFE (appelés via root.after() )
# ════════════════════════════════════════════════════════════════════

def _process_queue():
    global _alert_win
    with _queue_lock:
        if not _show_queue:
            return
        data = _show_queue.pop(0)

    if _alert_win:
        try:
            _alert_win.destroy()
        except Exception:
            pass

    _alert_win = EcranRouge(
        _root,
        ip=data['ip'],
        mac=data['mac'],
        attack=data['attack'],
        heure=data['heure'],
    )


def _close_alert():
    global _alert_win
    if _alert_win:
        try:
            _alert_win.destroy()
        except Exception:
            pass
        _alert_win = None


# ════════════════════════════════════════════════════════════════════
#  UTILITAIRES RÉSEAU
# ════════════════════════════════════════════════════════════════════

def _get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('192.168.0.1', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return 'Inconnu'


def _get_local_mac():
    """Récupère le MAC réel de la machine Windows."""
    try:
        import uuid
        mac_int = uuid.getnode()
        mac_hex = ':'.join(
            f'{(mac_int >> (i*8)) & 0xff:02x}'
            for i in reversed(range(6))
        )
        return mac_hex
    except Exception:
        return 'Inconnu'


# ════════════════════════════════════════════════════════════════════
#  FLASK — thread daemon
# ════════════════════════════════════════════════════════════════════

def _start_flask():
    app.run(
        host='0.0.0.0',
        port=LISTEN_PORT,
        debug=False,
        threaded=True,
        use_reloader=False,
    )


# ════════════════════════════════════════════════════════════════════
#  POINT D'ENTRÉE
# ════════════════════════════════════════════════════════════════════

def main():
    global _root

    # ── Sur Windows : cacher la fenêtre console si elle existe ───
    try:
        ctypes.windll.user32.ShowWindow(
            ctypes.windll.kernel32.GetConsoleWindow(), 0)
    except Exception:
        pass

    # ── Vérifier que le port 9999 n'est pas déjà utilisé ─────────
    test = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    test.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        test.bind(('0.0.0.0', LISTEN_PORT))
        test.close()
    except OSError:
        # Agent déjà en cours — on quitte silencieusement
        sys.exit(0)

    # ── Lancer Flask en arrière-plan ──────────────────────────────
    t = threading.Thread(target=_start_flask, daemon=True)
    t.start()

    # ── Fenêtre Tkinter cachée (boucle d'événements) ──────────────
    _root = tk.Tk()
    _root.withdraw()
    _root.title('NetShield Agent')

    # Garder la boucle vivante
    _root.mainloop()


if __name__ == '__main__':
    main()
