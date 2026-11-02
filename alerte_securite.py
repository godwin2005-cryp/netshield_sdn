#!/usr/bin/env python3
"""
NetShield SDN — Écran d'Alerte de Sécurité
Agent client Tkinter — Affichage d'isolement réseau
"""

import tkinter as tk
from tkinter import font as tkfont
import sys
import argparse
from datetime import datetime


def parse_args():
    parser = argparse.ArgumentParser(description="Alerte de sécurité NetShield SDN")
    parser.add_argument("--ip",      default="10.0.0.10",       help="Adresse IP de la machine")
    parser.add_argument("--mac",     default="aa:bb:cc:dd:10",   help="Adresse MAC de la machine")
    parser.add_argument("--attack",  default="DDoS SYN Flood",   help="Type d'attaque détectée")
    parser.add_argument("--time",    default=None,               help="Heure de détection (HH:MM:SS)")
    return parser.parse_args()


class AlerteSecurite:
    def __init__(self, root, ip, mac, attack, detection_time):
        self.root = root
        self.ip = ip
        self.mac = mac
        self.attack = attack
        self.detection_time = detection_time

        # ── Couleurs ──────────────────────────────────────────────────
        self.BG_DARK   = "#8B0000"   # rouge sombre (fond principal)
        self.BG_GRID   = "#9B0000"   # rouge grille légèrement plus clair
        self.BG_INFO   = "#5A0000"   # fond bandeau infos
        self.FG_WHITE  = "#FFFFFF"
        self.FG_YELLOW = "#FFD700"
        self.FG_GRAY   = "#CCCCCC"

        self._build_ui()

    # ─────────────────────────────────────────────────────────────────
    def _build_ui(self):
        root = self.root

        # Plein écran, pas de barre de titre
        root.attributes("-fullscreen", True)
        root.configure(bg=self.BG_DARK, cursor="none")
        root.title("ALERTE DE SÉCURITÉ")

        # Quitter avec Échap (pour les démos)
        root.bind("<Escape>", lambda e: root.destroy())
        root.bind("<q>",      lambda e: root.destroy())

        # Canvas principal (pour le fond quadrillé)
        self.canvas = tk.Canvas(root, bg=self.BG_DARK, highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)

        # Dessin différé (on attend que la fenêtre ait ses dimensions)
        root.update_idletasks()
        self._draw_background()
        self._draw_widgets()

        # Effet de clignotement toutes les 800 ms
        self._blink = True
        self._blink_loop()

    # ─────────────────────────────────────────────────────────────────
    def _draw_background(self):
        """Fond rouge foncé avec quadrillage subtil."""
        c = self.canvas
        W = c.winfo_width()
        H = c.winfo_height()
        step = 40

        c.create_rectangle(0, 0, W, H, fill=self.BG_DARK, outline="")

        for x in range(0, W, step):
            c.create_line(x, 0, x, H, fill=self.BG_GRID, width=1)
        for y in range(0, H, step):
            c.create_line(0, y, W, y, fill=self.BG_GRID, width=1)

    # ─────────────────────────────────────────────────────────────────
    def _draw_widgets(self):
        c      = self.canvas
        W      = c.winfo_width()
        H      = c.winfo_height()
        cx     = W // 2          # centre horizontal

        # ── Polices ───────────────────────────────────────────────────
        font_title  = ("DejaVu Sans", int(H * 0.07), "bold")
        font_body   = ("DejaVu Sans", int(H * 0.030))
        font_info   = ("DejaVu Sans Mono", int(H * 0.025))

        # ── Triangle d'avertissement ──────────────────────────────────
        tri_y   = H * 0.12
        tri_h   = H * 0.20
        tri_w   = tri_h * 1.10
        pts = [
            cx,           tri_y,
            cx - tri_w/2, tri_y + tri_h,
            cx + tri_w/2, tri_y + tri_h,
        ]
        c.create_polygon(pts, fill=self.FG_YELLOW, outline=self.FG_YELLOW)

        # Point d'exclamation dans le triangle
        ex_x  = cx
        ex_y1 = tri_y + tri_h * 0.22
        ex_y2 = tri_y + tri_h * 0.68
        ex_y3 = tri_y + tri_h * 0.78
        ex_y4 = tri_y + tri_h * 0.90
        bar_w = tri_w * 0.09
        c.create_rectangle(ex_x - bar_w, ex_y1, ex_x + bar_w, ex_y2,
                           fill="#3D1C00", outline="")
        c.create_oval(ex_x - bar_w, ex_y3, ex_x + bar_w, ex_y4,
                      fill="#3D1C00", outline="")

        # ── Titre ─────────────────────────────────────────────────────
        title_y = H * 0.52
        self.title_id = c.create_text(
            cx, title_y,
            text="!!! ALERTE DE SÉCURITÉ !!!",
            fill=self.FG_WHITE,
            font=font_title,
            anchor="center"
        )

        # ── Sous-titres ───────────────────────────────────────────────
        c.create_text(
            cx, H * 0.63,
            text="Votre machine a été compromise et isolée du réseau.",
            fill=self.FG_WHITE,
            font=font_body,
            anchor="center"
        )
        c.create_text(
            cx, H * 0.695,
            text="Contactez immédiatement votre administrateur réseau.",
            fill=self.FG_WHITE,
            font=font_body,
            anchor="center"
        )

        # ── Bandeau d'informations techniques ─────────────────────────
        box_w  = W * 0.46
        box_h  = H * 0.115
        box_x  = cx - box_w / 2
        box_y  = H * 0.77
        radius = 8
        self._rounded_rect(c, box_x, box_y,
                            box_x + box_w, box_y + box_h,
                            radius, fill=self.BG_INFO, outline="")

        line1 = f"IP: {self.ip}  |  MAC: {self.mac}"
        line2 = f"Attaque détectée: {self.attack}  |  {self.detection_time}"

        c.create_text(cx, box_y + box_h * 0.30,
                      text=line1, fill=self.FG_GRAY,
                      font=font_info, anchor="center")
        c.create_text(cx, box_y + box_h * 0.68,
                      text=line2, fill=self.FG_GRAY,
                      font=font_info, anchor="center")

    # ─────────────────────────────────────────────────────────────────
    def _rounded_rect(self, canvas, x1, y1, x2, y2, r, **kw):
        """Rectangle aux coins arrondis."""
        canvas.create_arc(x1,   y1,   x1+2*r, y1+2*r, start=90,  extent=90,  style="pieslice", **kw)
        canvas.create_arc(x2-2*r, y1, x2,     y1+2*r, start=0,   extent=90,  style="pieslice", **kw)
        canvas.create_arc(x1,   y2-2*r, x1+2*r, y2,   start=180, extent=90,  style="pieslice", **kw)
        canvas.create_arc(x2-2*r, y2-2*r, x2, y2,     start=270, extent=90,  style="pieslice", **kw)
        canvas.create_rectangle(x1+r, y1, x2-r, y2, **kw)
        canvas.create_rectangle(x1, y1+r, x2, y2-r, **kw)

    # ─────────────────────────────────────────────────────────────────
    def _blink_loop(self):
        """Fait clignoter le titre toutes les 800 ms."""
        if hasattr(self, "title_id"):
            color = self.FG_WHITE if self._blink else "#FF4444"
            self.canvas.itemconfig(self.title_id, fill=color)
            self._blink = not self._blink
        self.root.after(800, self._blink_loop)


# ─────────────────────────────────────────────────────────────────────
def main():
    args = parse_args()
    detection_time = args.time or datetime.now().strftime("%H:%M:%S")

    root = tk.Tk()
    AlerteSecurite(
        root,
        ip=args.ip,
        mac=args.mac,
        attack=args.attack,
        detection_time=detection_time,
    )
    root.mainloop()


if __name__ == "__main__":
    main()
