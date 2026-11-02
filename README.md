# NetShield SDN

Système de détection et d'isolation automatique des machines compromises, conçu et validé sur l'infrastructure réseau réelle du **Ministère de l'économie et des finances en charge du budget et de la Fonction Publique (MBFP), Cotonou**, dans le cadre d'un stage Cybersécurité & SDN (février–avril 2025).

> Ce projet a fait l'objet d'un mémoire de fin de formation co-signé avec GBEHOLO Mahouna Gajhor Wilson (Institut Universitaire Les Cours Sonou, 2025-2026). Le code de ce dépôt correspond à la partie développée individuellement par TCHEDE Godwin

## Contexte

Les PME représentent plus de 43 % des cibles de cyberattaques dans le monde, en raison de ressources défensives généralement insuffisantes. Au Bénin, ce risque est aggravé par l'absence fréquente de mécanismes automatisés de réponse aux incidents : lorsqu'une machine est infectée, le délai moyen d'identification et d'isolation manuelle par un administrateur varie entre **15 et 180 minutes** — une fenêtre pendant laquelle un attaquant peut se déplacer latéralement, chiffrer des données ou établir une persistance.

**Hypothèse de recherche validée par le projet :** l'intégration étroite d'un système de détection d'intrusion (Suricata) avec un commutateur managé piloté via Telnet permet de réduire ce temps de réponse à moins de deux secondes, avec des logiciels exclusivement open-source, dans un environnement aux ressources limitées représentatif d'une PME béninoise.

## Résultats mesurés (100 tests par métrique, sur équipement physique réel)

| Métrique | Objectif | Valeur mesurée | Écart-type |
|---|---|---|---|
| Détection (Suricata, mode passif) | < 100 ms | **78 ms** | 12 ms |
| Isolation (Python + switch, bout en bout) | < 2 000 ms | **1,3 s** (1,38 s en moyenne pondérée) | 400 ms |
| Basculement port de secours (DHCP) | < 5 s | **200 ms** d'écart-type | — |
| Taux de détection global | > 95 % | **98 %** | — |
| Taux de faux positifs | < 5 % | **2,1 %** | — |

5 catégories d'attaques prioritaires analysées (DDoS, scan de ports, force brute, communication C2, propagation de ransomware), validées sur **7 scénarios d'attaque réels** contre le commutateur physique.

## Architecture

```
Trafic réseau (port mirroring)
     │
     ▼
Suricata 7.0.2 (IDS/IPS, sortie EVE JSON) — détection ping/scan, DDoS,
     │                                       brute force, C2/malware, ransomware
     ▼
sdn_quarantaine.py — orchestrateur (dashboard Flask, WebSocket temps réel)
     │   • Classifie l'attaque (SID Suricata → catégorie)
     │   • Détermine la stratégie de réponse (6 stratégies, voir ci-dessous)
     │   • Localise le port physique de la machine (table MAC/ARP du switch,
     │     connexion Telnet persistante via Netmiko)
     │
     ├──► Switch TP-Link T1600G-28PS (Telnet/Netmiko)
     │        → bascule le port en VLAN 666 (quarantaine)
     │        → active un port de secours (VLAN normal) pour ne pas couper l'utilisateur
     │
     ├──► Serveur DHCP (ISC DHCP) — attribue une IP au port de secours en < 5 s
     ├──► Serveur Samba — restaure l'accès aux fichiers de travail en < 15 s
     │
     ├──► netshield_agent_windows.py (déployé sur chaque poste : SSH → Samba → lien HTTP)
     │        → écran d'alerte plein écran sur la machine isolée
     │
     └──► Bot Telegram — notification temps réel (attaquant, victime, signature, port)
```

## Les 6 stratégies d'isolation

Déterminées selon que la source/destination de l'attaque est locale, externe, ou un équipement protégé (serveur SDN, switch, gateway) :

1. **DUAL_QUARANTINE** — attaquant et victime locaux → isolation des deux
2. **ISOLATE_ATTACKER** — attaquant local, victime externe → isolation de l'attaquant
3. **PROTECT_VICTIM** — attaquant externe, victime locale → protection de la victime
4. **SERVER_LOCAL_ATTACK** — un poste local attaque un serveur protégé → isolation de l'attaquant uniquement
5. **SERVER_EXTERNAL_ATTACK** — un serveur protégé attaqué depuis l'extérieur → journalisation (aucune action possible côté switch sur une IP externe)
6. **EXTERNAL_ONLY** — attaquant et cible externes → journalisation uniquement

## Fichiers

| Fichier | Rôle |
|---|---|
| `sdn_quarantaine.py` | Orchestrateur principal : réception/classification des alertes Suricata, décision de stratégie, pilotage du switch, dashboard Flask, alertes Telegram, déploiement automatique de l'agent |
| `netshield_agent_windows.py` | Agent Windows (compilable en `.exe` via PyInstaller) : reçoit les notifications de l'orchestrateur et affiche un écran d'alerte plein écran sur la machine isolée |
| `alerte_securite.py` | Version autonome de l'écran d'alerte, pilotable en ligne de commande (démonstration / tests visuels sans le reste de la chaîne) |

## Installation

```bash
pip install -r requirements.txt
```

Variables d'environnement nécessaires (aucune valeur par défaut sensible n'est incluse dans le code) :

```
SWITCH_HOST=192.168.0.1
SWITCH_USER=admin
SWITCH_PASS=...
SWITCH_SECRET=...
TELEGRAM_TOKEN=...
TELEGRAM_CHAT_ID=...
```

## Périmètre et avertissement

Ce projet a été conçu pour un déploiement précis (switch TP-Link T1600G-28PS, plan d'adressage et VLANs du réseau du MTFP) — la configuration réseau (IPs, ports, VLANs) est à adapter pour tout autre environnement.

Le déploiement automatique de l'agent (`deploy_agent_all()`) teste une liste d'identifiants par défaut courants (SSH) sur les machines découvertes du réseau **surveillé et administré par l'auteur** dans le cadre du stage — ce n'est pas un outil d'intrusion, mais un mécanisme de déploiement d'agent de supervision sur un parc dont l'administration était autorisée. À adapter/retirer pour tout usage hors de ce contexte précis.

## Stack technique

| Composant | Rôle |
|---|---|
| Python 3.10 | Langage pivot — module de contrôle, forwarder d'alertes, agent utilisateur |
| Flask 2.3 | API REST + dashboard de supervision temps réel (WebSocket) |
| Suricata 7.0.2 | IDS/IPS en mode passif (port mirroring), sortie EVE JSON |
| Netmiko 4.x | Connexion Telnet persistante et pilotage CLI du switch |
| TP-Link T1600G-28PS | Commutateur managé 28 ports — VLANs 802.1Q, port mirroring, MAC statique |
| ISC DHCP Server | Attribution IP automatique sur les ports de secours (< 5 s) |
| Samba 4.x | Continuité d'accès aux fichiers de travail depuis le port de secours |
| Telegram Bot API | Notifications temps réel à l'administrateur |

---

*Auteur : TCHEDE Godwin Erioluwa*
