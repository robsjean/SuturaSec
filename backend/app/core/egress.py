"""
Protection anti-SSRF des scanners.

SuturaSec émet des requêtes vers des cibles choisies par les utilisateurs. Sans garde,
un utilisateur pourrait viser le serveur lui-même (127.0.0.1), le réseau interne de
l'hébergeur (10.x, 172.16.x, 192.168.x) ou le service de métadonnées cloud
(169.254.169.254) — directement, via une redirection HTTP, ou via un domaine dont le
DNS change entre la validation et le scan (DNS rebinding).

Deux couches :
  1. is_blocked_ip() / resolve_public() : validation explicite (création du scan,
     re-vérification au démarrage du scan) avec un message clair.
  2. install_egress_guard() : remplace socket.getaddrinfo pour refuser toute connexion
     sortante vers une adresse non publique, quelle que soit la bibliothèque (httpx,
     socket.create_connection, ssl…). Couvre les redirections et le DNS rebinding.

En développement local, ALLOW_PRIVATE_TARGETS=true désactive les deux couches pour
pouvoir scanner une application qui tourne sur la machine.
"""

import ipaddress
import socket
from typing import List

_original_getaddrinfo = socket.getaddrinfo
_guard_installed = False


class BlockedDestination(OSError):
    """Connexion refusée : la destination n'est pas une adresse publique."""


def private_targets_allowed() -> bool:
    from app.config import settings
    return bool(settings.ALLOW_PRIVATE_TARGETS)


def is_blocked_ip(ip_str: str) -> bool:
    """True si l'adresse n'est pas routable publiquement (privée, locale, réservée…)."""
    try:
        ip = ipaddress.ip_address(ip_str.split("%", 1)[0])   # retire l'éventuel scope IPv6
    except ValueError:
        return True   # adresse illisible : on refuse par prudence
    if isinstance(ip, ipaddress.IPv6Address):
        # ::ffff:127.0.0.1 et 2002:7f00:1:: (6to4) encapsulent une IPv4 : on juge celle-ci
        if ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        elif ip.sixtofour:
            ip = ip.sixtofour
    return (not ip.is_global) or ip.is_multicast


def resolve_all(host: str) -> List[str]:
    """Toutes les adresses de host (sans passer par la garde, pour pouvoir expliquer un refus)."""
    infos = _original_getaddrinfo(host, None)
    return sorted({info[4][0] for info in infos})


def blocked_addresses(host: str) -> List[str]:
    """Adresses non publiques parmi celles de host (liste vide = cible publique)."""
    return [a for a in resolve_all(host) if is_blocked_ip(a)]


def _guarded_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    results = _original_getaddrinfo(host, port, family, type, proto, flags)
    if flags & socket.AI_PASSIVE:
        return results          # résolution pour écouter (bind), pas pour se connecter
    for res in results:
        addr = res[4][0]
        if is_blocked_ip(addr):
            raise BlockedDestination(
                f"Connexion bloquée vers {host} ({addr}) : SuturaSec n'analyse que des "
                "adresses publiques (protection anti-SSRF)."
            )
    return results


def install_egress_guard() -> None:
    """À appeler une fois au démarrage de l'application."""
    global _guard_installed
    if _guard_installed or private_targets_allowed():
        return
    socket.getaddrinfo = _guarded_getaddrinfo
    _guard_installed = True
