"""
Validation et normalisation des cibles de scan.

Objectif : refuser dès la création les cibles invalides ou introuvables,
pour ne jamais produire un rapport « aucune vulnérabilité » sur une cible
qui n'a en réalité jamais été scannée.
"""

import ipaddress
import re
import socket
from urllib.parse import urlparse

# Types qui attendent une URL http(s)
URL_TYPES = {"web", "api", "authenticated_web"}
# Types qui attendent un nom de domaine (pas d'IP)
DOMAIN_TYPES = {"subdomain", "osint"}
# Types qui acceptent un domaine ou une IP
HOST_TYPES = {"network", "cti"}

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_RANGE_RE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$")
_CIDR_RE = re.compile(r"^[\d.]+/\d{1,2}$")


class InvalidTarget(ValueError):
    """Cible refusée ; le message est destiné à l'utilisateur (en français)."""


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _is_hostname(host: str) -> bool:
    if host == "localhost":
        return True
    if len(host) > 253 or "." not in host:
        return False
    labels = host.split(".")
    if not all(_LABEL_RE.match(l) for l in labels):
        return False
    # Le TLD ne peut pas être purement numérique
    return not labels[-1].isdigit()


def _extract_host(raw: str) -> str:
    """Récupère l'hôte d'une saisie qui peut être une URL, un domaine ou une IP."""
    candidate = raw if "://" in raw else f"//{raw}"
    parsed = urlparse(candidate)
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    return host


_PRIVATE_MSG = (
    "SuturaSec n'analyse que des cibles publiques sur Internet : les adresses privées, "
    "locales ou réservées (127.0.0.1, 10.x, 192.168.x, 169.254.x…) sont refusées."
)


def _check_host(host: str, check_dns: bool) -> None:
    """Vérifie que host existe (DNS) et ne pointe que vers des adresses publiques."""
    from app.core.egress import blocked_addresses, is_blocked_ip, private_targets_allowed

    allow_private = private_targets_allowed()
    if _is_ip(host):
        if not allow_private and is_blocked_ip(host):
            raise InvalidTarget(f"L'adresse {host} n'est pas publique. {_PRIVATE_MSG}")
        return
    if host == "localhost" and not allow_private:
        raise InvalidTarget(f"« localhost » désigne le serveur SuturaSec lui-même. {_PRIVATE_MSG}")
    if not check_dns:
        return
    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(5)
    try:
        blocked = blocked_addresses(host)
    except (socket.gaierror, socket.timeout, UnicodeError, OSError):
        raise InvalidTarget(
            f"Le domaine « {host} » est introuvable (aucune résolution DNS). "
            "Vérifiez l'orthographe de la cible."
        )
    finally:
        socket.setdefaulttimeout(previous)
    if blocked and not allow_private:
        raise InvalidTarget(
            f"Le domaine « {host} » pointe vers une adresse non publique ({', '.join(blocked)}). "
            f"{_PRIVATE_MSG}"
        )


def _check_range(addresses, label: str) -> None:
    from app.core.egress import is_blocked_ip, private_targets_allowed
    if private_targets_allowed():
        return
    blocked = [str(a) for a in addresses if is_blocked_ip(str(a))]
    if blocked:
        raise InvalidTarget(f"La plage {label} contient des adresses non publiques ({blocked[0]}…). {_PRIVATE_MSG}")


def normalize_target(scan_type: str, raw: str, check_dns: bool = True) -> str:
    """
    Valide la cible selon le type de scan et retourne sa forme normalisée.
    Lève InvalidTarget avec un message explicite si la cible est refusée.
    """
    value = (raw or "").strip()
    if not value:
        raise InvalidTarget("Veuillez saisir une cible à analyser.")
    if any(c.isspace() for c in value):
        raise InvalidTarget(
            f"« {value} » n'est pas une cible valide : elle ne doit pas contenir d'espaces."
        )

    if scan_type in URL_TYPES:
        if "://" not in value:
            value = f"https://{value}"
        parsed = urlparse(value)
        if parsed.scheme not in ("http", "https"):
            raise InvalidTarget("L'URL doit commencer par http:// ou https://.")
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host or not (_is_hostname(host) or _is_ip(host)):
            raise InvalidTarget(
                f"« {raw.strip()} » n'est pas une URL valide. Exemple : https://example.com"
            )
        normalized = value.rstrip("/") if parsed.path in ("", "/") and not parsed.query else value
    elif scan_type == "network" and (_RANGE_RE.match(value) or _CIDR_RE.match(value)):
        # Plage CIDR (192.168.1.0/24) ou plage d'IP (192.168.1.1-20) : pas de DNS à vérifier
        m = _RANGE_RE.match(value)
        if m:
            start, end = int(m.group(2)), int(m.group(3))
            try:
                ipaddress.ip_address(f"{m.group(1)}{start}")
                ipaddress.ip_address(f"{m.group(1)}{end}")
            except ValueError:
                raise InvalidTarget(f"« {value} » n'est pas une plage d'IP valide. Exemple : 192.168.1.1-20")
            if start > end:
                raise InvalidTarget(f"« {value} » : le début de la plage doit être inférieur à la fin.")
            _check_range(
                (ipaddress.ip_address(f"{m.group(1)}{i}") for i in range(start, end + 1)), value)
        else:
            try:
                net = ipaddress.ip_network(value, strict=False)
            except ValueError:
                raise InvalidTarget(f"« {value} » n'est pas une plage CIDR valide. Exemple : 192.168.1.0/24")
            if net.num_addresses > 256:
                raise InvalidTarget(
                    f"La plage {value} est trop large ({net.num_addresses} adresses). "
                    "Maximum : /24 (256 adresses)."
                )
            _check_range(net, value)
        return value
    else:
        host = _extract_host(value)
        if scan_type in DOMAIN_TYPES:
            if _is_ip(host):
                raise InvalidTarget(
                    "Ce type d'analyse attend un nom de domaine, pas une adresse IP. Exemple : example.com"
                )
            if not host or host == "localhost" or not _is_hostname(host):
                raise InvalidTarget(
                    f"« {raw.strip()} » n'est pas un nom de domaine valide. Exemple : example.com"
                )
        else:  # HOST_TYPES
            if not host or not (_is_hostname(host) or _is_ip(host)):
                raise InvalidTarget(
                    f"« {raw.strip()} » n'est ni un domaine ni une adresse IP valide. "
                    "Exemple : example.com ou une adresse IP publique"
                )
        normalized = host

    _check_host(host, check_dns)
    return normalized
