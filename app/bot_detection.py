import socket
import ipaddress
import urllib.request
import json
import threading
import logging

# ─────────────────────────────────────────────
# CLOUD IP RANGES — chargés dynamiquement au démarrage
# Sources AWS / GCP / Azure
# ─────────────────────────────────────────────

_cloud_networks = []
_cloud_networks_lock = threading.Lock()

def _fetch_aws_ranges():
    """Récupère les ranges AWS officiels depuis ip-ranges.amazonaws.com"""
    try:
        with urllib.request.urlopen(
            "https://ip-ranges.amazonaws.com/ip-ranges.json", timeout=5
        ) as r:
            data = json.loads(r.read())
        return [
            ipaddress.ip_network(p["ip_prefix"], strict=False)
            for p in data.get("prefixes", [])
        ] + [
            ipaddress.ip_network(p["ipv6_prefix"], strict=False)
            for p in data.get("ipv6_prefixes", [])
        ]
    except Exception as e:
        logging.warning(f"[bot_detection] AWS ranges fetch failed: {e}")
        return []

def _fetch_gcp_ranges():
    """Récupère les ranges Google Cloud officiels"""
    try:
        with urllib.request.urlopen(
            "https://www.gstatic.com/ipranges/cloud.json", timeout=5
        ) as r:
            data = json.loads(r.read())
        ranges = []
        for p in data.get("prefixes", []):
            cidr = p.get("ipv4Prefix") or p.get("ipv6Prefix")
            if cidr:
                ranges.append(ipaddress.ip_network(cidr, strict=False))
        return ranges
    except Exception as e:
        logging.warning(f"[bot_detection] GCP ranges fetch failed: {e}")
        return []

# Fallback hardcodé si les fetches échouent
_FALLBACK_RANGES = [
    "54.0.0.0/8",    "52.0.0.0/8",    "34.0.0.0/8",
    "35.0.0.0/8",    "40.0.0.0/8",    "20.0.0.0/8",
    "66.249.64.0/19","64.233.160.0/19","72.14.192.0/18",
]

def load_cloud_ranges():
    """Appelé une fois au démarrage dans un thread séparé"""
    global _cloud_networks
    ranges = _fetch_aws_ranges() + _fetch_gcp_ranges()
    if not ranges:
        ranges = [ipaddress.ip_network(r) for r in _FALLBACK_RANGES]
    with _cloud_networks_lock:
        _cloud_networks = ranges
    logging.info(f"[bot_detection] Loaded {len(ranges)} cloud IP ranges")


# ─────────────────────────────────────────────
# FONCTIONS DE DÉTECTION
# ─────────────────────────────────────────────

def is_cloud_ip(ip_str: str) -> tuple[bool, str]:
    """
    Vérifie si l'IP appartient à un cloud provider connu.
    Retourne (True, "provider name") ou (False, "")
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        with _cloud_networks_lock:
            for network in _cloud_networks:
                if ip in network:
                    return True, "cloud IP range"
    except ValueError:
        pass
    return False, ""


def reverse_dns_check(ip_str: str) -> tuple[bool, str]:
    """
    Vérifie le reverse DNS pour identifier les bots officiels.
    Slackbot → *.amazonaws.com
    Googlebot → *.googlebot.com
    Bingbot → *.search.msn.com
    
    reverse DNS → forward DNS → doit matcher l'IP originale.
    """
    BOT_DOMAINS = {
        "googlebot.com":       "Googlebot",
        "google.com":          "Google",
        "crawl.yahoo.net":     "YahooBot",
        "search.msn.com":      "Bingbot",
        "amazonaws.com":       "AWS/Slackbot",
        "facebookbot.com":     "Facebookbot",
        "twitterbot.com":      "Twitterbot",
        "linkedinbot.com":     "LinkedInBot",
        "archive.org":         "Wayback Machine",
        "semrushbot.com":      "SemrushBot",
        "ahrefsbot.com":       "AhrefsBot",
    }
    try:
        hostname = socket.gethostbyaddr(ip_str)[0].lower()
        for domain, name in BOT_DOMAINS.items():
            if hostname.endswith(domain):
                # Double vérification forward DNS 
                try:
                    resolved_ip = socket.gethostbyname(hostname)
                    if resolved_ip == ip_str:
                        return True, f"verified reverse DNS: {name} ({hostname})"
                    else:
                        # Hostname existe mais IP ne correspond pas → suspect
                        return True, f"reverse DNS mismatch suspect: {hostname}"
                except:
                    # Pas de forward DNS → quand même flaguer
                    return True, f"reverse DNS: {name} ({hostname})"
    except (socket.herror, socket.gaierror, OSError):
        pass
    return False, ""


def detect_bot(ip: str, user_agent: str, js_enabled: bool,
               webgl_supported: bool, hw_concurrency: int,
               js_exec_time_ms: float, webgl_vendor: str = "",
               webgl_renderer: str = "") -> tuple[bool, str]:
    """
    Détection bot unifiée — par ordre de fiabilité décroissante.
    Retourne (is_bot: bool, reason: str)
    """

    # 1. JS non exécuté → bot quasi-certain
    if not js_enabled:
        return True, "no JS executed"

    # 2. Reverse DNS → méthode la plus fiable pour bots officiels
    rdns_bot, rdns_reason = reverse_dns_check(ip)
    if rdns_bot:
        return True, rdns_reason

    # 3. IP dans range cloud provider
    cloud_bot, cloud_reason = is_cloud_ip(ip)
    if cloud_bot:
        return True, cloud_reason

    # 4. Signaux fingerprint
    if not webgl_supported:
        return True, "no WebGL / headless"

    virtual_gpu_keywords = ["swiftshader", "llvmpipe", "vmware", "virtualbox",
                             "mesa offscreen", "softpipe"]
    renderer_lower = webgl_renderer.lower()
    if any(k in renderer_lower for k in virtual_gpu_keywords):
        return True, f"virtual/software GPU: {webgl_renderer}"

    if hw_concurrency == 0:
        return True, "hw_concurrency=0 / VM"

    if js_exec_time_ms > 0 and js_exec_time_ms < 5:
        return True, f"JS exec too fast: {js_exec_time_ms}ms"

    # 5. UA comme dernier recours seulement pour les cas évidents
    ua_lower = user_agent.lower()
    OBVIOUS_BOT_UA = ["curl/", "wget/", "python-requests", "go-http-client",
                      "java/", "libwww", "scrapy", "headlesschrome"]
    for pattern in OBVIOUS_BOT_UA:
        if pattern in ua_lower:
            return True, f"obvious bot UA: {pattern}"

    return False, ""