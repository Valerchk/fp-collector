import socket
import ipaddress
import urllib.request
import json
import threading
import logging
import os

# ─────────────────────────────────────────────
# MAXMIND ASN — détection datacenter / cloud
# ─────────────────────────────────────────────

try:
    import geoip2.database
    import geoip2.errors
    _GEOIP2_AVAILABLE = True
except ImportError:
    _GEOIP2_AVAILABLE = False
    logging.warning("[bot_detection] geoip2 not installed — ASN detection disabled")

# Chemin vers la base MaxMind (monté via Docker volume)
MAXMIND_ASN_DB = os.environ.get(
    "MAXMIND_ASN_DB",
    "/app/data/GeoLite2-ASN.mmdb"
)

# ASN orgs connues pour être des datacenters / bots
# Format: substring lowercase de l'org name
DATACENTER_ASN_KEYWORDS = [
    "google",
    "amazon",
    "microsoft",
    "cloudflare",
    "digitalocean",
    "linode",
    "vultr",
    "ovh",
    "hetzner",
    "fastly",
    "akamai",
    "oracle cloud",
    "alibaba",
    "tencent",
    "scaleway",
    "contabo",
    "leaseweb",
]

def get_asn_info(ip_str: str) -> dict:
    """
    Retourne {"asn": "AS15169", "org": "Google LLC"} ou {} si erreur.
    Utilise MaxMind GeoLite2-ASN.
    """
    if not _GEOIP2_AVAILABLE:
        return {}
    if not os.path.exists(MAXMIND_ASN_DB):
        logging.warning(f"[bot_detection] MaxMind DB not found at {MAXMIND_ASN_DB}")
        return {}
    try:
        with geoip2.database.Reader(MAXMIND_ASN_DB) as reader:
            response = reader.asn(ip_str)
            return {
                "asn": f"AS{response.autonomous_system_number}",
                "org": response.autonomous_system_organization or "",
            }
    except geoip2.errors.AddressNotFoundError:
        return {}
    except Exception as e:
        logging.warning(f"[bot_detection] ASN lookup failed for {ip_str}: {e}")
        return {}


def is_datacenter_asn(ip_str: str) -> tuple[bool, str, str]:
    """
    Retourne (is_datacenter, asn, org).
    Ex: (True, "AS15169", "Google LLC")
    """
    info = get_asn_info(ip_str)
    if not info:
        return False, "", ""

    asn = info.get("asn", "")
    org = info.get("org", "")
    org_lower = org.lower()

    for keyword in DATACENTER_ASN_KEYWORDS:
        if keyword in org_lower:
            return True, asn, org

    return False, asn, org


# ─────────────────────────────────────────────
# CLOUD IP RANGES — fallback si MaxMind absent
# ─────────────────────────────────────────────

_cloud_networks = []
_cloud_networks_lock = threading.Lock()

def _fetch_aws_ranges():
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

_FALLBACK_RANGES = [
    "54.0.0.0/8",    "52.0.0.0/8",    "34.0.0.0/8",
    "35.0.0.0/8",    "40.0.0.0/8",    "20.0.0.0/8",
    "66.249.64.0/19","64.233.160.0/19","72.14.192.0/18",
]

def load_cloud_ranges():
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
    BOT_DOMAINS = {
        "googlebot.com":   "Googlebot",
        "google.com":      "Google",
        "crawl.yahoo.net": "YahooBot",
        "search.msn.com":  "Bingbot",
        "amazonaws.com":   "AWS/Slackbot",
        "facebookbot.com": "Facebookbot",
        "twitterbot.com":  "Twitterbot",
        "linkedinbot.com": "LinkedInBot",
        "archive.org":     "Wayback Machine",
        "semrushbot.com":  "SemrushBot",
        "ahrefsbot.com":   "AhrefsBot",
    }
    try:
        hostname = socket.gethostbyaddr(ip_str)[0].lower()
        for domain, name in BOT_DOMAINS.items():
            if hostname.endswith(domain):
                try:
                    resolved_ip = socket.gethostbyname(hostname)
                    if resolved_ip == ip_str:
                        return True, f"verified reverse DNS: {name} ({hostname})"
                    else:
                        return True, f"reverse DNS mismatch suspect: {hostname}"
                except:
                    return True, f"reverse DNS: {name} ({hostname})"
    except (socket.herror, socket.gaierror, OSError):
        pass
    return False, ""