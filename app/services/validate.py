"""Zentrale Eingabevalidierung gegen Command-/Config-/Path-Injection."""
import re

# Erlaubte Zeichensätze (kein Whitespace, keine Shell-Metazeichen)
RE_NAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.\-]{0,63}$")           # Objektnamen
RE_PATH = re.compile(r"^(?!.*\.\.)[a-zA-Z0-9/_\.\-~]{1,200}$")        # Pfade, kein ..
RE_HOST = re.compile(r"^[a-zA-Z0-9\.\-]{1,253}$")                     # Hostname/IP
RE_DOMAIN = re.compile(r"^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$")
RE_IFACE = re.compile(r"^[a-zA-Z0-9\.\-:]{1,32}$")                    # Netzwerk-Interface
RE_VIP = re.compile(r"^[0-9a-fA-F\.:]+(/\d{1,3})?$")                  # IP oder IP/CIDR


def require(pattern, value, field):
    value = (value or "").strip()
    if not pattern.match(value):
        raise ValueError(f"Ungültiger Wert für {field}: {value!r}")
    return value


def clean_name(v, f="Name"):      return require(RE_NAME, v, f)
def clean_path(v, f="Pfad"):      return require(RE_PATH, v, f)
def clean_host(v, f="Host"):      return require(RE_HOST, v, f)
def clean_domain(v, f="Domain"):  return require(RE_DOMAIN, v, f)
def clean_iface(v, f="Interface"): return require(RE_IFACE, v, f)
def clean_vip(v, f="VIP"):        return require(RE_VIP, v, f)


def no_newline(value, field="Wert"):
    value = value or ""
    if "\n" in value or "\r" in value:
        raise ValueError(f"{field} darf keinen Zeilenumbruch enthalten")
    return value
