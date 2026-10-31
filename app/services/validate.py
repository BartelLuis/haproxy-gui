"""Zentrale Eingabevalidierung gegen Command-/Config-/Path-Injection."""
import ipaddress
import re

# Erlaubte Zeichensätze (kein Whitespace, keine Shell-Metazeichen)
RE_NAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.\-]{0,63}$")           # Objektnamen
RE_PATH = re.compile(r"^(?!.*\.\.)[a-zA-Z0-9/_\.\-~]{1,200}$")        # Pfade, kein ..
RE_HOST = re.compile(r"^[a-zA-Z0-9\.\-]{1,253}$")                     # Hostname
RE_DOMAIN = re.compile(r"^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$")
RE_IFACE = re.compile(r"^[a-zA-Z0-9\.\-:]{1,32}$")                    # Netzwerk-Interface


def require(pattern, value, field):
    value = (value or "").strip()
    if not pattern.match(value):
        raise ValueError(f"Ungültiger Wert für {field}: {value!r}")
    return value


def clean_name(v, f="Name"):      return require(RE_NAME, v, f)
def clean_path(v, f="Pfad"):      return require(RE_PATH, v, f)
def clean_host(v, f="Host"):
    value = (v or "").strip()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    if "%" not in value:
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            pass
    if RE_HOST.fullmatch(value):
        return value
    raise ValueError(f"Ungültiger Wert für {f}: {value!r}")


def clean_bind_ip(v, f="Bind-IP"):
    value = (v or "").strip()
    if value == "*":
        return value
    return clean_host(value, f)


def clean_domain(v, f="Domain"):  return require(RE_DOMAIN, v, f)
def clean_iface(v, f="Interface"): return require(RE_IFACE, v, f)


def clean_vip(v, f="VIP"):
    value = (v or "").strip()
    if not value:
        return ""
    entries = [item.strip() for item in re.split(r"[\n,]+", value)]
    cleaned = []
    try:
        for item in entries:
            if not item or "%" in item:
                raise ValueError
            ipaddress.ip_interface(item)
            if item not in cleaned:
                cleaned.append(item)
    except ValueError:
        raise ValueError(f"Ungültiger Wert für {f}: {value!r}") from None
    return "\n".join(cleaned)


def no_newline(value, field="Wert"):
    value = value or ""
    if "\n" in value or "\r" in value:
        raise ValueError(f"{field} darf keinen Zeilenumbruch enthalten")
    return value
