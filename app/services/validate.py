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


def require_tls_hostname(host, f="Server"):
    """HAProxy prüft Zertifikatsnamen nur gegen DNS-Namen, nicht gegen IP-Adressen."""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host
    raise ValueError(
        f"{f}: Zertifikatsprüfung benötigt einen Hostnamen statt der IP-Adresse {host}"
    )


def clean_dns_resolvers(values: list[str]) -> list[str]:
    if not isinstance(values, list) or any(not isinstance(v, str) for v in values):
        raise ValueError("DNS-Server müssen als Liste von IP-Adressen angegeben werden")
    cleaned = []
    for value in values:
        resolver = value.strip()
        host, port = resolver, "53"
        try:
            if resolver.startswith("["):
                host, closing, suffix = resolver[1:].partition("]")
                if not closing or ":" not in host:
                    raise ValueError
                if suffix:
                    if not suffix.startswith(":"):
                        raise ValueError
                    port = suffix[1:]
            elif resolver.count(":") == 1:
                host, port = resolver.split(":")
            if "%" in host or not port.isascii() or not port.isdecimal():
                raise ValueError
            address = ipaddress.ip_address(host)
            port_number = int(port)
            if not 1 <= port_number <= 65535:
                raise ValueError
        except ValueError:
            raise ValueError(
                f"Ungültiger DNS-Server: {value!r}. Erwartet wird eine IPv4-/IPv6-Adresse"
                " mit optionalem Port (1-65535)."
            ) from None
        host = f"[{address}]" if address.version == 6 else str(address)
        resolver = f"{host}:{port_number}"
        if resolver not in cleaned:
            cleaned.append(resolver)
    return cleaned


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
