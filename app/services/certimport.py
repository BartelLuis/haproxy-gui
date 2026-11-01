"""Validierung und Normalisierung manuell importierter TLS-Zertifikate."""

import base64
import binascii
from dataclasses import dataclass, field
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

MAX_IMPORT_BYTES = 1024 * 1024
MAX_CHAIN_CERTIFICATES = 32


@dataclass(frozen=True)
class ImportedCertificate:
    domains: list[str]
    not_after: str
    cert_pem: bytes
    key_pem: bytes = field(repr=False)


def _check_size(size: int) -> None:
    if size > MAX_IMPORT_BYTES:
        raise ValueError("Zertifikatsimport darf insgesamt höchstens 1 MiB groß sein")


def _normalize(
    certificates: list[x509.Certificate], key: PrivateKeyTypes
) -> ImportedCertificate:
    certificates = list({
        cert.public_bytes(serialization.Encoding.DER): cert for cert in certificates
    }.values())
    if len(certificates) > MAX_CHAIN_CERTIFICATES:
        raise ValueError(
            f"Eine Zertifikatskette darf höchstens {MAX_CHAIN_CERTIFICATES} Zertifikate enthalten"
        )
    public_key = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    matching = [
        cert for cert in certificates
        if cert.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ) == public_key
    ]
    if not matching:
        raise ValueError("Zertifikat und privater Schlüssel passen nicht zusammen")
    if len(matching) != 1:
        raise ValueError("Bitte genau ein zum Schlüssel passendes Server-Zertifikat importieren")
    leaf = matching[0]
    chain = [leaf]
    remaining = [cert for cert in certificates if cert != leaf]
    while remaining:
        issuers = [cert for cert in remaining if cert.subject == chain[-1].issuer]
        if len(issuers) != 1:
            raise ValueError("Die Zertifikatskette ist nicht eindeutig oder enthält fremde Zertifikate")
        issuer = issuers[0]
        try:
            chain[-1].verify_directly_issued_by(issuer)
        except (ValueError, InvalidSignature, UnsupportedAlgorithm) as exc:
            raise ValueError("Die Signatur der Zertifikatskette ist ungültig") from exc
        chain.append(issuer)
        remaining.remove(issuer)

    now = datetime.now(timezone.utc)
    for cert in chain:
        if cert.not_valid_after_utc <= now:
            raise ValueError("Das Zertifikat oder seine Zertifikatskette ist abgelaufen")
        if cert.not_valid_before_utc > now:
            raise ValueError("Das Zertifikat oder seine Zertifikatskette ist noch nicht gültig")
    try:
        san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        domains = [
            str(attr.value).strip().lower()
            for attr in leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        ]
    else:
        domains = [name.lower() for name in san.get_values_for_type(x509.DNSName)]
        domains += [str(address) for address in san.get_values_for_type(x509.IPAddress)]
    domains = list(dict.fromkeys(domain for domain in domains if domain))
    if not domains:
        raise ValueError("Das Zertifikat enthält keinen DNS-Namen und keine IP-Adresse")
    return ImportedCertificate(
        domains=domains,
        not_after=leaf.not_valid_after_utc.isoformat(),
        cert_pem=b"".join(cert.public_bytes(serialization.Encoding.PEM) for cert in chain),
        key_pem=key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


def parse_pem(
    certificate_pem: str, private_key_pem: str = "", chain_pem: str = "", password: str = ""
) -> ImportedCertificate:
    certificate_data = certificate_pem.encode("utf-8")
    key_data = private_key_pem.encode("utf-8")
    chain_data = chain_pem.encode("utf-8")
    _check_size(len(certificate_data) + len(key_data) + len(chain_data))
    if not certificate_data.strip():
        raise ValueError("Zertifikat bzw. Fullchain im PEM-Format erforderlich")
    try:
        certificates = x509.load_pem_x509_certificates(certificate_data)
        if chain_data.strip():
            certificates += x509.load_pem_x509_certificates(chain_data)
    except ValueError as exc:
        raise ValueError("Ungültiges PEM-Zertifikat oder ungültige Zertifikatskette") from exc
    try:
        key = serialization.load_pem_private_key(
            key_data if key_data.strip() else certificate_data,
            password=password.encode("utf-8") if password else None,
        )
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise ValueError("Privater PEM-Schlüssel ungültig, nicht unterstützt oder Passwort falsch") from exc
    try:
        return _normalize(certificates, key)
    except (x509.DuplicateExtension, x509.UnsupportedGeneralNameType, UnsupportedAlgorithm) as exc:
        raise ValueError("Das Zertifikat enthält ungültige oder nicht unterstützte Angaben") from exc


def parse_pkcs12(data_base64: str, password: str = "") -> ImportedCertificate:
    if len(data_base64) > ((MAX_IMPORT_BYTES + 2) // 3) * 4:
        _check_size(MAX_IMPORT_BYTES + 1)
    try:
        data = base64.b64decode(data_base64, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("PFX/P12-Datei muss als gültiges Base64 übertragen werden") from exc
    _check_size(len(data))
    try:
        key, certificate, chain = pkcs12.load_key_and_certificates(
            data, password=password.encode("utf-8") if password else None
        )
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise ValueError("PFX/P12-Datei ungültig, nicht unterstützt oder Passwort falsch") from exc
    if key is None or certificate is None:
        raise ValueError("PFX/P12-Datei muss ein Zertifikat und seinen privaten Schlüssel enthalten")
    try:
        return _normalize([certificate, *chain], key)
    except (x509.DuplicateExtension, x509.UnsupportedGeneralNameType, UnsupportedAlgorithm) as exc:
        raise ValueError("Das Zertifikat enthält ungültige oder nicht unterstützte Angaben") from exc
