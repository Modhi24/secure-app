"""Create a self-signed certificate for the local course demonstration."""

from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def main():
    directory = Path(__file__).resolve().parent / ".local-tls"
    directory.mkdir(mode=0o700, exist_ok=True)
    cert_path = directory / "cert.pem"
    key_path = directory / "key.pem"
    if cert_path.exists() or key_path.exists():
        raise SystemExit("TLS files already exist. Reuse the pair or remove both to regenerate.")

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ip_address("127.0.0.1")),
            ]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )
    # Keep the private key local. Only the certificate is shown to clients.
    with key_path.open("xb") as output:
        output.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    print("Created .local-tls/cert.pem and .local-tls/key.pem")


if __name__ == "__main__":
    main()
