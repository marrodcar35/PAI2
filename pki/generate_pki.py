import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import ipaddress

def generate_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def save_key(key, filename):
    with open(filename, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

def save_cert(cert, filename):
    with open(filename, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

# 1. GENERAR CA RAÍZ
print("[+] Generando CA Raíz...")
ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
ca_subject = ca_issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Sevilla"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Universidad U-Secure"),
    x509.NameAttribute(NameOID.COMMON_NAME, "U-Secure Root CA"),
])

ca_cert = (
    x509.CertificateBuilder()
    .subject_name(ca_subject)
    .issuer_name(ca_issuer)
    .public_key(ca_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(ca_key, hashes.SHA256())
)

save_key(ca_key, "ca.key")
save_cert(ca_cert, "ca.crt")

# 2. GENERAR CERTIFICADO DEL SERVIDOR VPN
print("[+] Generando Certificado del Servidor VPN...")
server_key = generate_key()
server_subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Sevilla"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Universidad U-Secure"),
    x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
])

server_cert = (
    x509.CertificateBuilder()
    .subject_name(server_subject)
    .issuer_name(ca_subject)
    .public_key(server_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
    .add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1"))
        ]),
        critical=False,
    )
    .add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
        critical=False
    )
    .sign(ca_key, hashes.SHA256())
)

save_key(server_key, "server.key")
save_cert(server_cert, "server.crt")

# 3. GENERAR CERTIFICADO DEL CLIENTE (BYOD)
print("[+] Generando Certificado del Cliente BYOD...")
client_key = generate_key()
client_subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Sevilla"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Universidad U-Secure"),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "PDI"),
    x509.NameAttribute(NameOID.COMMON_NAME, "profesor1"),
])

client_cert = (
    x509.CertificateBuilder()
    .subject_name(client_subject)
    .issuer_name(ca_subject)
    .public_key(client_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
    .add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
        critical=False
    )
    .sign(ca_key, hashes.SHA256())
)

save_key(client_key, "client.key")
save_cert(client_cert, "client.crt")

print("PKI creada con éxito en la carpeta pki")