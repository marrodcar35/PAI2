import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import ipaddress
import json
import os

PKI_DIR = os.path.dirname(__file__)
SERVER_DIR = os.path.join(PKI_DIR, "..", "server")
USERS_FILE = os.path.join(SERVER_DIR, "users.json")

def generate_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def save_key(key, filename):
    filepath = os.path.join(PKI_DIR, filename)
    with open(filepath, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

def save_cert(cert, filename):
    filepath = os.path.join(PKI_DIR, filename)
    with open(filepath, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

print("[+] Generando CA Raíz...")
ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
ca_subject = ca_issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
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

print("[+] Generando Certificado del Servidor VPN...")
server_key = generate_key()
server_subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
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
        x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
        critical=False,
    )
    .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    .sign(ca_key, hashes.SHA256())
)
save_key(server_key, "server.key")
save_cert(server_cert, "server.crt")

# profesor1 usa client.crt/key, los demás usan {username}.crt/key
roles_usuarios = [
    {"username": "profesor1", "role": "PDI", "pass": "PassProfesor123!", "key_file": "client.key", "cert_file": "client.crt"},
    {"username": "pas1", "role": "PAS", "pass": "PassPas123!", "key_file": "pas1.key", "cert_file": "pas1.crt"},
    {"username": "investigador1", "role": "Investigadores", "pass": "PassInv123!", "key_file": "investigador1.key", "cert_file": "investigador1.crt"}
]

users_db = {}
print("[+] Generando Certificados de Clientes BYOD...")
for user in roles_usuarios:
    username = user["username"]
    u_key = generate_key()
    u_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Universidad U-Secure"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, user["role"]),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])
    u_cert = (
        x509.CertificateBuilder()
        .subject_name(u_subject)
        .issuer_name(ca_subject)
        .public_key(u_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    save_key(u_key, user["key_file"])
    save_cert(u_cert, user["cert_file"])
    users_db[username] = user["pass"]

os.makedirs(SERVER_DIR, exist_ok=True)
with open(USERS_FILE, "w", encoding="utf-8") as f:
    json.dump(users_db, f, indent=4)

print("[✓] PKI y base de usuarios generadas correctamente (sin entradas sintéticas).")