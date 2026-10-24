import os
import json
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# --- CONFIGURACIÓN DE RUTAS ---
BASE_DIR = os.path.dirname(__file__)
PKI_DIR = os.path.join(BASE_DIR, "pki")
SERVER_DIR = os.path.join(BASE_DIR, "server")
USERS_FILE = os.path.join(SERVER_DIR, "users.json")
CA_CERT_FILE = os.path.join(PKI_DIR, "ca.crt")
CA_KEY_FILE = os.path.join(PKI_DIR, "ca.key")

def cargar_ca():
    # Cargar el certificado de la CA
    with open(CA_CERT_FILE, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    
    # Cargar la clave privada de la CA
    with open(CA_KEY_FILE, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
        
    return ca_cert, ca_key

def registrar_nuevo_usuario():
    print("=== ALTA DE NUEVO USUARIO (BYOD) ===")
    username = input("Introduce el nuevo nombre de usuario: ").strip()
    password = input("Introduce la contraseña: ").strip()
    rol = input("Introduce el rol (Ej. Alumno, PDI, PAS): ").strip()

    # 1. Cargar la Autoridad de Certificación (CA)
    ca_cert, ca_key = cargar_ca()

    # 2. Generar la clave privada para el nuevo usuario
    print(f"[*] Generando claves criptográficas para {username}...")
    user_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # 3. Construir la identidad del certificado
    user_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Universidad U-Secure"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, rol),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])

    # 4. Crear y firmar el certificado digital
    print("[*] Emitiendo certificado digital...")
    user_cert = (
        x509.CertificateBuilder()
        .subject_name(user_subject)
        .issuer_name(ca_cert.subject) # Firmado por la CA
        .public_key(user_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256()) # La CA pone su "sello"
    )

    # 5. Guardar los archivos del usuario (.key y .crt) en la carpeta pki
    user_key_path = os.path.join(PKI_DIR, f"{username}.key")
    user_cert_path = os.path.join(PKI_DIR, f"{username}.crt")

    with open(user_key_path, "wb") as f:
        f.write(user_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(user_cert_path, "wb") as f:
        f.write(user_cert.public_bytes(serialization.Encoding.PEM))

    # 6. Actualizar la base de datos de usuarios (users.json)
    print("[*] Actualizando base de datos de credenciales...")
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            users_db = json.load(f)
    else:
        users_db = {}

    users_db[username] = password

    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users_db, f, indent=4)

    print(f"[✓] Usuario '{username}' registrado con éxito.")
    print(f"    - Certificado: {user_cert_path}")
    print(f"    - Clave privada: {user_key_path}")

if __name__ == "__main__":
    registrar_nuevo_usuario()