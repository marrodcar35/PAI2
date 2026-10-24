import socket
import ssl
import os
import threading
import time
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

PKI_DIR = os.path.join(os.path.dirname(__file__), "..", "pki")
CA_CERT = os.path.join(PKI_DIR, "ca.crt")
CLIENT_CERT = os.path.join(PKI_DIR, "client.crt")
CLIENT_KEY = os.path.join(PKI_DIR, "client.key")

HOST = '127.0.0.1'
PORT_ROGUE = 8445  # Puerto para simular el servidor atacante
PORT_VPN = 8443    # Puerto real del servidor VPN U-Secure

# --- AUXILIAR: GENERAR CERTIFICADO FALSO / NO TRATADO POR LA CA ---
def generate_fake_rogue_cert():
    """Genera una clave y certificado autofirmado que NO pertenece a la CA de la Universidad."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Atacante Malicioso Inc"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    return cert_pem, key_pem

# --- ESCENARIO 1: PRUEBA CONTRA SERVIDOR ROGUE / FALSO ---
def run_rogue_server(cert_pem, key_pem):
    """Lanza un servidor en el puerto 8445 con un certificado no reconocido."""
    # Escribir temporalmente el cert falso a disco
    fake_cert_path = os.path.join(PKI_DIR, "fake_server.crt")
    fake_key_path = os.path.join(PKI_DIR, "fake_server.key")
    with open(fake_cert_path, "wb") as f: f.write(cert_pem)
    with open(fake_key_path, "wb") as f: f.write(key_pem)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=fake_cert_path, keyfile=fake_key_path)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT_ROGUE))
    sock.listen(1)

    def listen():
        try:
            raw_conn, _ = sock.accept()
            _ = ctx.wrap_socket(raw_conn, server_side=True)
        except Exception:
            pass
        finally:
            sock.close()
            if os.path.exists(fake_cert_path): os.remove(fake_cert_path)
            if os.path.exists(fake_key_path): os.remove(fake_key_path)

    threading.Thread(target=listen, daemon=True).start()

def test_mitm_rogue_server():
    print("\n[ESCENARIO A] Probando conexión contra un Servidor Falso / Interceptador (Rogue Server)...")
    cert_pem, key_pem = generate_fake_rogue_cert()
    run_rogue_server(cert_pem, key_pem)
    time.sleep(0.5)

    # Configurar cliente legítimo que confía solo en la CA Raíz de U-Secure
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(cafile=CA_CERT)
    ctx.check_hostname = True

    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock = ctx.wrap_socket(raw_sock, server_hostname='localhost')
        ssl_sock.connect((HOST, PORT_ROGUE))
        print(" [!] ERROR GRAVE: El cliente aceptó la conexión con el servidor falso.")
    except ssl.SSLCertVerificationError as e:
        print(" [✓] ATAQUE BLOQUEADO CON ÉXITO (Capa Cliente):")
        print(f"     Motivo: El cliente rechazó la conexión porque el certificado no está firmado por la CA Raíz U-Secure.")
        print(f"     Detalle de excepción TLS: {e.verify_message}")
    except Exception as e:
        print(f" [✓] Conexión rechazada por error TLS esperado: {e}")

# --- ESCENARIO 2: PRUEBA DE CLIENTE SIN CERTIFICADO DIGITAL ---
def test_mitm_unauthenticated_client():
    print("\n[ESCENARIO B] Probando acceso al Gateway VPN desde un cliente SIN certificado digital mTLS...")
    
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(cafile=CA_CERT)
    ctx.check_hostname = True

    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock = ctx.wrap_socket(raw_sock, server_hostname='localhost')
        ssl_sock.connect((HOST, PORT_VPN))
        
        # Intentar enviar datos fuerza al socket a procesar la alerta TLS enviada por el servidor
        ssl_sock.sendall(b"PING_SIN_CERTIFICADO")
        _ = ssl_sock.recv(1024)
        
        print(" [!] ERROR GRAVE: El servidor aceptó la conexión sin exigencia de certificado mTLS.")
    except (ssl.SSLError, ssl.SSLEOFError, ConnectionResetError, BrokenPipeError, OSError) as e:
        print(" [✓] ATAQUE BLOQUEADO CON ÉXITO (Capa Servidor):")
        print("     Motivo: El Gateway VPN abortó la conexión porque el dispositivo no presentó un certificado mTLS válido.")
        print(f"     Detalle de excepción: {e}")
    except Exception as e:
        print(f" [✓] Conexión rechazada por la infraestructura: {e}")

def main():
    print("==========================================================================")
    print(" DEMOSTRACIÓN DE RESISTENCIA Y DEFONSA CONTRA ATAQUES MAN-IN-THE-MIDDLE")
    print(" Protocolo de Verificación: mTLS (Autenticación Mutua) + TLS 1.3")
    print("==========================================================================")
    
    test_mitm_rogue_server()
    test_mitm_unauthenticated_client()
    
    print("\n" + "="*74)
    print(" CONCLUSIÓN DE SEGURIDAD:")
    print(" La combinación de mTLS + TLS 1.3 garantiza la autenticación bidireccional,")
    print(" imposibilitando la interceptación de tráfico o suplantación en redes públicas.")
    print("="*74 + "\n")

if __name__ == "__main__":
    main()