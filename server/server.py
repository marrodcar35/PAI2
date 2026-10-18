import socket
import ssl
import json
import os

# Rutas a las credenciales criptográficas
PKI_DIR = os.path.join(os.path.dirname(__file__), "..", "pki")
CA_CERT = os.path.join(PKI_DIR, "ca.crt")
SERVER_CERT = os.path.join(PKI_DIR, "server.crt")
SERVER_KEY = os.path.join(PKI_DIR, "server.key")
USERS_FILE = os.path.join(os.path.dirname(__file__), "users.json")

HOST = '127.0.0.1'
PORT = 8443

def load_users():
    with open(USERS_FILE, 'r') as f:
        return json.load(f)

def create_ssl_context():
    # Contexto exclusivo de Servidor TLS
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    
    # RS2: Restricción estricta a TLS 1.3
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    
    # Cargar certificado y clave privada del servidor
    context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
    
    # RS1: Autenticación Mutua (mTLS)
    # Exigir y verificar obligatoriamente el certificado del dispositivo cliente
    context.load_verify_locations(cafile=CA_CERT)
    context.verify_mode = ssl.CERT_REQUIRED
    
    return context

def handle_client(ssl_sock, client_addr, users_db):
    print(f"\n[+] Nueva conexión entrante desde {client_addr}")
    
    # Extraer y verificar el certificado que presentó el cliente en el handshake mTLS
    client_cert = ssl_sock.getpeercert()
    subject = dict(x[0] for x in client_cert['subject'])
    cn_cliente = subject.get('commonName', 'Desconocido')
    print(f"[mTLS OK] Dispositivo autenticado. CN del Certificado: '{cn_cliente}'")
    
    try:
        # Capa 2: Autenticación de Aplicación (Usuario / Contraseña)
        raw_data = ssl_sock.recv(1024).decode('utf-8')
        if not raw_data:
            return
        
        credentials = json.loads(raw_data)
        username = credentials.get("username")
        password = credentials.get("password")
        
        # Validar credenciales
        if username in users_db and users_db[username] == password:
            print(f"[AUTH OK] Usuario '{username}' autenticado correctamente.")
            response = {"status": "SUCCESS", "message": f"Bienvenido a la red U-Secure, {username}."}
            ssl_sock.sendall(json.dumps(response).encode('utf-8'))
        else:
            print(f"[AUTH ERROR] Intento fallido para el usuario '{username}'.")
            response = {"status": "AUTH_FAILED", "message": "Credenciales inválidas."}
            ssl_sock.sendall(json.dumps(response).encode('utf-8'))
            ssl_sock.close()
            return

        # Bucle de atención dentro del túnel seguro
        while True:
            data = ssl_sock.recv(1024).decode('utf-8')
            if not data:
                break
            
            msg = json.loads(data)
            action = msg.get("action")
            
            if action == "PING":
                ssl_sock.sendall(json.dumps({"status": "PONG", "payload": "Conexión VPN activa"}).encode('utf-8'))
            
            elif action == "LOGOUT":
                # RF4: Cierre seguro y desmontaje del túnel
                print(f"[LOGOUT] El usuario '{username}' ha cerrado la sesión.")
                ssl_sock.sendall(json.dumps({"status": "DISCONNECTED", "message": "Túnel cerrado."}).encode('utf-8'))
                break

    except Exception as e:
        print(f"[ERROR] Excepción en la sesión: {e}")
    finally:
        ssl_sock.close()
        print(f"[-] Conexión con {client_addr} finalizada.")

def main():
    users_db = load_users()
    context = create_ssl_context()
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    
    print(f"[✓] Servidor Gateway VPN U-Secure escuchando en https://{HOST}:{PORT}")
    print("[+] Restricciones activadas: TLS 1.3 + mTLS (Autenticación Mutua Requerida)")
    
    try:
        while True:
            raw_sock, client_addr = server_socket.accept()
            # Envolver el socket estándar en el contexto seguro TLS 1.3 / mTLS
            try:
                ssl_sock = context.wrap_socket(raw_sock, server_side=True)
                handle_client(ssl_sock, client_addr, users_db)
            except ssl.SSLError as e:
                print(f"[RECHAZADO] Fallo en Handshake mTLS con {client_addr}: {e}")
                raw_sock.close()
    except KeyboardInterrupt:
        print("\n[!] Apagando Servidor VPN...")
    finally:
        server_socket.close()

if __name__ == "__main__":
    main()