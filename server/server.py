import socket
import ssl
import json
import os
import threading
import logging # Módulo formal para auditoría y trazabilidad (RS4)

# Rutas a las credenciales y ficheros
PKI_DIR = os.path.join(os.path.dirname(__file__), "..", "pki")
CA_CERT = os.path.join(PKI_DIR, "ca.crt")
SERVER_CERT = os.path.join(PKI_DIR, "server.crt")
SERVER_KEY = os.path.join(PKI_DIR, "server.key")
USERS_FILE = os.path.join(os.path.dirname(__file__), "users.json")
LOG_FILE = os.path.join(os.path.dirname(__file__), "audit.log")

HOST = '127.0.0.1'
PORT = 8443

# --- CONFIGURACIÓN DEL SISTEMA DE AUDITORÍA Y LOGS (RS4) ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] [%(threadName)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'), # Guarda en audit.log
        logging.StreamHandler()                           # Muestra en consola
    ]
)

def load_users():
    with open(USERS_FILE, 'r') as f:
        return json.load(f)

def create_ssl_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # RS2: Restricción estricta a TLS 1.3
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
    
    # RS1: Autenticación Mutua (mTLS)
    context.load_verify_locations(cafile=CA_CERT)
    context.verify_mode = ssl.CERT_REQUIRED
    return context

def handle_client_thread(ssl_sock, client_addr, users_db):
    logging.info(f"Conexión entrante aceptada desde {client_addr}")
    
    try:
        # Extraer certificado presentado en mTLS
        client_cert = ssl_sock.getpeercert()
        subject = dict(x[0] for x in client_cert['subject'])
        cn_cliente = subject.get('commonName', 'Desconocido')
        logging.info(f"[{client_addr}] [mTLS OK] Certificado validado. CN: '{cn_cliente}'")
        
        # Capa 2: Autenticación de Aplicación
        raw_data = ssl_sock.recv(1024).decode('utf-8')
        if not raw_data:
            return
        
        credentials = json.loads(raw_data)
        username = credentials.get("username")
        password = credentials.get("password")
        
        # Validar credenciales
        if username in users_db and users_db[username] == password:
            logging.info(f"[{client_addr}] [AUTH SUCCESS] Usuario '{username}' autenticado correctamente.")
            response = {"status": "SUCCESS", "message": f"Bienvenido a la red U-Secure, {username}."}
            ssl_sock.sendall(json.dumps(response).encode('utf-8'))
        else:
            # RS4: Registro explicito de intentos de acceso no autorizados
            logging.warning(f"[{client_addr}] [AUTH FAILED] Intento de acceso no autorizado con usuario '{username}'.")
            response = {"status": "AUTH_FAILED", "message": "Credenciales inválidas."}
            ssl_sock.sendall(json.dumps(response).encode('utf-8'))
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
                # RF4: Cierre seguro y trazabilidad del evento
                logging.info(f"[{client_addr}] [LOGOUT] Sesión cerrada por el usuario '{username}'.")
                ssl_sock.sendall(json.dumps({"status": "DISCONNECTED", "message": "Túnel cerrado."}).encode('utf-8'))
                break

    except Exception as e:
        logging.error(f"[{client_addr}] Excepción en la sesión: {e}")
    finally:
        ssl_sock.close()
        logging.info(f"Conexión con {client_addr} finalizada y socket liberado.")

def main():
    users_db = load_users()
    context = create_ssl_context()
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(300)
    
    logging.info(f"Servidor Gateway VPN U-Secure escuchando en https://{HOST}:{PORT}")
    logging.info("Restricciones: TLS 1.3 + mTLS activado | Auditoría RS4 en 'server/audit.log'")
    
    try:
        while True:
            raw_sock, client_addr = server_socket.accept()
            try:
                ssl_sock = context.wrap_socket(raw_sock, server_side=True)
                client_thread = threading.Thread(
                    target=handle_client_thread, 
                    args=(ssl_sock, client_addr, users_db)
                )
                client_thread.daemon = True
                client_thread.start()
            except ssl.SSLError as e:
                logging.warning(f"[RECHAZADO] Fallo Handshake mTLS con {client_addr}: {e}")
                raw_sock.close()
    except KeyboardInterrupt:
        logging.info("Apagando Servidor VPN...")
    finally:
        server_socket.close()

if __name__ == "__main__":
    main()