import socket
import ssl
import json
import os

# Rutas a las credenciales criptográficas 
PKI_DIR = os.path.join(os.path.dirname(__file__), "..", "pki")
CA_CERT = os.path.join(PKI_DIR, "ca.crt")
CLIENT_CERT = os.path.join(PKI_DIR, "client.crt")
CLIENT_KEY = os.path.join(PKI_DIR, "client.key")

HOST = '127.0.0.1'
PORT = 8443

def create_ssl_context():
    # Contexto exclusivo para Cliente TLS
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    
    # RS2: Restricción estricta a TLS 1.3
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    
    # Cargar certificado de la CA para verificar al servidor VPN
    context.load_verify_locations(cafile=CA_CERT)
    
    # RS1: Autenticación Mutua (mTLS) -> Cargar certificado y clave del cliente BYOD
    context.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
    
    # Exigir verificación estricta del nombre del host del servidor
    context.check_hostname = True
    
    return context

def main():
    context = create_ssl_context()
    
    print(f"[+] Conectando al Gateway VPN U-Secure en https://{HOST}:{PORT}...")
    
    try:
        # Crear socket TCP nativo
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Envolver en TLS 1.3 mTLS
        ssl_sock = context.wrap_socket(raw_sock, server_hostname='localhost')
        ssl_sock.connect((HOST, PORT))
        
        print("[✓] Handshake mTLS completado con éxito. Canal cifrado TLS 1.3 establecido.")
        
        # Capa 2: Autenticación de Aplicación (Credenciales)
        username = input("Usuario corporativo (ej. profesor1): ") or "profesor1"
        password = input("Contraseña: ") or "PassProfesor123!"
        
        auth_payload = {"username": username, "password": password}
        ssl_sock.sendall(json.dumps(auth_payload).encode('utf-8'))
        
        response = json.loads(ssl_sock.recv(1024).decode('utf-8'))
        print(f"[Servidor]: {response.get('message')}")
        
        if response.get("status") != "SUCCESS":
            print("[!] Autenticación fallida. Cerrando conexión.")
            ssl_sock.close()
            return

        # Simulación de tráfico seguro dentro del túnel
        print("\n--- TÚNEL VPN ACTIVO ---")
        print("1. Enviar PING")
        print("2. Cerrar Sesión (LOGOUT)")
        
        while True:
            opcion = input("\nElige una opción (1/2): ")
            if opcion == "1":
                ping_payload = {"action": "PING"}
                ssl_sock.sendall(json.dumps(ping_payload).encode('utf-8'))
                res = json.loads(ssl_sock.recv(1024).decode('utf-8'))
                print(f"[Respuesta VPN]: {res}")
            
            elif opcion == "2":
                # RF4: Cierre seguro y desmontaje del túnel
                logout_payload = {"action": "LOGOUT"}
                ssl_sock.sendall(json.dumps(logout_payload).encode('utf-8'))
                res = json.loads(ssl_sock.recv(1024).decode('utf-8'))
                print(f"[Respuesta VPN]: {res.get('message')}")
                break
                
    except ssl.SSLError as e:
        print(f"[ERROR TLS/mTLS] No se pudo establecer la conexión segura: {e}")
    except Exception as e:
        print(f"[ERROR] Ocurrió un fallo: {e}")
    finally:
        ssl_sock.close()
        print("[-] Túnel VPN desmontado y socket cerrado.")

if __name__ == "__main__":
    main()