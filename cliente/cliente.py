import socket
import ssl
import json
import os

PKI_DIR = os.path.join(os.path.dirname(__file__), "..", "pki")
CA_CERT = os.path.join(PKI_DIR, "ca.crt")
HOST = '127.0.0.1'
PORT = 8443

def create_ssl_context(username):
    # Excepción para profesor1 (el dueño del dispositivo usa client.crt/key)
    if username == "profesor1":
        cert_file = os.path.join(PKI_DIR, "client.crt")
        key_file = os.path.join(PKI_DIR, "client.key")
    else:
        cert_file = os.path.join(PKI_DIR, f"{username}.crt")
        key_file = os.path.join(PKI_DIR, f"{username}.key")

    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        raise FileNotFoundError(f"Faltan certificados mTLS para '{username}'.")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(cafile=CA_CERT)
    context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    context.check_hostname = True
    return context

def main():
    print("=== CLIENTE VPN BYOD U-SECURE ===")
    username = input("Usuario corporativo (profesor1, pas1, investigador1): ").strip()
    if not username:
        username = "profesor1"
        
    password = input(f"Contraseña para '{username}': ").strip()
    if not password and username == "profesor1":
        password = "PassProfesor123!"

    try:
        context = create_ssl_context(username)
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock = context.wrap_socket(raw_sock, server_hostname='localhost')
        ssl_sock.connect((HOST, PORT))
        print("[✓] Handshake mTLS completado.")

        ssl_sock.sendall(json.dumps({"username": username, "password": password}).encode('utf-8'))
        response = json.loads(ssl_sock.recv(1024).decode('utf-8'))
        print(f"[Servidor]: {response.get('message')}")

        if response.get("status") != "SUCCESS":
            ssl_sock.close()
            return

        while True:
            opcion = input("\n1. Enviar PING | 2. Cerrar Sesión (LOGOUT): ").strip()
            if opcion == "1":
                ssl_sock.sendall(json.dumps({"action": "PING"}).encode('utf-8'))
                print(f"[Respuesta VPN]: {json.loads(ssl_sock.recv(1024).decode('utf-8'))}")
            elif opcion == "2":
                ssl_sock.sendall(json.dumps({"action": "LOGOUT"}).encode('utf-8'))
                print(f"[Respuesta VPN]: {json.loads(ssl_sock.recv(1024).decode('utf-8')).get('message')}")
                break
    except Exception as e:
        print(f"[ERROR] {e}")

if __name__ == "__main__":
    main()