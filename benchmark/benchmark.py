import socket
import ssl
import json
import os
import time
import statistics
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- CONFIGURACIÓN DE RUTAS Y PARÁMETROS ---
PKI_DIR = os.path.join(os.path.dirname(__file__), "..", "pki")
CA_CERT = os.path.join(PKI_DIR, "ca.crt")

# Apunta al certificado y clave válidos generados para profesor1
CLIENT_CERT = os.path.join(PKI_DIR, "client.crt")
CLIENT_KEY = os.path.join(PKI_DIR, "client.key")

HOST = '127.0.0.1'
PORT_VPN = 8443        # Puerto del Servidor VPN (TLS 1.3 + mTLS)
PORT_PLAIN = 8444      # Puerto auxiliar para medir tráfico plano sin cifrar
PINGS_PER_CLIENT = 5   # Peticiones enviadas por cada socket
NIVELES_CARGA = [50, 100, 200, 300] # Evaluaciones escalonadas de concurrencia

# --- SERVIDOR AUXILIAR TCP PLANO (PARA MEDIR LÍNEA BASE SIN CIFRAR) ---
def start_plain_tcp_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT_PLAIN))
    server.listen(300)
    
    def handle_plain_client(conn):
        try:
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                msg = json.loads(data.decode('utf-8'))
                if msg.get("action") == "AUTH":
                    conn.sendall(json.dumps({"status": "SUCCESS"}).encode('utf-8'))
                elif msg.get("action") == "PING":
                    conn.sendall(json.dumps({"status": "PONG"}).encode('utf-8'))
                elif msg.get("action") == "LOGOUT":
                    conn.sendall(json.dumps({"status": "DISCONNECTED"}).encode('utf-8'))
                    break
        except Exception:
            pass
        finally:
            conn.close()

    def listen_loop():
        while True:
            try:
                conn, _ = server.accept()
                threading.Thread(target=handle_plain_client, args=(conn,), daemon=True).start()
            except Exception:
                break

    t = threading.Thread(target=listen_loop, daemon=True)
    t.start()
    return server

# --- CONTEXTO TLS 1.3 CLIENTE ---
def get_ssl_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(cafile=CA_CERT)
    context.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
    context.check_hostname = True
    return context

# --- SIMULACIÓN DE HILO VPN (TLS 1.3 + mTLS) ---
def run_vpn_client(client_id, ssl_context):
    metrics = {
        "client_id": client_id,
        "handshake_time_ms": 0.0,
        "auth_time_ms": 0.0,
        "ping_rtts_ms": [],
        "success": False,
        "error": None
    }
    
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock = ssl_context.wrap_socket(raw_sock, server_hostname='localhost')
        
        # 1. Conexión + Handshake mTLS
        t_start_hs = time.perf_counter()
        ssl_sock.connect((HOST, PORT_VPN))
        metrics["handshake_time_ms"] = (time.perf_counter() - t_start_hs) * 1000.0

        # 2. Autenticación de Aplicación
        t_start_auth = time.perf_counter()
        auth_payload = {"username": "profesor1", "password": "PassProfesor123!"}
        ssl_sock.sendall(json.dumps(auth_payload).encode('utf-8'))
        auth_res = json.loads(ssl_sock.recv(1024).decode('utf-8'))
        metrics["auth_time_ms"] = (time.perf_counter() - t_start_auth) * 1000.0

        if auth_res.get("status") != "SUCCESS":
            metrics["error"] = "Error en Autenticación"
            ssl_sock.close()
            return metrics

        # 3. Medir RTT dentro del túnel
        for _ in range(PINGS_PER_CLIENT):
            t_ping_start = time.perf_counter()
            ssl_sock.sendall(json.dumps({"action": "PING"}).encode('utf-8'))
            _ = ssl_sock.recv(1024)
            rtt = (time.perf_counter() - t_ping_start) * 1000.0
            metrics["ping_rtts_ms"].append(rtt)

        # 4. Cierre de sesión (LOGOUT)
        ssl_sock.sendall(json.dumps({"action": "LOGOUT"}).encode('utf-8'))
        _ = ssl_sock.recv(1024)
        ssl_sock.close()
        
        metrics["success"] = True

    except Exception as e:
        metrics["error"] = str(e)

    return metrics

# --- SIMULACIÓN DE HILO TCP PLANO (SIN CIFRAR) ---
def run_plain_client(client_id):
    metrics = {
        "connect_time_ms": 0.0,
        "ping_rtts_ms": [],
        "success": False
    }
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        t_start_conn = time.perf_counter()
        sock.connect((HOST, PORT_PLAIN))
        metrics["connect_time_ms"] = (time.perf_counter() - t_start_conn) * 1000.0

        sock.sendall(json.dumps({"action": "AUTH"}).encode('utf-8'))
        _ = sock.recv(1024)

        for _ in range(PINGS_PER_CLIENT):
            t_ping_start = time.perf_counter()
            sock.sendall(json.dumps({"action": "PING"}).encode('utf-8'))
            _ = sock.recv(1024)
            rtt = (time.perf_counter() - t_ping_start) * 1000.0
            metrics["ping_rtts_ms"].append(rtt)

        sock.sendall(json.dumps({"action": "LOGOUT"}).encode('utf-8'))
        _ = sock.recv(1024)
        sock.close()
        metrics["success"] = True
    except Exception:
        pass

    return metrics

# --- EJECUCIÓN DEL BENCHMARK COMPARATIVO ESCALONADO ---
def main():
    print("==========================================================================")
    print(" EVALUACIÓN DE ESCALABILIDAD, RENDIMIENTO Y SOBRECOSTE (OVERHEAD VPN)")
    print("==========================================================================\n")

    plain_server = start_plain_tcp_server()
    time.sleep(0.5)

    print(f"{'HILOS':<6} | {'TIPO':<10} | {'ÉXITO':<8} | {'RTT MEDIO (ms)':<16} | {'THROUGHPUT (req/s)':<18} | {'OVERHEAD RTT':<12}")
    print("=" * 85)

    for num_hilos in NIVELES_CARGA:
        # Tráfico Plano
        start_plain = time.perf_counter()
        plain_results = []
        with ThreadPoolExecutor(max_workers=num_hilos) as executor:
            futures = [executor.submit(run_plain_client, i) for i in range(num_hilos)]
            for f in as_completed(futures):
                plain_results.append(f.result())
        total_plain_time = time.perf_counter() - start_plain

        # Tráfico VPN (TLS 1.3 + mTLS)
        ssl_context = get_ssl_context()
        start_vpn = time.perf_counter()
        vpn_results = []
        with ThreadPoolExecutor(max_workers=num_hilos) as executor:
            futures = [executor.submit(run_vpn_client, i, ssl_context) for i in range(num_hilos)]
            for f in as_completed(futures):
                vpn_results.append(f.result())
        total_vpn_time = time.perf_counter() - start_vpn

        # Cálculo de Métricas Plano
        succ_plain = [r for r in plain_results if r["success"]]
        rtts_plain = [rtt for r in succ_plain for rtt in r["ping_rtts_ms"]]
        avg_rtt_plain = statistics.mean(rtts_plain) if rtts_plain else 0.0
        tp_plain = (len(succ_plain) * PINGS_PER_CLIENT) / total_plain_time if total_plain_time > 0 else 0

        # Cálculo de Métricas VPN
        succ_vpn = [r for r in vpn_results if r["success"]]
        rtts_vpn = [rtt for r in succ_vpn for rtt in r["ping_rtts_ms"]]
        avg_rtt_vpn = statistics.mean(rtts_vpn) if rtts_vpn else 0.0
        tp_vpn = (len(succ_vpn) * PINGS_PER_CLIENT) / total_vpn_time if total_vpn_time > 0 else 0

        # Cálculo del Overhead
        overhead_rtt = ((avg_rtt_vpn - avg_rtt_plain) / avg_rtt_plain * 100.0) if avg_rtt_plain > 0 else 0.0

        print(f"{num_hilos:<6} | Plano      | {len(succ_plain)}/{num_hilos:<5} | {avg_rtt_plain:<16.2f} | {tp_plain:<18.2f} | -")
        print(f"{num_hilos:<6} | VPN mTLS   | {len(succ_vpn)}/{num_hilos:<5} | {avg_rtt_vpn:<16.2f} | {tp_vpn:<18.2f} | +{overhead_rtt:.2f}%")
        print("-" * 85)

    plain_server.close()

if __name__ == "__main__":
    main()