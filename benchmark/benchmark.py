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
CLIENT_CERT = os.path.join(PKI_DIR, "client.crt")
CLIENT_KEY = os.path.join(PKI_DIR, "client.key")

HOST = '127.0.0.1'
PORT_VPN = 8443        # Puerto del Servidor VPN (TLS 1.3 + mTLS)
PORT_PLAIN = 8444      # Puerto auxiliar para prueba de tráfico no cifrado
NUM_CLIENTS = 300      # Requisito RS3: 300 usuarios concurrentes
PINGS_PER_CLIENT = 5   # Peticiones enviadas por cada cliente en el túnel

# --- SERVIDOR AUXILIAR TCP PLANO (PARA COMPARAR OVERHEAD) ---
def start_plain_tcp_server():
    """Servidor TCP sin cifrar para medir el tráfico sin encapsular (Benchmark RS3)."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT_PLAIN))
    server.listen(NUM_CLIENTS)
    
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

# --- SIMULACIÓN DE UN CLIENTE VPN (TLS 1.3 + mTLS) ---
def run_vpn_client(client_id, ssl_context):
    metrics = {
        "client_id": client_id,
        "handshake_time_ms": 0.0,
        "auth_time_ms": 0.0,
        "ping_rtts_ms": [],
        "success": False,
        "error": None
    }
    
    start_total = time.perf_counter()
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock = ssl_context.wrap_socket(raw_sock, server_hostname='localhost')
        
        # 1. Medir tiempo de Conexión + Handshake mTLS
        t_start_hs = time.perf_counter()
        ssl_sock.connect((HOST, PORT_VPN))
        metrics["handshake_time_ms"] = (time.perf_counter() - t_start_hs) * 1000.0

        # 2. Medir tiempo de Autenticación de Aplicación
        t_start_auth = time.perf_counter()
        auth_payload = {"username": "profesor1", "password": "PassProfesor123!"}
        ssl_sock.sendall(json.dumps(auth_payload).encode('utf-8'))
        auth_res = json.loads(ssl_sock.recv(1024).decode('utf-8'))
        metrics["auth_time_ms"] = (time.perf_counter() - t_start_auth) * 1000.0

        if auth_res.get("status") != "SUCCESS":
            metrics["error"] = "Error en Autenticación"
            ssl_sock.close()
            return metrics

        # 3. Medir RTT de mensajes PING dentro del túnel seguro
        for _ in range(PINGS_PER_CLIENT):
            t_ping_start = time.perf_counter()
            ssl_sock.sendall(json.dumps({"action": "PING"}).encode('utf-8'))
            _ = ssl_sock.recv(1024)
            rtt = (time.perf_counter() - t_ping_start) * 1000.0
            metrics["ping_rtts_ms"].append(rtt)

        # 4. Desmontaje del túnel (LOGOUT)
        ssl_sock.sendall(json.dumps({"action": "LOGOUT"}).encode('utf-8'))
        _ = ssl_sock.recv(1024)
        ssl_sock.close()
        
        metrics["success"] = True

    except Exception as e:
        metrics["error"] = str(e)

    return metrics

# --- SIMULACIÓN DE UN CLIENTE TCP SIN CIFRAR (PLANO) ---
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

        # Autenticación plana
        sock.sendall(json.dumps({"action": "AUTH"}).encode('utf-8'))
        _ = sock.recv(1024)

        # PINGs planos
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

# --- EJECUCIÓN DEL BENCHMARK COMPARATIVO ---
def main():
    print(f"============================================================")
    print(f" BENCHMARK DE ESCALABILIDAD Y RENDIMIENTO (PROYECTO PAI-2)")
    print(f" Carga simulada: {NUM_CLIENTS} usuarios concurrentes")
    print(f"============================================================\n")

    # Iniciar servidor TCP plano auxiliar
    plain_server = start_plain_tcp_server()
    time.sleep(0.5)

    # 1. EJECUCIÓN SOBRE TRÁFICO TCP SIN CIFRAR
    print(f"[1/2] Ejecutando prueba de {NUM_CLIENTS} clientes sobre TCP PLANO (Sin cifrar)...")
    start_plain_test = time.perf_counter()
    plain_results = []
    with ThreadPoolExecutor(max_workers=NUM_CLIENTS) as executor:
        futures = [executor.submit(run_plain_client, i) for i in range(NUM_CLIENTS)]
        for f in as_completed(futures):
            plain_results.append(f.result())
    total_plain_time = time.perf_counter() - start_plain_test

    # 2. EJECUCIÓN SOBRE TÚNEL VPN TLS 1.3 + mTLS
    print(f"[2/2] Ejecutando prueba de {NUM_CLIENTS} clientes sobre TÚNEL VPN TLS 1.3 + mTLS...")
    ssl_context = get_ssl_context()
    start_vpn_test = time.perf_counter()
    vpn_results = []
    with ThreadPoolExecutor(max_workers=NUM_CLIENTS) as executor:
        futures = [executor.submit(run_vpn_client, i, ssl_context) for i in range(NUM_CLIENTS)]
        for f in as_completed(futures):
            vpn_results.append(f.result())
    total_vpn_time = time.perf_counter() - start_vpn_test

    plain_server.close()

    # --- PROCESAMIENTO Y CÁLCULO DE MÉTRICAS ---
    successful_vpn = [r for r in vpn_results if r["success"]]
    failed_vpn = [r for r in vpn_results if not r["success"]]
    
    vpn_handshakes = [r["handshake_time_ms"] for r in successful_vpn]
    vpn_rtts = [rtt for r in successful_vpn for rtt in r["ping_rtts_ms"]]
    
    successful_plain = [r for r in plain_results if r["success"]]
    plain_conns = [r["connect_time_ms"] for r in successful_plain]
    plain_rtts = [rtt for r in successful_plain for rtt in r["ping_rtts_ms"]]

    avg_plain_rtt = statistics.mean(plain_rtts) if plain_rtts else 0.0
    avg_vpn_rtt = statistics.mean(vpn_rtts) if vpn_rtts else 0.0
    avg_hs_time = statistics.mean(vpn_handshakes) if vpn_handshakes else 0.0
    
    total_reqs = len(successful_vpn) * PINGS_PER_CLIENT
    throughput_vpn = total_reqs / total_vpn_time if total_vpn_time > 0 else 0

    # Cálculo del sobrecoste (Overhead)
    overhead_rtt = ((avg_vpn_rtt - avg_plain_rtt) / avg_plain_rtt * 100.0) if avg_plain_rtt > 0 else 0.0

    # --- INFORME CUANTITATIVO DE RESULTADOS ---
    print("\n" + "="*60)
    print(" INFORME DE RESULTADOS Y EVALUACIÓN DE OVERHEAD (RS3)")
    print("="*60)
    print(f" Conexiones Exitosas (VPN):      {len(successful_vpn)} / {NUM_CLIENTS} ({len(successful_vpn)/NUM_CLIENTS*100:.1f}%)")
    print(f" Conexiones Fallidas (VPN):      {len(failed_vpn)}")
    print(f" Tiempo Total del Test (VPN):    {total_vpn_time:.2f} segundos")
    print(f" Throughput (Tasa Procesamiento): {throughput_vpn:.2f} peticiones/segundo")
    print("-" * 60)
    print(f" Latencia Conexión TCP Plana:    {statistics.mean(plain_conns):.2f} ms")
    print(f" Latencia Handshake mTLS+TLS1.3: {avg_hs_time:.2f} ms")
    print(f" RTT Medio Mensaje (TCP Plano):  {avg_plain_rtt:.2f} ms")
    print(f" RTT Medio Mensaje (Túnel VPN):  {avg_vpn_rtt:.2f} ms")
    print("-" * 60)
    print(f" [OVERHEAD LATENCIA CIFRADO]:    +{overhead_rtt:.2f}% de sobrecoste RTT")
    print("="*60 + "\n")

if __name__ == "__main__":
    main()