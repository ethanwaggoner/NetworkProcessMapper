import webview
import time
import psutil
import socket
from datetime import datetime
from threading import Lock, Thread
import logging
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

capture_running = False
packet_logs = []
log_lock = Lock()
recent_ports = {}
cache_ttl = 5
capture_thread = None
port_map_thread = None

def get_local_ips():
    ips = set()
    for interface, snics in psutil.net_if_addrs().items():
        for snic in snics:
            if snic.family == socket.AF_INET:
                ips.add(snic.address)
    return ips

local_ips = get_local_ips()

def update_port_map(interval=1):
    global recent_ports
    while capture_running:
        now = time.time()
        temp_map = {}
        for conn in psutil.net_connections(kind='inet'):
            if conn.laddr:
                port = conn.laddr.port
                try:
                    proc = psutil.Process(conn.pid)
                    temp_map[port] = {
                        'pid': conn.pid,
                        'name': proc.name(),
                        'cmdline': ' '.join(proc.cmdline()),
                        'create_time': proc.create_time(),
                        'timestamp': now
                    }
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        recent_ports.update(temp_map)
        expired = [port for port, info in recent_ports.items() if now - info['timestamp'] > cache_ttl]
        for port in expired:
            del recent_ports[port]
        time.sleep(interval)

def match_process(port):
    info = recent_ports.get(port)
    if info:
        return {
            'pid': info['pid'],
            'name': info['name'],
            'cmdline': info['cmdline'],
            'create_time': info['create_time']
        }
    return {
        'pid': None,
        'name': 'unknown',
        'cmdline': '',
        'create_time': None
    }

def process_packet(packet):
    try:
        if not hasattr(packet, 'haslayer') or not packet.haslayer('IP'):
            return
        ip_layer = packet.getlayer('IP')
        if not ip_layer:
            return
        if not packet.haslayer('TCP'):
            return
        tcp_layer = packet.getlayer('TCP')
        if not tcp_layer:
            return
        src_port = tcp_layer.sport
        dst_port = tcp_layer.dport
        if ip_layer.src in local_ips:
            proc_info = match_process(src_port)
        elif ip_layer.dst in local_ips:
            proc_info = match_process(dst_port)
        else:
            src_info = match_process(src_port)
            dst_info = match_process(dst_port)
            proc_info = src_info if src_info['name'] != 'unknown' else dst_info
        if proc_info['name'] == 'unknown':
            return
        now = datetime.now()
        timestamp = now.isoformat()
        log_entry = {
            'timestamp': timestamp,
            'src': f"{ip_layer.src}:{tcp_layer.sport}",
            'dst': f"{ip_layer.dst}:{tcp_layer.dport}",
            'pid': proc_info['pid'],
            'process': proc_info['name'],
            'cmdline': proc_info['cmdline'] if proc_info['cmdline'] else '',
            'create_time': proc_info['create_time']
        }
        with log_lock:
            packet_logs.append(log_entry)
            if len(packet_logs) > 1000:
                packet_logs.pop(0)
    except Exception as e:
        logger.error("Error processing packet: %s", e)

def capture_packets():
    try:
        from scapy.all import sniff
        from scapy.layers.inet import IP, TCP
        logger.info("Starting packet capture...")
        while capture_running:
            try:
                sniff(filter="tcp", prn=process_packet, store=0, timeout=2)
                logger.info("Active connections captured: %d", len(packet_logs))
            except Exception as inner_e:
                logger.error("Error during sniffing: %s", inner_e)
                time.sleep(0.5)
    except Exception as e:
        logger.error("Critical error in capture thread: %s", e)

class NetworkCaptureAPI:
    def __init__(self):
        self.last_fetch_time = time.time()
    def start_capture(self):
        global capture_running, capture_thread, port_map_thread, packet_logs
        if capture_running:
            return {"status": "already running"}
        logger.info("Starting packet capture...")
        capture_running = True
        with log_lock:
            packet_logs.clear()
        capture_thread = Thread(target=capture_packets, daemon=True)
        port_map_thread = Thread(target=update_port_map, daemon=True)
        port_map_thread.start()
        capture_thread.start()
        self.last_fetch_time = time.time()
        return {"status": "capture started", "timestamp": time.time(), "running": True}
    def stop_capture(self):
        global capture_running
        if not capture_running:
            return {"status": "not running"}
        capture_running = False
        if capture_thread is not None:
            capture_thread.join(timeout=3)
        if port_map_thread is not None:
            port_map_thread.join(timeout=3)
        return {"status": "capture stopped"}
    def get_logs(self):
        with log_lock:
            filtered_logs = [log for log in packet_logs if log['process'] != 'unknown']
            filtered_logs.sort(key=lambda x: x['timestamp'], reverse=True)
            return filtered_logs
    def get_status(self):
        global capture_running
        capture_status = {
            "running": capture_running,
            "timestamp": time.time(),
            "log_count": len(packet_logs),
            "threads_active": {
                "capture": capture_thread is not None and capture_thread.is_alive() if capture_thread else False,
                "port_map": port_map_thread is not None and port_map_thread.is_alive() if port_map_thread else False
            }
        }
        logger.info("Status check: Capture running = %s, Log count = %d", capture_running, len(packet_logs))
        return capture_status
    def get_metrics(self):
        with log_lock:
            unique_processes = len(set(log['process'] for log in packet_logs if log['process'] != 'unknown'))
            connection_count = len([log for log in packet_logs if log['process'] != 'unknown'])
            return {"connections": connection_count, "processes": unique_processes}

class NetworkProcessMapper:
    def __init__(self):
        self.window = None
        self.api = NetworkCaptureAPI()
        self.debug = True
    def start(self):
        logger.info("Starting Network Process Mapper...")
        logger.info("Debug mode: %s", "enabled" if self.debug else "disabled")
        try:
            html_content = self.get_html_content()
            self.window = webview.create_window('Network Process Mapper', html=html_content, js_api=self.api, width=1000, height=700, min_size=(800, 600))
            self.window.events.closed += self.on_closed
            self.window.events.loaded += self.on_loaded
            webview.start()
        except Exception as e:
            logger.error("Error starting application: %s", e)
    def on_loaded(self):
        logger.info("Window loaded successfully")
    def on_closed(self):
        logger.info("Window closed, shutting down...")
        global capture_running
        capture_running = False
    def get_html_content(self):
        try:
            with open('app.html', 'r', encoding='utf-8') as file:
                return file.read()
        except Exception as e:
            logger.error("Error loading HTML content: %s", e)
            raise

if __name__ == "__main__":
    logger.info("Initializing application...")
    app = NetworkProcessMapper()
    app.start()
