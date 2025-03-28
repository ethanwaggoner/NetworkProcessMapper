import time
import psutil
import socket
import os
import ctypes
import struct
import json
import argparse
import logging
from datetime import datetime
from threading import Lock, Thread

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),

    ]
)

class NetworkProcessMonitor:
    def __init__(self, cache_ttl=5, refresh_interval=1, time_limit=0, output_json=False, disable_table=False):
        self.capture_running = False
        self.log_lock = Lock()
        self.recent_ports = {}
        self.cache_ttl = cache_ttl
        self.process_table = {}
        self.refresh_interval = refresh_interval
        self.time_limit = time_limit
        self.output_json_flag = output_json
        self.disable_table = disable_table
        self.local_ips = self._get_local_ips()
        self.update_thread = None
        self.capture_thread = None
        self.table_thread = None

        self.header_cols = ["Process", "PID", "Owner", "Mem(KB)", "Cmdline", "Create Time", "Direction", "Last Act", "Src", "Dst"]
        self.col_widths = [15, 6, 10, 8, 30, 19, 8, 19, 16, 16]

    def _get_local_ips(self):
        ips = set()
        try:
            for interface, snics in psutil.net_if_addrs().items():
                for snic in snics:
                    if snic.family == socket.AF_INET:
                        ips.add(snic.address)
        except Exception as e:
            logging.exception("Error detecting local IPs")
        return ips

    def _get_extended_tcp_table(self):
        AF_INET = 2
        TCP_TABLE_OWNER_PID_ALL = 5

        class MIB_TCPROW_OWNER_PID(ctypes.Structure):
            _fields_ = [
                ("state", ctypes.c_ulong),
                ("localAddr", ctypes.c_ulong),
                ("localPort", ctypes.c_ulong),
                ("remoteAddr", ctypes.c_ulong),
                ("remotePort", ctypes.c_ulong),
                ("owningPid", ctypes.c_ulong)
            ]

        try:
            iphlpapi = ctypes.WinDLL('iphlpapi.dll')
            GetExtendedTcpTable = iphlpapi.GetExtendedTcpTable
            GetExtendedTcpTable.argtypes = [
                ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_ulong),
                ctypes.c_bool,
                ctypes.c_ulong,
                ctypes.c_ulong,
                ctypes.c_ulong
            ]
            GetExtendedTcpTable.restype = ctypes.c_ulong

            size = ctypes.c_ulong(0)
            ret = GetExtendedTcpTable(None, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
            buf = ctypes.create_string_buffer(size.value)
            ret = GetExtendedTcpTable(buf, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
            if ret != 0:
                raise Exception("GetExtendedTcpTable failed with error code: {}".format(ret))
            num_entries = struct.unpack("I", buf.raw[:4])[0]
            rows = []
            row_size = ctypes.sizeof(MIB_TCPROW_OWNER_PID)
            for i in range(num_entries):
                offset = 4 + i * row_size
                row_bytes = buf.raw[offset:offset + row_size]
                row = MIB_TCPROW_OWNER_PID.from_buffer_copy(row_bytes)
                rows.append(row)
            return rows
        except Exception as e:
            logging.exception("Error retrieving extended TCP table")
            return []

    def _update_port_map_windows(self, interval=1):
        while self.capture_running:
            now = time.time()
            temp_map = {}
            try:
                tcp_rows = self._get_extended_tcp_table()
                for row in tcp_rows:
                    local_port = socket.ntohs(row.localPort & 0xFFFF)
                    try:
                        proc = psutil.Process(row.owningPid)
                        temp_map[local_port] = {
                            'pid': row.owningPid,
                            'name': proc.name(),
                            'cmdline': ' '.join(proc.cmdline()),
                            'create_time': proc.create_time(),
                            'timestamp': now,
                            'owner': proc.username(),
                            'memory': proc.memory_info().rss // 1024
                        }
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            except Exception as e:
                logging.exception("Error updating port map (Windows API)")
            self.recent_ports.update(temp_map)
            expired = [port for port, info in self.recent_ports.items() if now - info['timestamp'] > self.cache_ttl]
            for port in expired:
                del self.recent_ports[port]
            time.sleep(interval)

    def _update_port_map(self, interval=1):
        while self.capture_running:
            now = time.time()
            temp_map = {}
            try:
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
                                'timestamp': now,
                                'owner': proc.username(),
                                'memory': proc.memory_info().rss // 1024
                            }
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
            except Exception as e:
                logging.exception("Error updating port map (psutil)")
            self.recent_ports.update(temp_map)
            expired = [port for port, info in self.recent_ports.items() if now - info['timestamp'] > self.cache_ttl]
            for port in expired:
                del self.recent_ports[port]
            time.sleep(interval)

    def _match_process(self, port):
        info = self.recent_ports.get(port)
        if info:
            return info
        return {
            'pid': None,
            'name': 'unknown',
            'cmdline': '',
            'create_time': None,
            'owner': '',
            'memory': 0,
            'timestamp': 0
        }

    def _process_packet(self, packet):
        try:
            if not hasattr(packet, 'haslayer') or not packet.haslayer('IP'):
                return
            ip_layer = packet.getlayer('IP')
            if not ip_layer or not packet.haslayer('TCP'):
                return
            tcp_layer = packet.getlayer('TCP')
            if not tcp_layer:
                return

            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            directions = []
            if ip_layer.src in self.local_ips:
                directions.append('outbound')
            if ip_layer.dst in self.local_ips:
                directions.append('inbound')
            if not directions:
                src_info = self._match_process(src_port)
                dst_info = self._match_process(dst_port)
                if src_info['name'] != 'unknown':
                    directions.append('outbound')
                elif dst_info['name'] != 'unknown':
                    directions.append('inbound')

            now = time.time()
            for direction in directions:
                if direction == 'outbound':
                    proc_info = self._match_process(src_port)
                else:
                    proc_info = self._match_process(dst_port)

                if proc_info['name'] == 'unknown':
                    continue

                key = (proc_info['pid'], proc_info['create_time'], direction)
                with self.log_lock:
                    if key in self.process_table:
                        entry = self.process_table[key]
                        entry['last_activity'] = now
                        entry['src_ip'] = ip_layer.src
                        entry['src_port'] = src_port
                        entry['dst_ip'] = ip_layer.dst
                        entry['dst_port'] = dst_port
                        entry['memory'] = proc_info['memory']
                    else:
                        self.process_table[key] = {
                            'name': proc_info['name'],
                            'pid': proc_info['pid'],
                            'owner': proc_info['owner'],
                            'memory': proc_info['memory'],
                            'cmdline': proc_info['cmdline'],
                            'create_time': proc_info['create_time'],
                            'direction': direction,
                            'last_activity': now,
                            'src_ip': ip_layer.src,
                            'src_port': src_port,
                            'dst_ip': ip_layer.dst,
                            'dst_port': dst_port
                        }
        except Exception as e:
            logging.exception("Error processing packet")

    def _capture_packets(self):
        from scapy.all import sniff
        logging.info("Starting packet capture... (Press Ctrl+C to stop)")
        while self.capture_running:
            try:
                sniff(filter="tcp", prn=self._process_packet, store=0, timeout=2)
            except Exception as inner_e:
                logging.exception("Error during packet sniffing")
                time.sleep(0.5)

    def _build_row_str(self, values):
        row_str_parts = []
        for val, width in zip(values, self.col_widths):
            val_str = str(val) if val is not None else ""
            row_str_parts.append(f"{val_str:<{width}}")
        return " | ".join(row_str_parts)

    def _print_table_loop(self):
        while self.capture_running:
            try:
                time.sleep(self.refresh_interval)
                os.system('cls' if os.name == 'nt' else 'clear')
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                with self.log_lock:
                    process_count = len(self.process_table)
                header_title = " Network Process Monitor "
                header_info = f"Timestamp: {current_time} | Processes Captured: {process_count}"
                total_width = sum(self.col_widths) + 3 * len(self.col_widths) + 1
                print(header_title.center(total_width))
                print(header_info.center(total_width))
                print("=" * total_width)
                header_row = self._build_row_str(self.header_cols)
                print(header_row)
                print("-" * total_width)
                with self.log_lock:
                    for key in sorted(self.process_table.keys()):
                        proc = self.process_table[key]
                        create_time_str = datetime.fromtimestamp(proc['create_time']).strftime("%Y-%m-%d %H:%M:%S") if proc['create_time'] else "N/A"
                        last_act_str = datetime.fromtimestamp(proc.get('last_activity', 0)).strftime("%Y-%m-%d %H:%M:%S") if proc.get('last_activity') else "N/A"
                        cmdline_display = (proc['cmdline'][:27] + '...') if len(proc['cmdline']) > 30 else proc['cmdline']
                        src = f"{proc['src_ip']}:{proc['src_port']}"
                        dst = f"{proc['dst_ip']}:{proc['dst_port']}"
                        row_data = [
                            proc['name'],
                            str(proc['pid']),
                            proc['owner'],
                            str(proc['memory']),
                            cmdline_display,
                            create_time_str,
                            proc['direction'],
                            last_act_str,
                            src,
                            dst
                        ]
                        print(self._build_row_str(row_data))
                print("=" * total_width)
            except Exception as e:
                logging.exception("Error in printing table loop")

    def output_json(self, filename="network_process.json"):
        data_list = []
        try:
            with self.log_lock:
                for (pid, ctime, direction), info in self.process_table.items():
                    data_list.append({
                        "pid": pid,
                        "create_time": ctime,
                        "direction": direction,
                        "name": info['name'],
                        "owner": info['owner'],
                        "memory": info['memory'],
                        "cmdline": info['cmdline'],
                        "last_activity": info.get('last_activity', None),
                        "src_ip": info.get('src_ip', ''),
                        "src_port": info.get('src_port', ''),
                        "dst_ip": info.get('dst_ip', ''),
                        "dst_port": info.get('dst_port', '')
                    })
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(data_list, f, indent=2)
            logging.info("JSON output saved to %s", filename)
        except Exception as e:
            logging.exception("Error outputting JSON")

    def start(self):
        self.capture_running = True
        if os.name == 'nt':
            self.update_thread = Thread(target=self._update_port_map_windows, daemon=True)
        else:
            self.update_thread = Thread(target=self._update_port_map, daemon=True)
        self.capture_thread = Thread(target=self._capture_packets, daemon=True)
        if not self.disable_table:
            self.table_thread = Thread(target=self._print_table_loop, daemon=True)
        self.update_thread.start()
        self.capture_thread.start()
        if not self.disable_table:
            self.table_thread.start()
        try:
            if self.time_limit > 0:
                time.sleep(self.time_limit)
            else:
                while True:
                    time.sleep(1)
        except KeyboardInterrupt:
            logging.info("Keyboard interrupt received. Stopping capture...")
        self.capture_running = False
        self.capture_thread.join()
        self.update_thread.join()
        if not self.disable_table:
            self.table_thread.join()
        logging.info("Capture stopped.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Network Process Mapper\n\n"
                    "Examples:\n"
                    "  python app.py --time 30         Run for 30 seconds and display table\n"
                    "  python app.py --json            Run indefinitely and output JSON on exit\n"
                    "  python app.py --time 30 --json    Run for 30 seconds and output JSON\n"
                    "  python app.py --no-table          Disable real-time table output",
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--time", type=int, default=0, help="Time to run in seconds (0 means indefinite).")
    parser.add_argument("--json", action="store_true", help="Output the final table to a JSON file (network_process.json).")
    parser.add_argument("--no-table", action="store_true", help="Disable real-time table display during capture.")
    args = parser.parse_args()

    monitor = NetworkProcessMonitor(time_limit=args.time, output_json=args.json, disable_table=args.no_table)
    monitor.start()

    if args.json:
        monitor.output_json("network_process_map.json")
