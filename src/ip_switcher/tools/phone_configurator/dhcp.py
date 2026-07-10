import dataclasses
import ipaddress
import queue
import socket
import struct
import threading
import time


def phone_log(progress, message):
    if progress:
        progress(message)


@dataclasses.dataclass(frozen=True)
class PhoneDhcpLease:
    ip: ipaddress.IPv4Address
    mac: str
    hostname: str
    vendor_class: str


def phone_ip_to_bytes(value):
    return socket.inet_aton(str(value))


def phone_bytes_to_ip(value):
    return ipaddress.ip_address(socket.inet_ntoa(value))


def phone_mac_to_text(value):
    return ":".join(f"{byte:02x}" for byte in value)


def phone_parse_dhcp_options(data):
    options = {}
    index = 0
    while index < len(data):
        code = data[index]
        index += 1
        if code == 255:
            break
        if code == 0:
            continue
        if index >= len(data):
            break
        length = data[index]
        index += 1
        options[code] = data[index : index + length]
        index += length
    return options


def phone_dhcp_option(code, value):
    if len(value) > 255:
        raise ValueError(f"DHCP option {code} is too long.")
    return bytes([code, len(value)]) + value


def phone_dhcp_message_type(options):
    value = options.get(53)
    return value[0] if value else None


def phone_build_dhcp_discover(transaction_id):
    chaddr = b"\x02\x49\x50\x53\x57\x01" + b"\x00" * 10
    fixed = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        1,
        1,
        6,
        0,
        transaction_id,
        0,
        0x8000,
        b"\x00\x00\x00\x00",
        b"\x00\x00\x00\x00",
        b"\x00\x00\x00\x00",
        b"\x00\x00\x00\x00",
        chaddr,
        b"",
        b"",
    )
    options = [
        phone_dhcp_option(53, b"\x01"),
        phone_dhcp_option(55, bytes([1, 3, 6, 28, 51, 54])),
        phone_dhcp_option(12, b"IP-Switcher-Probe"),
        b"\xff",
    ]
    return fixed + b"\x63\x82\x53\x63" + b"".join(options)


def phone_probe_other_dhcp_servers(config, progress=None, timeout_seconds=4):
    if not config.use_dhcp_server:
        return []

    transaction_id = int(time.time() * 1000) & 0xFFFFFFFF
    discover = phone_build_dhcp_discover(transaction_id)
    offers = []
    phone_log(progress, f"Checking for other DHCP servers on {config.staging_interface}...")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.bind(("", 68))
            sock.settimeout(0.5)
            sock.sendto(discover, ("255.255.255.255", 67))
            sock.sendto(discover, (str(config.scan_subnet.broadcast_address), 67))
            deadline = time.monotonic() + timeout_seconds
            while time.monotonic() < deadline:
                try:
                    data, _addr = sock.recvfrom(4096)
                except socket.timeout:
                    continue
                if len(data) < 240 or data[236:240] != b"\x63\x82\x53\x63":
                    continue
                _op, _htype, _hlen, _hops, xid, _secs, _flags = struct.unpack("!BBBBIHH", data[:12])
                if xid != transaction_id:
                    continue
                options = phone_parse_dhcp_options(data[240:])
                if phone_dhcp_message_type(options) != 2:
                    continue
                server_id = options.get(54)
                server_ip = phone_bytes_to_ip(server_id) if server_id and len(server_id) == 4 else "unknown"
                offered_ip = phone_bytes_to_ip(data[16:20])
                if str(server_ip) == str(config.dhcp_server_ip):
                    continue
                offers.append({"server": str(server_ip), "offered_ip": str(offered_ip)})
    except PermissionError as exc:
        raise RuntimeError("DHCP conflict check needs Administrator privileges to bind UDP port 68.") from exc
    except OSError as exc:
        raise RuntimeError(f"DHCP conflict check could not run: {exc}") from exc

    unique = []
    seen = set()
    for offer in offers:
        key = (offer["server"], offer["offered_ip"])
        if key not in seen:
            seen.add(key)
            unique.append(offer)
    if unique:
        for offer in unique:
            phone_log(progress, f"Detected other DHCP server {offer['server']} offering {offer['offered_ip']}.")
    else:
        phone_log(progress, "No other DHCP server responded to the probe.")
    return unique


class PhoneDhcpServer:
    def __init__(self, config, progress=None):
        self.config = config
        self.progress = progress
        self.thread = None
        self.stop_event = threading.Event()
        self.ready_event = threading.Event()
        self.start_error = None
        self.leases = {}
        self.lease_queue = queue.Queue()
        self.socket = None

    def start(self):
        if self.thread:
            return
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()
        if not self.ready_event.wait(timeout=5):
            raise RuntimeError("DHCP server did not finish starting within 5 seconds.")
        if self.start_error:
            raise RuntimeError(self.start_error)

    def stop(self):
        self.stop_event.set()
        if self.socket:
            try:
                self.socket.close()
            except OSError:
                pass
        if self.thread:
            self.thread.join(timeout=2)

    def wait_for_lease(self, timeout_seconds):
        try:
            return self.lease_queue.get(timeout=timeout_seconds)
        except queue.Empty as exc:
            raise TimeoutError("Timed out waiting for a DHCP lease.") from exc

    def serve(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                self.socket = sock
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                sock.bind(("", 67))
                sock.settimeout(1)
                self.ready_event.set()
                phone_log(
                    self.progress,
                    f"DHCP server listening on UDP/67 using {self.config.dhcp_server_ip} "
                    f"as server IP with pool {self.config.dhcp_pool_start}-{self.config.dhcp_pool_end}",
                )
                while not self.stop_event.is_set():
                    try:
                        data, _addr = sock.recvfrom(4096)
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                    try:
                        self.handle_packet(sock, data)
                    except Exception as exc:
                        phone_log(self.progress, f"DHCP warning: {exc}")
        except PermissionError:
            self.start_error = "DHCP server needs Administrator privileges to bind UDP port 67."
            self.ready_event.set()
        except OSError as exc:
            self.start_error = f"DHCP server could not start: {exc}"
            self.ready_event.set()

    def handle_packet(self, sock, data):
        if len(data) < 240 or data[236:240] != b"\x63\x82\x53\x63":
            return

        fixed = data[:236]
        op, _htype, hlen, _hops, xid, _secs, flags = struct.unpack("!BBBBIHH", fixed[:12])
        if op != 1 or hlen < 1:
            return

        ciaddr = fixed[12:16]
        chaddr = fixed[28 : 28 + hlen]
        mac = phone_mac_to_text(chaddr[:6])
        options = phone_parse_dhcp_options(data[240:])
        msg_type = phone_dhcp_message_type(options)
        if msg_type not in {1, 3}:
            return

        hostname = options.get(12, b"").decode(errors="ignore")
        vendor_class = options.get(60, b"").decode(errors="ignore")
        if msg_type == 1:
            offered_ip = self.lease_for_mac(mac)
            phone_log(self.progress, f"DHCP discover from {mac}; offering {offered_ip}")
            reply_type = 2
        else:
            server_identifier = options.get(54)
            if server_identifier and server_identifier != phone_ip_to_bytes(self.config.dhcp_server_ip):
                selected_server = phone_bytes_to_ip(server_identifier) if len(server_identifier) == 4 else "unknown"
                phone_log(self.progress, f"Ignoring DHCP request from {mac}; selected server is {selected_server}")
                return
            if mac not in self.leases:
                phone_log(self.progress, f"Ignoring DHCP request from {mac}; no offer was made to this MAC")
                return
            offered_ip = self.leases[mac]
            requested_ip = self.requested_ip(options, ciaddr)
            if requested_ip and requested_ip != offered_ip:
                phone_log(self.progress, f"Ignoring DHCP request from {mac}; requested {requested_ip}, offered {offered_ip}")
                return
            phone_log(self.progress, f"DHCP request from {mac}; ack {offered_ip}")
            reply_type = 5
            self.lease_queue.put(PhoneDhcpLease(offered_ip, mac, hostname, vendor_class))

        reply = self.build_reply(fixed, xid, flags, fixed[28:44], offered_ip, reply_type)
        sock.sendto(reply, ("255.255.255.255", 68))
        sock.sendto(reply, (str(self.config.scan_subnet.broadcast_address), 68))

    def lease_for_mac(self, mac):
        if mac in self.leases:
            return self.leases[mac]
        used = set(self.leases.values())
        for value in range(int(self.config.dhcp_pool_start), int(self.config.dhcp_pool_end) + 1):
            candidate = ipaddress.ip_address(value)
            if candidate not in used:
                self.leases[mac] = candidate
                return candidate
        raise RuntimeError("No free DHCP lease IPs remain.")

    def requested_ip(self, options, ciaddr):
        requested = options.get(50)
        if requested and len(requested) == 4:
            return phone_bytes_to_ip(requested)
        if ciaddr != b"\x00\x00\x00\x00":
            return phone_bytes_to_ip(ciaddr)
        return None

    def build_reply(self, _request, xid, flags, chaddr, yiaddr, message_type):
        fixed = struct.pack(
            "!BBBBIHH4s4s4s4s16s64s128s",
            2,
            1,
            6,
            0,
            xid,
            0,
            flags,
            b"\x00\x00\x00\x00",
            phone_ip_to_bytes(yiaddr),
            phone_ip_to_bytes(self.config.dhcp_server_ip),
            b"\x00\x00\x00\x00",
            chaddr,
            b"",
            b"",
        )
        options = [
            phone_dhcp_option(53, bytes([message_type])),
            phone_dhcp_option(54, phone_ip_to_bytes(self.config.dhcp_server_ip)),
            phone_dhcp_option(51, struct.pack("!I", self.config.dhcp_lease_seconds)),
            phone_dhcp_option(1, phone_ip_to_bytes(self.config.netmask)),
            phone_dhcp_option(3, phone_ip_to_bytes(self.config.gateway)),
            phone_dhcp_option(6, phone_ip_to_bytes(self.config.gateway)),
            phone_dhcp_option(28, phone_ip_to_bytes(self.config.scan_subnet.broadcast_address)),
            phone_dhcp_option(66, self.config.tftp_server.encode()),
            b"\xff",
        ]
        return fixed + b"\x63\x82\x53\x63" + b"".join(options)
