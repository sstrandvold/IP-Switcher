import concurrent.futures
import ipaddress
import os
import socket
import subprocess
import time

from ...constants import CREATE_NO_WINDOW
from ...paths import PHONE_CONFIG_LOG_FILE
from ...winutil import run_hidden, run_powershell
from .dhcp import PhoneDhcpLease, PhoneDhcpServer, phone_log, phone_probe_other_dhcp_servers
from .history import (
    phone_append_assignment,
    phone_append_config_log,
    phone_load_state,
    phone_next_target_ip,
    phone_save_state,
    phone_update_assignment,
)

try:
    import paramiko
except ImportError:
    paramiko = None


def phone_tcp_port_open(host, port, timeout):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((str(host), port)) == 0


def phone_ssh_connect(host, config):
    if paramiko is None:
        raise RuntimeError("Missing dependency: install paramiko.")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=str(host),
        port=config.ssh_port,
        username=config.ssh_username,
        password=config.ssh_password,
        look_for_keys=False,
        allow_agent=False,
        timeout=3,
        auth_timeout=3,
        banner_timeout=3,
    )
    return client


def phone_wait_for_ssh_login(host, config, timeout_seconds, progress=None):
    deadline = time.monotonic() + timeout_seconds
    last_error = ""
    phone_log(progress, f"Waiting for SSH login on {host}...")
    while time.monotonic() < deadline:
        try:
            client = phone_ssh_connect(host, config)
            client.close()
            phone_log(progress, f"SSH login OK: {host}")
            return
        except Exception as exc:
            last_error = str(exc)
            time.sleep(2)
    raise TimeoutError(f"Timed out waiting for SSH login on {host}: {last_error}")


def phone_find_with_dhcp_server(config, progress=None):
    server = PhoneDhcpServer(config, progress=progress)
    server.start()
    try:
        phone_log(progress, "Waiting for a DHCP phone lease...")
        deadline = time.monotonic() + config.dhcp_wait_seconds
        last_error = ""
        while time.monotonic() < deadline:
            remaining = max(1, int(deadline - time.monotonic()))
            lease = server.wait_for_lease(remaining)
            phone_log(progress, f"DHCP lease: {lease.ip} for {lease.mac}")
            if lease.hostname:
                phone_log(progress, f"Hostname: {lease.hostname}")
            if lease.vendor_class:
                phone_log(progress, f"Vendor class: {lease.vendor_class}")
            try:
                phone_wait_for_ssh_login(lease.ip, config, config.dhcp_ssh_probe_seconds, progress)
                return lease
            except TimeoutError as exc:
                last_error = str(exc)
                phone_log(progress, f"Lease {lease.ip} did not accept phone SSH login; still waiting.")
        raise TimeoutError(f"Timed out waiting for a DHCP lease with phone SSH login: {last_error}")
    finally:
        server.stop()


def phone_find_by_scan(config, progress=None):
    hosts = [str(host) for host in config.scan_subnet.hosts()]
    phone_log(progress, f"Scanning {config.scan_subnet} for SSH on port {config.ssh_port}...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as pool:
        futures = {
            pool.submit(phone_tcp_port_open, host, config.ssh_port, 1.5): host
            for host in hosts
        }
        candidates = []
        for future in concurrent.futures.as_completed(futures):
            host = futures[future]
            try:
                if future.result():
                    candidates.append(host)
                    phone_log(progress, f"SSH open: {host}")
            except OSError:
                pass

    authenticated = []
    for candidate in sorted(candidates, key=ipaddress.ip_address):
        try:
            client = phone_ssh_connect(candidate, config)
            client.close()
            authenticated.append(candidate)
            phone_log(progress, f"Phone login OK: {candidate}")
        except Exception as exc:
            phone_log(progress, f"Skipping {candidate}: {exc}")

    if not authenticated:
        raise RuntimeError("No scanned SSH hosts accepted the phone login.")
    if len(authenticated) > 1:
        raise RuntimeError("More than one device accepted the phone login. Use DHCP mode or isolate one phone.")
    return PhoneDhcpLease(ipaddress.ip_address(authenticated[0]), "", "", "")


def phone_interfaces_content(target_ip, config):
    return "\n".join(
        [
            "# Configure Loopback",
            "auto lo",
            "iface lo inet loopback",
            "",
            "auto eth0",
            "iface eth0 inet static",
            f"address {target_ip}",
            f"netmask {config.netmask}",
            f"gateway {config.gateway}",
            f"server  {config.tftp_server}",
            "",
        ]
    )


def phone_sh_single_quote(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"


def phone_run_ssh_command(client, command, timeout=30):
    _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    exit_code = stdout.channel.recv_exit_status()
    return exit_code, stdout.read().decode(errors="replace"), stderr.read().decode(errors="replace")


def phone_write_config(dhcp_ip, target_ip, config, progress=None):
    content = phone_interfaces_content(target_ip, config)
    tftp_content = config.tftp_server + "\n"
    backup_suffix = time.strftime("%Y%m%d-%H%M%S")
    command = "\n".join(
        [
            "set -e",
            f"cp /etc/network/interfaces /etc/network/interfaces.bak-ip-switcher-{backup_suffix}",
            f"cp /etc/tftp_server /etc/tftp_server.bak-ip-switcher-{backup_suffix}",
            f"printf %s {phone_sh_single_quote(content)} > /etc/network/interfaces",
            f"printf %s {phone_sh_single_quote(tftp_content)} > /etc/tftp_server",
            "sync",
            "(sleep 1; reboot) >/dev/null 2>&1 &",
        ]
    )
    phone_log(progress, f"Connecting to {dhcp_ip} over SSH...")
    client = phone_ssh_connect(dhcp_ip, config)
    try:
        phone_log(progress, f"Writing static IP {target_ip} and TFTP server {config.tftp_server}...")
        exit_code, stdout_text, stderr_text = phone_run_ssh_command(client, command, timeout=30)
        if exit_code != 0:
            raise RuntimeError(
                f"Remote configuration failed with exit code {exit_code}\n"
                f"stdout: {stdout_text}\n"
                f"stderr: {stderr_text}"
            )
    finally:
        client.close()


def phone_read_remote_mac(host, config):
    client = phone_ssh_connect(host, config)
    try:
        exit_code, stdout_text, _stderr_text = phone_run_ssh_command(
            client,
            "cat /sys/class/net/eth0/address 2>/dev/null || true",
            timeout=10,
        )
    finally:
        client.close()
    if exit_code != 0:
        return ""
    return stdout_text.strip().lower()


def phone_interface_has_ip(interface_name, ip_address):
    escaped_name = interface_name.replace("'", "''")
    escaped_ip = str(ip_address).replace("'", "''")
    script = f"""
$ErrorActionPreference = 'Stop'
$match = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias '{escaped_name}' -ErrorAction SilentlyContinue |
    Where-Object {{ $_.IPAddress -eq '{escaped_ip}' }} |
    Select-Object -First 1
if ($match) {{ 'true' }} else {{ 'false' }}
"""
    result = run_powershell(script)
    return result.returncode == 0 and result.stdout.strip().lower() == "true"


def phone_wait_for_interface_ip(config, progress=None, timeout_seconds=20):
    deadline = time.monotonic() + timeout_seconds
    phone_log(progress, f"Waiting for Windows to apply {config.dhcp_server_ip} on {config.staging_interface}...")
    while time.monotonic() < deadline:
        if phone_interface_has_ip(config.staging_interface, config.dhcp_server_ip):
            phone_log(progress, f"Confirmed {config.staging_interface} has {config.dhcp_server_ip}.")
            return
        time.sleep(1)
    raise RuntimeError(
        f"{config.staging_interface} did not show {config.dhcp_server_ip} within {timeout_seconds} seconds."
    )


def phone_apply_staging_interface(config, progress=None):
    if not config.use_dhcp_server:
        return

    args = [
        "netsh",
        "interface",
        "ipv4",
        "set",
        "address",
        f"name={config.staging_interface}",
        "source=static",
        f"address={config.dhcp_server_ip}",
        f"mask={config.netmask}",
        f"gateway={config.gateway or 'none'}",
    ]
    phone_log(progress, f"Setting {config.staging_interface} to {config.dhcp_server_ip}/{config.netmask}...")
    result = run_hidden(args)
    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip()
            or result.stdout.strip()
            or f"Could not set {config.staging_interface} to {config.dhcp_server_ip}."
        )
    phone_wait_for_interface_ip(config, progress)
    phone_log(progress, f"{config.staging_interface} is ready for DHCP hosting.")


def phone_ping_once(host):
    command = ["ping", "-n", "1", "-w", "1000", str(host)]
    result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=CREATE_NO_WINDOW)
    return result.returncode == 0


def phone_wait_for_ping(host, timeout_seconds, interval_seconds, progress=None):
    deadline = time.monotonic() + timeout_seconds
    success_count = 0
    phone_log(progress, f"Waiting for ping replies from {host}...")
    while time.monotonic() < deadline:
        if phone_ping_once(host):
            success_count += 1
            phone_log(progress, f"Ping reply {success_count}/3")
            if success_count >= 3:
                return True
        else:
            success_count = 0
        time.sleep(interval_seconds)
    return False


def phone_normalize_remote_text(value):
    value = value.replace("\r\n", "\n").replace("\r", "\n")
    return "\n".join(line.rstrip() for line in value.strip().split("\n"))


def phone_verify_settings(host, target_ip, config):
    expected_interfaces = phone_normalize_remote_text(phone_interfaces_content(target_ip, config))
    expected_tftp = phone_normalize_remote_text(config.tftp_server)
    marker = "---IP-SWITCHER-TFTP---"
    command = f"cat /etc/network/interfaces; printf '\\n{marker}\\n'; cat /etc/tftp_server"
    client = phone_ssh_connect(host, config)
    try:
        exit_code, stdout_text, stderr_text = phone_run_ssh_command(client, command, timeout=15)
    finally:
        client.close()
    if exit_code != 0:
        return False, f"Could not read remote config: {stderr_text.strip()}"
    if marker not in stdout_text:
        return False, "Could not parse remote config output."
    interfaces_text, tftp_text = stdout_text.split(marker, 1)
    if phone_normalize_remote_text(interfaces_text) != expected_interfaces:
        return False, "Remote /etc/network/interfaces does not match expected static config."
    if phone_normalize_remote_text(tftp_text) != expected_tftp:
        return False, "Remote /etc/tftp_server does not match expected TFTP server."
    return True, "Ping and SSH file verification succeeded."


def phone_wait_for_settings_verification(host, target_ip, config, progress=None):
    deadline = time.monotonic() + config.ping_timeout_seconds
    last_message = ""
    phone_log(progress, f"Verifying actual settings over SSH on {host}...")
    while time.monotonic() < deadline:
        try:
            verified, message = phone_verify_settings(host, target_ip, config)
            if verified:
                phone_log(progress, "SSH settings verification OK.")
                return True, message
            last_message = message
        except Exception as exc:
            last_message = str(exc)
        time.sleep(config.ping_interval_seconds)
    return False, last_message or "SSH settings verification timed out."


def phone_configure_next(config, progress=None):
    state = phone_load_state()
    target_ip = phone_next_target_ip(config, state)
    phone_apply_staging_interface(config, progress)
    conflicting_servers = phone_probe_other_dhcp_servers(config, progress)
    if conflicting_servers:
        details = "\n".join(
            f"Server {item['server']} offered {item['offered_ip']}"
            for item in conflicting_servers
        )
        raise RuntimeError(
            "Another DHCP server was detected on the selected interface.\n"
            f"{details}\n"
            "The built-in DHCP server was not started. Use an isolated switch/VLAN/direct cable, "
            "or disable the other DHCP server for the provisioning port."
        )
    lease = phone_find_with_dhcp_server(config, progress) if config.use_dhcp_server else phone_find_by_scan(config, progress)
    phone_log(progress, f"Planned assignment: DHCP {lease.ip} -> static {target_ip}")
    phone_mac = lease.mac
    if not phone_mac:
        try:
            phone_mac = phone_read_remote_mac(lease.ip, config)
            if phone_mac:
                phone_log(progress, f"Phone MAC: {phone_mac}")
        except Exception as exc:
            phone_log(progress, f"Could not read phone MAC before configuration: {exc}")
    log_base = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "mac": phone_mac,
        "dhcp_ip": str(lease.ip),
        "target_ip": str(target_ip),
        "netmask": config.netmask,
        "gateway": config.gateway,
        "tftp_server": config.tftp_server,
    }

    phone_append_assignment(state, lease.ip, target_ip, "pending", dhcp_mac=phone_mac)
    phone_save_state(state)
    try:
        phone_write_config(lease.ip, target_ip, config, progress)
        phone_update_assignment(state, target_ip, "rebooting")
        phone_save_state(state)

        if not phone_wait_for_ping(target_ip, config.ping_timeout_seconds, config.ping_interval_seconds, progress):
            phone_update_assignment(state, target_ip, "failed", "Timed out waiting for ping.")
            phone_save_state(state)
            raise RuntimeError(f"{target_ip} did not respond to ping before timeout.")

        verified, message = phone_wait_for_settings_verification(target_ip, target_ip, config, progress)
        if not verified:
            phone_update_assignment(state, target_ip, "failed", message)
            phone_save_state(state)
            raise RuntimeError(message)

        phone_update_assignment(state, target_ip, "configured", message)
        phone_save_state(state)
        try:
            log_path = phone_append_config_log({**log_base, "status": "configured", "message": message})
            if log_path != PHONE_CONFIG_LOG_FILE:
                phone_log(progress, f"Main CSV log was locked; wrote assignment to {os.path.basename(log_path)}.")
        except OSError as log_exc:
            phone_log(progress, f"Could not write phone assignment log: {log_exc}")
        phone_log(progress, f"Success: {target_ip} is responding and settings were verified.")
        return target_ip
    except Exception as exc:
        phone_update_assignment(state, target_ip, "failed", str(exc))
        phone_save_state(state)
        try:
            log_path = phone_append_config_log({**log_base, "status": "failed", "message": str(exc)})
            if log_path != PHONE_CONFIG_LOG_FILE:
                phone_log(progress, f"Main CSV log was locked; wrote assignment to {os.path.basename(log_path)}.")
        except OSError as log_exc:
            phone_log(progress, f"Could not write phone assignment log: {log_exc}")
        raise
