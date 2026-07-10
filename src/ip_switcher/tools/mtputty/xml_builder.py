import os
import uuid
import xml.dom.minidom as minidom
import xml.etree.ElementTree as ET

from ...constants import MTPUTTY_PASSWORD_TOKEN
from ...network import validate_ipv4


def parse_multiping_file(file_path):
    entries = []
    with open(file_path, "r", encoding="utf-8-sig") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split(maxsplit=1)
            ip = validate_ipv4(parts[0], f"Line {line_number} IP address")
            name = parts[1].strip() if len(parts) > 1 else ""
            entries.append({"ip": ip, "name": name})

    if not entries:
        raise ValueError("The selected file does not contain any IP entries.")
    return entries


def mtputty_display_name(entry):
    return f"{entry['ip']} {entry['name']}".strip()


def mtputty_category_name(file_path):
    name = os.path.splitext(os.path.basename(file_path))[0].strip()
    if name.lower().startswith("multiping "):
        name = name[10:].strip()
    return name or "Imported devices"


def add_mtputty_hosts(parent, entries, username, port, commands):
    for entry in entries:
        ip = entry["ip"]
        node = ET.SubElement(parent, "Node", {"Type": "1"})
        ET.SubElement(node, "SavedSession").text = "Default Settings"
        ET.SubElement(node, "DisplayName").text = mtputty_display_name(entry)
        ET.SubElement(node, "UID").text = str(uuid.uuid4())
        ET.SubElement(node, "ServerName").text = ip
        ET.SubElement(node, "PuttyConType").text = "4"
        ET.SubElement(node, "Port").text = str(port)
        ET.SubElement(node, "UserName").text = username
        ET.SubElement(node, "Password").text = MTPUTTY_PASSWORD_TOKEN
        ET.SubElement(node, "PasswordDelay").text = "10"
        ET.SubElement(node, "CLParams").text = f"{ip} -ssh -P {port} -l {username} -pw *****"
        ET.SubElement(node, "ScriptDelay").text = "50"
        script_node = ET.SubElement(node, "Script")
        for index, command in enumerate(commands):
            ET.SubElement(script_node, f"L{index}").text = command


def build_mtputty_tree(entries, folder_name, username, port, commands):
    servers = ET.Element("Servers")
    putty = ET.SubElement(servers, "Putty")
    folder = ET.SubElement(putty, "Node", {"Type": "0", "Expanded": "1"})
    ET.SubElement(folder, "DisplayName").text = folder_name
    add_mtputty_hosts(folder, entries, username, port, commands)
    return servers


def build_mtputty_category_tree(categories, root_folder_name, username, port, commands):
    if not categories:
        raise ValueError("Add at least one multiping text file.")

    servers = ET.Element("Servers")
    putty = ET.SubElement(servers, "Putty")

    for category in categories:
        folder = ET.SubElement(putty, "Node", {"Type": "0", "Expanded": "1"})
        ET.SubElement(folder, "DisplayName").text = category["name"]
        add_mtputty_hosts(folder, category["entries"], username, port, commands)

    return servers


def pretty_xml_bytes(root):
    rough_xml = ET.tostring(root, "utf-8")
    return minidom.parseString(rough_xml).toprettyxml(indent="\t", encoding="UTF-8")


def export_mtputty_xml(input_path, output_path, folder_name, username, port, commands):
    entries = parse_multiping_file(input_path)
    root = build_mtputty_tree(entries, folder_name, username, port, commands)
    with open(output_path, "wb") as handle:
        handle.write(pretty_xml_bytes(root))
    return len(entries)


def export_mtputty_xml_files(input_paths, output_path, root_folder_name, username, port, commands):
    if not input_paths:
        raise ValueError("Add at least one multiping text file.")

    unique_paths = []
    seen = set()
    for path in input_paths:
        normalized = os.path.abspath(path)
        if normalized not in seen:
            seen.add(normalized)
            unique_paths.append(normalized)

    if len(unique_paths) == 1:
        path = unique_paths[0]
        entries = parse_multiping_file(path)
        folder_name = root_folder_name or mtputty_category_name(path)
        root = build_mtputty_tree(entries, folder_name, username, port, commands)
        count = len(entries)
    else:
        categories = []
        count = 0
        for path in unique_paths:
            entries = parse_multiping_file(path)
            categories.append(
                {
                    "name": mtputty_category_name(path),
                    "entries": entries,
                }
            )
            count += len(entries)
        root = build_mtputty_category_tree(
            categories,
            root_folder_name,
            username,
            port,
            commands,
        )

    with open(output_path, "wb") as handle:
        handle.write(pretty_xml_bytes(root))
    return count
