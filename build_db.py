import sqlite3
import yaml
import re
import ipaddress
import json
import os

# Define the base directory for output files
OUTPUTS_DIR = "outputs"

def create_db_and_tables(db_name="network.db"): # <-- ENSURE THIS IS "network.db"
    """
    Creates the SQLite database and necessary tables for network inventory.
    Drops existing inventory tables first to ensure schema is up-to-date.
    """
    conn = None
    try:
        conn = sqlite3.connect(db_name)
        cursor = conn.cursor()

        # ONLY DROP TABLES MANAGED BY THIS SCRIPT (inventory tables)
        cursor.execute("DROP TABLE IF EXISTS route_entries;")
        cursor.execute("DROP TABLE IF EXISTS arp_entries;")
        cursor.execute("DROP TABLE IF EXISTS interfaces;")
        cursor.execute("DROP TABLE IF EXISTS devices;")
        print("Dropped existing inventory tables (if any) to ensure schema consistency.")

        # Create devices table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                device_id INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname TEXT UNIQUE NOT NULL,
                device_type TEXT
            );
        """)

        # Create interfaces table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS interfaces (
                interface_id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER,
                name TEXT NOT NULL,
                ipv4_address TEXT,
                ipv4_subnet TEXT,
                mac_address TEXT,
                description TEXT,
                status TEXT,
                type TEXT,
                FOREIGN KEY (device_id) REFERENCES devices(device_id)
            );
        """)

        # Create arp_entries table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS arp_entries (
                arp_id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER,
                ip_address TEXT NOT NULL,
                mac_address TEXT NOT NULL,
                interface_name TEXT,
                FOREIGN KEY (device_id) REFERENCES devices(device_id)
            );
        """)

        # Create route_entries table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS route_entries (
                route_id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER,
                destination_network TEXT NOT NULL,
                next_hop TEXT,
                metric INTEGER,
                admin_distance INTEGER,
                interface_name TEXT,
                route_type TEXT,
                flags TEXT,
                FOREIGN KEY (device_id) REFERENCES devices(device_id)
            );
        """)

        conn.commit()
        print(f"Database '{db_name}' and inventory tables created/verified successfully.")
    except sqlite3.Error as e:
        print(f"Error creating database or tables: {e}")
    finally:
        if conn:
            conn.close()

def insert_device(cursor, hostname, device_type):
    """Inserts a device and returns its device_id. Handles existing devices."""
    cursor.execute("INSERT OR IGNORE INTO devices (hostname, device_type) VALUES (?, ?)", (hostname, device_type))
    cursor.execute("SELECT device_id FROM devices WHERE hostname = ?", (hostname,))
    return cursor.fetchone()[0]

def parse_cisco_interface_data(interface_data):
    """Parses Cisco interface data."""
    interfaces = []
    if isinstance(interface_data, dict):
        for iface_name, details in interface_data.items():
            ipv4_address = None
            ipv4_subnet = None
            if details.get('ipv4'):
                # Assuming the first IPv4 address is the primary one
                first_ipv4 = details['ipv4'][0]
                iface_ipv4_address = first_ipv4.get('address')
                iface_ipv4_subnet = first_ipv4.get('subnet')

            interfaces.append({
                'name': iface_name,
                'ipv4_address': iface_ipv4_address,
                'ipv4_subnet': iface_ipv4_subnet,
                'mac_address': details.get('macaddress'),
                'description': details.get('description'),
                'status': f"{details.get('lineprotocol')}/{details.get('operstatus')}",
                'type': details.get('type')
            })
    return interfaces

def parse_paloalto_interface_data(interface_data):
    """Parses Palo Alto interface data."""
    interfaces = []
    if isinstance(interface_data, list):
        for details in interface_data:
            iface_ipv4_address = None
            iface_ipv4_subnet = None
            if details.get('ip'):
                # Assuming the first IP is the primary one
                ip_with_mask = details['ip'][0]
                if '/' in ip_with_mask:
                    ip_obj = ipaddress.ip_interface(ip_with_mask)
                    iface_ipv4_address = str(ip_obj.ip)
                    iface_ipv4_subnet = str(ip_obj.network.prefixlen)

            interfaces.append({
                'name': details.get('name'),
                'ipv4_address': iface_ipv4_address,
                'ipv4_subnet': iface_ipv4_subnet,
                'mac_address': None, # Palo Alto interface data might not directly provide MAC in this format
                'description': details.get('comment'),
                'status': None, # Status might require different parsing
                'type': None # Type might require different parsing
            })
    return interfaces

def parse_fortigate_interface_data(interface_data):
    """Parses FortiGate interface data."""
    interfaces = []
    if isinstance(interface_data, dict):
        for iface_id, details in interface_data.items():
            iface_ipv4_address = details.get('ip')
            iface_ipv4_subnet = details.get('mask')
            interfaces.append({
                'name': details.get('name'),
                'ipv4_address': iface_ipv4_address,
                'ipv4_subnet': iface_ipv4_subnet,
                'mac_address': details.get('mac'),
                'description': details.get('alias'),
                'status': f"link:{'up' if details.get('link') else 'down'}",
                'type': None # FortiGate interface type might be more granular than a simple field
            })
    return interfaces


def parse_cisco_arp_data(arp_output):
    """Parses Cisco ARP data from plain text."""
    arp_entries = []
    lines = arp_output.strip().split('\n')
    # Regex to match lines like: "Internet  10.0.1.1              15   0050.7966.6800  ARPA   GigabitEthernet0/0"
    arp_pattern = re.compile(r'Internet\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\S+\s+([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+\S+\s+(.+)')
    for line in lines:
        match = arp_pattern.match(line)
        if match:
            ip_address, mac_address, interface_name = match.groups()
            arp_entries.append({
                'ip_address': ip_address,
                'mac_address': mac_address,
                'interface_name': interface_name.strip()
            })
    return arp_entries

def parse_paloalto_arp_data(arp_json_str):
    """Parses Palo Alto ARP data from JSON string."""
    arp_entries = []
    try:
        data = json.loads(arp_json_str)
        entries = data.get('response', {}).get('result', {}).get('entries', {}).get('entry', [])
        for entry in entries:
            arp_entries.append({
                'ip_address': entry.get('ip'),
                'mac_address': entry.get('mac'),
                'interface_name': entry.get('interface')
            })
    except json.JSONDecodeError as e:
        print(f"Error decoding Palo Alto ARP JSON: {e}")
    return arp_entries

def parse_fortigate_arp_data(arp_yaml_str):
    """Parses FortiGate ARP data from YAML string."""
    arp_entries = []
    try:
        data = yaml.safe_load(arp_yaml_str)
        results = data.get('meta', {}).get('results', [])
        for entry in results:
            arp_entries.append({
                'ip_address': entry.get('ip'),
                'mac_address': entry.get('mac'),
                'interface_name': entry.get('interface')
            })
    except yaml.YAMLError as e:
        print(f"Error decoding FortiGate ARP YAML: {e}")
    return arp_entries

def parse_cisco_route_data(route_output):
    """Parses Cisco route data from plain text."""
    routes = []
    lines = route_output.strip().split('\n')
    
    # Regex for static/connected/local routes and OSPF
    # Captures: route_type, destination_network, admin_distance, metric, next_hop, interface_name
    # Group 1: Route Code (e.g., S*, C, O)
    # Group 2: Destination Network
    # Group 3: Admin Distance (optional)
    # Group 4: Metric (optional)
    # Group 5: Next Hop (optional)
    # Group 6: Time (optional, ignored)
    # Group 7: Interface Name (optional)
    route_pattern = re.compile(
        r'^\s*([CSOLDRBEIiaNnEe]\*?)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)(?: \[\s*(\d+)\s*/\s*(\d+)\s*\])?(?: via (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:, \S+)?(?:, (\S+))?)?'
    )
    
    # Specific pattern for directly connected routes that don't have 'via' next-hop
    direct_connected_pattern = re.compile(
        r'^\s*([CL])\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)\s+is directly connected,\s+(\S+)'
    )

    for line in lines:
        # Try direct connected pattern first
        match = direct_connected_pattern.match(line)
        if match:
            route_type_code, dest_net, iface_name = match.groups()
            route_type = {
                'C': 'connected',
                'L': 'local'
            }.get(route_type_code, route_type_code)
            routes.append({
                'destination_network': dest_net,
                'next_hop': None, # Directly connected routes don't have a next hop in the traditional sense
                'metric': None,
                'admin_distance': None,
                'interface_name': iface_name.strip(),
                'route_type': route_type,
                'flags': route_type_code
            })
            continue

        # Then try general route pattern
        match = route_pattern.match(line)
        if match:
            route_type_code, dest_net, admin_distance, metric, next_hop, iface_name = match.groups()
            
            # Map common codes to more descriptive types
            route_type = {
                'S': 'static', 'S*': 'static default',
                'C': 'connected', 'L': 'local',
                'O': 'ospf', 'IA': 'ospf inter area',
                'N1': 'ospf nssa external type 1', 'N2': 'ospf nssa external type 2',
                'E1': 'ospf external type 1', 'E2': 'ospf external type 2',
                'D': 'eigrp', 'EX': 'eigrp external',
                'R': 'rip', 'B': 'bgp',
                'i': 'is-is', 'su': 'is-is summary',
                'L1': 'is-is level-1', 'L2': 'is-is level-2',
                'ia': 'is-is inter area'
            }.get(route_type_code, route_type_code) # Fallback to code if not mapped

            routes.append({
                'destination_network': dest_net,
                'next_hop': next_hop if next_hop else None,
                'metric': int(metric) if metric else None,
                'admin_distance': int(admin_distance) if admin_distance else None,
                'interface_name': iface_name.strip() if iface_name else None,
                'route_type': route_type,
                'flags': route_type_code
            })

    # Handle "Gateway of last resort" if present, only if a default route (0.0.0.0/0) isn't already captured by the general pattern
    if "Gateway of last resort" in route_output and not any(r['destination_network'] == "0.0.0.0/0" for r in routes):
        gateway_match = re.search(r'Gateway of last resort is (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) to network 0.0.0.0', route_output)
        if gateway_match:
            default_gw = gateway_match.group(1)
            # Find the static default route that uses this gateway
            static_default_match = re.search(r'S\*\s+0\.0\.0\.0/0\s+\[(\d+)/(\d+)\] via (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', route_output)
            if static_default_match:
                ad, metric, nh = static_default_match.groups()
                routes.append({
                    'destination_network': '0.0.0.0/0',
                    'next_hop': nh,
                    'metric': int(metric),
                    'admin_distance': int(ad),
                    'interface_name': None, # Interface might not be explicit in summary line
                    'route_type': 'static default',
                    'flags': 'S*'
                })

    return routes

def parse_paloalto_route_data(route_json_str):
    """Parses Palo Alto route data from JSON string."""
    routes = []
    try:
        data = json.loads(route_json_str)
        entries = data.get('response', {}).get('result', {}).get('entry', [])
        for entry in entries:
            # Extract flags and map them to common types
            flags_str = entry.get('flags', '')
            route_type = "unknown"
            if 'C' in flags_str: route_type = 'connected'
            elif 'S' in flags_str: route_type = 'static'
            elif 'R' in flags_str: route_type = 'rip'
            elif 'O' in flags_str: route_type = 'ospf'
            elif 'B' in flags_str: route_type = 'bgp'
            elif 'Oi' in flags_str: route_type = 'ospf intra-area'
            elif 'Oo' in flags_str: route_type = 'ospf inter-area'
            elif 'O1' in flags_str: route_type = 'ospf ext-type-1'
            elif 'O2' in flags_str: route_type = 'ospf ext-type-2'

            routes.append({
                'destination_network': entry.get('destination'),
                'next_hop': entry.get('nexthop') if entry.get('nexthop') != '0.0.0.0' else None, # 0.0.0.0 means connected
                'metric': int(entry['metric']) if entry.get('metric') is not None else None,
                'admin_distance': None, # Palo Alto output doesn't seem to have explicit AD in this format
                'interface_name': entry.get('interface'),
                'route_type': route_type,
                'flags': flags_str
            })
    except json.JSONDecodeError as e:
        print(f"Error decoding Palo Alto Route JSON: {e}")
    return routes

def parse_fortigate_route_data(route_yaml_str):
    """Parses FortiGate route data from YAML string."""
    routes = []
    try:
        data = yaml.safe_load(route_yaml_str)
        results = data.get('meta', {}).get('results', [])
        for entry in results:
            routes.append({
                'destination_network': entry.get('ip_mask'),
                'next_hop': entry.get('gateway'),
                'metric': entry.get('metric'),
                'admin_distance': entry.get('distance'),
                'interface_name': entry.get('interface'),
                'route_type': entry.get('type'),
                'flags': None # FortiGate YAML doesn't have a direct 'flags' field in this format
            })
    except yaml.YAMLError as e:
        print(f"Error decoding FortiGate Route YAML: {e}")
    return routes


def process_device_data(db_name, hostname, device_type, interface_filename, arp_filename, route_filename):
    """Processes data for a single device and populates the database."""
    conn = None
    try:
        conn = sqlite3.connect(db_name)
        cursor = conn.cursor()

        device_id = insert_device(cursor, hostname, device_type)
        print(f"Processing data for {hostname} (Device ID: {device_id})...")

        # --- Clear existing data for this device before inserting new data ---
        cursor.execute("DELETE FROM interfaces WHERE device_id = ?", (device_id,))
        cursor.execute("DELETE FROM arp_entries WHERE device_id = ?", (device_id,))
        cursor.execute("DELETE FROM route_entries WHERE device_id = ?", (device_id,))
        print(f"Cleared old interface, ARP, and route entries for {hostname}.")
        # --- End Clear ---

        # Process Interface data
        if interface_filename:
            interface_file_path = os.path.join(OUTPUTS_DIR, interface_filename)
            with open(interface_file_path, 'r') as f:
                iface_content = yaml.safe_load(f)
            
            interfaces_data = []
            if device_type == "Router" or device_type == "Switch": # Cisco devices
                interfaces_data = parse_cisco_interface_data(iface_content.get('ansible_net_interfaces', {}))
            elif device_type == "Firewall" and hostname == "pafw": # Palo Alto
                interfaces_data = parse_paloalto_interface_data(iface_content.get('ansible_facts', {}).get('ansible_net_interfaces', []))
            elif device_type == "Firewall" and hostname == "fgt": # FortiGate
                interfaces_data = parse_fortigate_interface_data(iface_content.get('meta', {}).get('results', {}))

            for iface in interfaces_data:
                cursor.execute("""
                    INSERT INTO interfaces (device_id, name, ipv4_address, ipv4_subnet, mac_address, description, status, type)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (device_id, iface.get('name'), iface.get('ipv4_address'), iface.get('ipv4_subnet'),
                      iface.get('mac_address'), iface.get('description'), iface.get('status'), iface.get('type')))
            print(f"Inserted {len(interfaces_data)} interfaces for {hostname}.")

        # Process ARP data
        if arp_filename:
            arp_file_path = os.path.join(OUTPUTS_DIR, arp_filename)
            with open(arp_file_path, 'r') as f:
                arp_content = f.read()
            
            arp_data = []
            if device_type == "Router" or device_type == "Switch": # Cisco devices
                arp_data = parse_cisco_arp_data(arp_content)
            elif device_type == "Firewall" and hostname == "pafw": # Palo Alto
                arp_data = parse_paloalto_arp_data(arp_content)
            elif device_type == "Firewall" and hostname == "fgt": # FortiGate
                arp_data = parse_fortigate_arp_data(arp_content)

            for arp in arp_data:
                cursor.execute("""
                    INSERT INTO arp_entries (device_id, ip_address, mac_address, interface_name)
                    VALUES (?, ?, ?, ?)
                """, (device_id, arp.get('ip_address'), arp.get('mac_address'), arp.get('interface_name')))
            print(f"Inserted {len(arp_data)} ARP entries for {hostname}.")

        # Process Route data
        if route_filename:
            route_file_path = os.path.join(OUTPUTS_DIR, route_filename)
            with open(route_file_path, 'r') as f:
                route_content = f.read()
            
            route_data = []
            if device_type == "Router" or device_type == "Switch": # Cisco devices
                route_data = parse_cisco_route_data(route_content)
            elif device_type == "Firewall" and hostname == "pafw": # Palo Alto
                route_data = parse_paloalto_route_data(route_content)
            elif device_type == "Firewall" and hostname == "fgt": # FortiGate
                route_data = parse_fortigate_route_data(route_content)

            for route in route_data:
                cursor.execute("""
                    INSERT INTO route_entries (device_id, destination_network, next_hop, metric, admin_distance, interface_name, route_type, flags)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (device_id, route.get('destination_network'), route.get('next_hop'),
                      route.get('metric'), route.get('admin_distance'), route.get('interface_name'),
                      route.get('route_type'), route.get('flags')))
            print(f"Inserted {len(route_data)} route entries for {hostname}.")

        conn.commit()
        print(f"Successfully processed data for {hostname}.")

    except sqlite3.Error as e:
        print(f"Database error processing {hostname}: {e}")
    except FileNotFoundError as e:
        print(f"File not found for {hostname}: {e}")
    except Exception as e:
        print(f"An unexpected error occurred processing {hostname}: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    db_name = "network.db" # <-- THIS LINE NEEDS TO BE "network.db"
    create_db_and_tables(db_name)

    # Dictionary to store grouped file paths for each device
    device_files = {}

    # Scan the outputs directory to find and group device data files
    for filename in os.listdir(OUTPUTS_DIR):
        hostname = None
        device_type = None
        file_category = None # 'interfaces', 'arp', 'routes'

        # Infer device type based on hostname prefix or specific filename patterns
        if filename.startswith('R') and ('_interfaces.yml' in filename or '_arp.txt' in filename or '_routes.txt' in filename):
            hostname = filename.split('_')[0]
            device_type = "Router"
        elif filename.startswith('SW') and ('_interfaces.yml' in filename or '_arp.txt' in filename or '_routes.txt' in filename):
            hostname = filename.split('_')[0]
            device_type = "Switch"
        elif filename.startswith('pafw_') and ('_interfaces.yml' in filename or '_arp.txt' in filename or '_routes.txt' in filename):
            hostname = "pafw"
            device_type = "Firewall"
        elif filename.startswith('fgt_') and ('_interfaces.yml' in filename or '_arp.yml' in filename or '_routes.yml' in filename):
            hostname = "fgt"
            device_type = "Firewall"
        
        # Determine file category
        if hostname:
            if '_interfaces.yml' in filename:
                file_category = 'interfaces'
            elif '_arp.txt' in filename or '_arp.yml' in filename:
                file_category = 'arp'
            elif '_routes.txt' in filename or '_routes.yml' in filename:
                file_category = 'routes'
            
            if file_category:
                if hostname not in device_files:
                    device_files[hostname] = {'type': device_type, 'interfaces': None, 'arp': None, 'routes': None}
                device_files[hostname][file_category] = filename

    # Process data for each discovered device
    for hostname, files_info in device_files.items():
        process_device_data(
            db_name,
            hostname,
            files_info['type'],
            files_info['interfaces'],
            files_info['arp'],
            files_info['routes']
        )
    print("\nDatabase import process completed.")
