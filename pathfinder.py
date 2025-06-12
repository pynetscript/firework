import sqlite3
import ipaddress
import sys
import json # Import json for structured output

class NetworkPathfinder:
    def __init__(self, db_name="network.db"):
        self.db_name = db_name
        self.conn = None
        self.cursor = None
        self._connect_db()

    def _connect_db(self):
        """Establishes a connection to the SQLite database."""
        try:
            self.conn = sqlite3.connect(self.db_name)
            self.cursor = self.conn.cursor()
        except sqlite3.Error as e:
            print(f"Error connecting to database {self.db_name}: {e}")
            sys.exit(1) # Exit if can't connect to db

    def _close_db(self):
        """Closes the database connection."""
        if self.conn:
            self.conn.close()

    def _get_device_by_ip(self, ip_address_str):
        """
        Finds the device (hostname and ID) that has an interface configured with the given IP
        or has a directly connected network that contains the IP.
        Returns (device_id, hostname) or None if not found.
        """
        try:
            ip_obj = ipaddress.ip_address(ip_address_str)
        except ipaddress.AddressValueError:
            print(f"Invalid IP address format: {ip_address_str}")
            return None, None

        # Check for exact match on an interface IP
        self.cursor.execute("""
            SELECT d.device_id, d.hostname
            FROM devices d
            JOIN interfaces i ON d.device_id = i.device_id
            WHERE i.ipv4_address = ?
        """, (ip_address_str,))
        result = self.cursor.fetchone()
        if result:
            return result[0], result[1]

        # If no exact match, check if the IP belongs to any directly connected subnet
        self.cursor.execute("""
            SELECT d.device_id, d.hostname, i.ipv4_address, i.ipv4_subnet
            FROM devices d
            JOIN interfaces i ON d.device_id = i.device_id
            WHERE i.ipv4_address IS NOT NULL AND i.ipv4_subnet IS NOT NULL
        """)
        connected_interfaces = self.cursor.fetchall()

        for dev_id, hostname, iface_ip, iface_subnet in connected_interfaces:
            try:
                network_str = f"{iface_ip}/{iface_subnet}"
                network_obj = ipaddress.ip_network(network_str, strict=False)
                if ip_obj in network_obj:
                    # Found a connected network that contains the IP
                    return dev_id, hostname
            except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
                continue
        return None, None

    def _get_best_route(self, device_id, destination_ip_str):
        """
        Finds the best route for a given destination IP on a specific device.
        Prioritizes by:
        1. Longest prefix match
        2. Lowest Administrative Distance
        3. Lowest Metric
        Returns (next_hop, interface_name, route_type) or None
        """
        try:
            destination_ip_obj = ipaddress.ip_address(destination_ip_str)
        except ipaddress.AddressValueError:
            return None, None, None

        self.cursor.execute("""
            SELECT destination_network, next_hop, metric, admin_distance, interface_name, route_type, flags
            FROM route_entries
            WHERE device_id = ?
        """, (device_id,))
        routes = self.cursor.fetchall()

        best_route = None
        best_prefix_length = -1

        for route in routes:
            dest_net_str, next_hop, metric, admin_distance, iface_name, route_type, flags = route

            try:
                # Handle default route explicitly as 0.0.0.0/0
                if dest_net_str == "0.0.0.0/0":
                    network_obj = ipaddress.ip_network("0.0.0.0/0")
                else:
                    network_obj = ipaddress.ip_network(dest_net_str, strict=False)

                if destination_ip_obj in network_obj:
                    current_prefix_length = network_obj.prefixlen

                    if best_route is None:
                        best_route = route
                        best_prefix_length = current_prefix_length
                    else:
                        # Apply routing logic: Longest prefix match first
                        if current_prefix_length > best_prefix_length:
                            best_route = route
                            best_prefix_length = current_prefix_length
                        elif current_prefix_length == best_prefix_length:
                            # Then Administrative Distance (lower is better)
                            current_ad = admin_distance if admin_distance is not None else float('inf')
                            best_ad = best_route[3] if best_route[3] is not None else float('inf')

                            if current_ad < best_ad:
                                best_route = route
                            elif current_ad == best_ad:
                                # Then Metric (lower is better)
                                current_metric = metric if metric is not None else float('inf')
                                best_metric = best_route[2] if best_route[2] is not None else float('inf')
                                if current_metric < best_metric:
                                    best_route = route
            except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
                continue

        if best_route:
            return best_route[1], best_route[4], best_route[5] # next_hop, interface_name, route_type
        return None, None, None

    def get_device_type(self, hostname):
        """
        Retrieves the device_type for a given hostname from the database.
        Returns the device_type string or None if not found.
        """
        self.cursor.execute("""
            SELECT device_type FROM devices WHERE hostname = ?
        """, (hostname,))
        result = self.cursor.fetchone()
        return result[0] if result else None

    def find_network_path(self, source_ip, destination_ip):
        """
        Finds the network path from a source IP to a destination IP.
        Returns a list of tuples representing the path:
        [(device_hostname, interface_name, next_hop_ip, route_type), ...]
        """
        path = []
        visited_devices = set() # To detect routing loops

        current_device_id, current_hostname = self._get_device_by_ip(source_ip)

        if not current_device_id:
            return f"Error: Source IP {source_ip} not found on any device."

        path.append((current_hostname, "Initial Source", source_ip, "Source"))

        while True:
            if current_device_id in visited_devices:
                path.append((current_hostname, "Loop Detected", "N/A", "Loop"))
                return f"Error: Routing loop detected involving device {current_hostname}. Path: {path}"

            visited_devices.add(current_device_id)

            # Check if destination is directly connected to the current device
            self.cursor.execute("""
                SELECT i.name, i.ipv4_address, i.ipv4_subnet
                FROM interfaces i
                WHERE i.device_id = ? AND i.ipv4_address IS NOT NULL AND i.ipv4_subnet IS NOT NULL
            """, (current_device_id,))
            connected_interfaces = self.cursor.fetchall()

            destination_reached = False
            for iface_name, iface_ip, iface_subnet in connected_interfaces:
                try:
                    network_str = f"{iface_ip}/{iface_subnet}"
                    network_obj = ipaddress.ip_network(network_str, strict=False)
                    if ipaddress.ip_address(destination_ip) in network_obj:
                        path.append((current_hostname, iface_name, destination_ip, "Directly Connected"))
                        destination_reached = True
                        break
                except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
                    continue
            if destination_reached:
                return path

            # If not directly connected, find the best route
            next_hop_ip, out_interface_name, route_type = self._get_best_route(current_device_id, destination_ip)

            if not next_hop_ip:
                return f"Error: No route found from {current_hostname} to {destination_ip}. Current path: {path}"

            # If route type is 'connected', the next hop is the destination itself via the interface
            if route_type == 'connected':
                path.append((current_hostname, out_interface_name, destination_ip, route_type))
                destination_reached = True
                return path

            # Find the next device based on the next_hop_ip
            next_device_id, next_device_hostname = self._get_device_by_ip(next_hop_ip)

            if not next_device_id:
                return f"Error: Next hop IP {next_hop_ip} from {current_hostname} does not identify a known device interface. Current path: {path}"

            path.append((current_hostname, out_interface_name, next_hop_ip, route_type))

            current_device_id = next_device_id
            current_hostname = next_device_hostname

def get_firewalls_from_path(path_result, pathfinder_instance):
    """
    Takes a path result (list of hops) and a NetworkPathfinder instance,
    and returns a list of hostnames that are identified as 'Firewall' devices.
    """
    firewalls_in_path = []
    if isinstance(path_result, list):
        for hop in path_result:
            device_hostname = hop[0]
            device_type = pathfinder_instance.get_device_type(device_hostname)
            if device_type and device_type.lower() == 'firewall' and device_hostname not in firewalls_in_path:
                firewalls_in_path.append(device_hostname)
    return firewalls_in_path


if __name__ == "__main__":
    # Check for --json-output argument
    json_output_requested = "--json-output" in sys.argv

    # Remove --json-output from arguments if present, so ipaddress doesn't complain
    if json_output_requested:
        sys.argv.remove("--json-output")

    # Check if correct number of arguments are provided (after removing --json-output)
    if len(sys.argv) != 3:
        if not json_output_requested: # Only print usage if not in JSON output mode
            print("Usage: python pathfinder.py <source_ip> <destination_ip> [--json-output]")
        sys.exit(1)

    source_ip = sys.argv[1]
    destination_ip = sys.argv[2]

    try:
        # Validate IP addresses
        ipaddress.ip_address(source_ip)
        ipaddress.ip_address(destination_ip)
    except ipaddress.AddressValueError:
        if not json_output_requested: # Only print error if not in JSON output mode
            print("Error: Invalid IP address format. Please enter valid IPv4 addresses.")
        sys.exit(1)

    pathfinder = NetworkPathfinder()

    path = pathfinder.find_network_path(source_ip, destination_ip)
    firewalls = [] # Initialize firewalls list

    if isinstance(path, str): # Error message
        if not json_output_requested:
            print(f"\n--- Path Result ---")
            print(path)
    else:
        if not json_output_requested:
            print(f"\n--- Finding path from {source_ip} to {destination_ip} ---")
            print("\n--- Path Result ---")
            print("Path found:")
            for i, hop in enumerate(path):
                device, interface, ip, route_type = hop
                print(f"{i+1}. Device: {device}, Outgoing Interface: {interface}, Next Hop/Destination IP: {ip}, Route Type: {route_type}")

        # Identify firewalls in the path
        firewalls = get_firewalls_from_path(path, pathfinder)

    # Output firewalls based on --json-output flag
    if json_output_requested:
        print(json.dumps(firewalls))
    else:
        print(f"\n--- Firewalls in Path ---")
        if firewalls:
            print(f"The following firewalls are in the path: {', '.join(firewalls)}")
        else:
            print("No firewalls found in this network path.")

    pathfinder._close_db()
    if not json_output_requested:
        print("Pathfinding complete.")
