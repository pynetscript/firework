from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash
from app.models import FirewallRule, BlacklistRule, db
import ipaddress
import json
import logging # Import logging
# Import the new NetworkAutomationService
from app.services.network_automation import NetworkAutomationService
from datetime import datetime # Import datetime for timestamps


routes = Blueprint('routes', __name__)

# Initialize the NetworkAutomationService
network_automation_service = NetworkAutomationService()

# Get the Flask app logger
app_logger = logging.getLogger(__name__)

@routes.route('/')
def home():
    return render_template('index.html')

@routes.route('/request-form')
def request_form():
    return render_template('request_form.html')

@routes.route('/task-results')
def task_results():
    rules = FirewallRule.query.all()
    # firewalls_involved is a JSONEncodedList, so it should already be a Python list when accessed.
    # No explicit json.loads needed here unless JSONEncodedList is not working as expected.
    for rule in rules:
        if rule.firewalls_involved is None:
            rule.firewalls_involved = [] # Ensure it's an empty list if None
    return render_template('task_results.html', rules=rules)

# --- Helper Validation Functions ---
def validate_ip_address(ip_str, field_name):
    """Validates if a string is a valid IPv4 address or network."""
    if not ip_str:
        return False, f"{field_name} cannot be empty."
    try:
        ipaddress.IPv4Address(ip_str)
        return True, None
    except ipaddress.AddressValueError:
        try:
            ipaddress.IPv4Network(ip_str, strict=False)
            return True, None
        except ipaddress.AddressValueError:
            return False, f"Invalid {field_name}: '{ip_str}'. Must be a valid IPv4 address or network (e.g., 10.0.0.0/24)."

def validate_protocol(protocol_str):
    """
    Validates if a string is a common protocol (tcp, udp, icmp) or a valid protocol number.
    """
    common_protocols = ['tcp', 'udp', 'icmp', 'any']
    if protocol_str.lower() in common_protocols:
        return True, None
    
    try:
        proto_num = int(protocol_str)
        if 0 < proto_num <= 255:
            return True, None
        else:
            return False, f"Invalid protocol number: '{protocol_str}'. Must be between 1 and 255."
    except ValueError:
        return False, f"Invalid protocol: '{protocol_str}'. Must be 'tcp', 'udp', 'icmp', 'any' or a valid protocol number (1-255)."

def validate_port(port_value):
    """Validates if a value is a valid port number (1-65535) or a port range (e.g., 8000-8999) or 'any'."""
    if isinstance(port_value, int):
        if 0 < port_value <= 65535:
            return True, None
        else:
            return False, f"Invalid port: {port_value}. Must be an integer between 1 and 65535."
    
    port_str = str(port_value).strip().lower()
    if port_str == 'any':
        return True, None

    if '-' in port_str:
        try:
            rule_start, rule_end = map(int, port_str.split('-'))
            if 0 < rule_start <= rule_end <= 65535:
                return True, None
            else:
                return False, f"Invalid port range: '{port_value}'. Start and end ports must be between 1 and 65535, and start must be less than or equal to end."
        except ValueError:
            return False, f"Invalid port range format: '{port_value}'. Use 'start-end' (e.g., '8000-8999')."
    else:
        try:
            port_num = int(port_value)
            if 0 < port_num <= 65535:
                return True, None
            else:
                return False, f"Invalid port: {port_num}. Must be an integer between 1 and 65535."
        except ValueError:
            return False, f"Invalid port format: '{port_value}'. Must be an integer, 'start-end', or 'any'."


# --- Blacklist Logic ---
def check_blacklist(source_ip, destination_ip, protocol, destination_port):
    """
    Checks if a given request matches any active blacklist rules.
    Rules are processed from top to bottom, sorted by sequence.
    Returns (True, rule_name) if blacklisted, (False, None) otherwise.
    """
    blacklist_rules = BlacklistRule.query.filter_by(enabled=True).order_by(BlacklistRule.sequence).all()

    for rule in blacklist_rules:
        # Source IP check
        src_match = False
        if rule.source_ip is None or rule.source_ip.lower() == 'any':
            src_match = True
        else:
            try:
                rule_src_net = ipaddress.ip_network(rule.source_ip, strict=False)
                if ipaddress.ip_address(source_ip) in rule_src_net:
                    src_match = True
            except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
                pass

        if not src_match:
            continue

        # Destination IP check
        dst_match = False
        if rule.destination_ip is None or rule.destination_ip.lower() == 'any':
            dst_match = True
        else:
            try:
                rule_dst_net = ipaddress.ip_network(rule.destination_ip, strict=False)
                if ipaddress.ip_address(destination_ip) in rule_dst_net:
                    dst_match = True
            except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
                pass

        if not dst_match:
            continue

        # Protocol check
        proto_match = False
        if rule.protocol is None or rule.protocol.lower() == 'any':
            proto_match = True
        elif rule.protocol.lower() == protocol.lower():
            proto_match = True
        else:
            try:
                if int(rule.protocol) == int(protocol):
                    proto_match = True
            except ValueError:
                pass

        if not proto_match:
            continue

        # Destination Port check
        port_match = False
        if rule.destination_port is None or rule.destination_port.lower() == 'any':
            port_match = True
        elif '-' in str(rule.destination_port):
            try:
                rule_start, rule_end = map(int, rule.destination_port.split('-'))
                req_port = int(destination_port)
                if rule_start <= req_port <= rule_end:
                    port_match = True
            except ValueError:
                pass
        elif str(rule.destination_port) == str(destination_port):
            port_match = True

        if port_match:
            return True, rule.rule_name
    return False, None

@routes.route('/api/request', methods=['POST'])
def create_request():
    data = request.form

    source_ip = data.get('source_ip')
    destination_ip = data.get('destination_ip')
    protocol = data.get('protocol')
    dest_port = data.get('port') # Renamed 'port' to 'dest_port' from form data

    errors = []

    # 1.1 Pre-check: Input field validation
    is_valid, error_msg = validate_ip_address(source_ip, "Source IP")
    if not is_valid: errors.append(error_msg)
    is_valid, error_msg = validate_ip_address(destination_ip, "Destination IP")
    if not is_valid: errors.append(error_msg)
    is_valid, error_msg = validate_protocol(protocol)
    if not is_valid: errors.append(error_msg)
    is_valid, error_msg = validate_port(dest_port) # Use dest_port for validation
    if not is_valid: errors.append(error_msg)

    if errors:
        app_logger.warning(f"Request validation failed: {errors}")
        return jsonify({"status": "error", "message": "Validation failed", "errors": errors}), 400

    # 2.2 Pre-check: Run requested rule against blacklist db
    is_blacklisted, rule_name = check_blacklist(source_ip, destination_ip, protocol, dest_port) # Use dest_port for blacklist check
    if is_blacklisted:
        app_logger.warning(f"Request from {source_ip} to {destination_ip}:{dest_port}/{protocol} denied by blacklist rule: '{rule_name}'")
        return jsonify({"status": "denied", "message": f"Request denied: Matches blacklist rule '{rule_name}'"}), 403
    else:
        app_logger.info(f"Request from {source_ip} to {destination_ip}:{dest_port}/{protocol} passed blacklist check.")


    # --- Pre-check 2.3 & 2.4: Network Path & Firewall Identification using service ---
    firewalls_in_path = []
    initial_rule_status = "Pending" # Default status before pathfinding
    initial_approval_status = "Pending" # Default approval status

    try:
        # 1. Call Ansible collector playbook and DB builder via service
        collection_result = network_automation_service.run_collector()
        if collection_result["status"] == "error":
            raise RuntimeError(collection_result["message"])
        
        db_build_result = network_automation_service.build_database()
        if db_build_result["status"] == "error":
            raise RuntimeError(db_build_result["message"])


        # 2. Run Pathfinder script and capture JSON output via service
        firewalls_in_path = network_automation_service.find_path_and_firewalls(source_ip, destination_ip)
        
        if firewalls_in_path:
            # --- NEW: Check if policy already exists on identified firewalls ---
            policy_already_exists = network_automation_service.check_policy_existence(
                source_ip, destination_ip, protocol, dest_port, firewalls_in_path # Use dest_port
            )
            if policy_already_exists:
                app_logger.info(f"Existing policy found for {source_ip} to {destination_ip}:{dest_port}/{protocol}. Request marked as already implemented.")
                return jsonify({"status": "info", "message": "Requested access is already implemented on one or more firewalls in the path."}), 200
            # --- END NEW CHECK ---

            initial_rule_status = "Pending Approval" # Firewalls found, needs human approval
            initial_approval_status = "Pending"
            app_logger.info(f"Path found for {source_ip} to {destination_ip}. Firewalls involved: {firewalls_in_path}. Request set to 'Pending Approval'.")
        else:
            initial_rule_status = "No Firewall Involved" # No firewalls, might not need approval or different workflow
            initial_approval_status = "N/A" # Not applicable for approval
            app_logger.info(f"No firewalls found in path for {source_ip} to {destination_ip}. Request set to 'No Firewall Involved'.")

    except RuntimeError as e: # Catch RuntimeError raised by the service
        app_logger.error(f"Network automation service failed during pre-check for {source_ip} to {destination_ip}: {e}")
        initial_rule_status = "Pathfinding Failed"
        initial_approval_status = "Failed"
        errors.append(f"Network automation pre-check failed: {e}")
    except Exception as e:
        app_logger.error(f"An unexpected error occurred during network automation pre-check for {source_ip} to {destination_ip}: {e}")
        initial_rule_status = "Pathfinding Failed"
        initial_approval_status = "Failed"
        errors.append(f"An internal error occurred during network automation pre-check: {e}")
    
    if errors:
        return jsonify({"status": "error", "message": "Pre-check failed", "errors": errors, "path_status": initial_rule_status}), 500


    # If validation and blacklist checks pass, proceed to create the rule
    try:
        rule = FirewallRule(
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            port=int(dest_port), # Store as 'port' in DB model (column name remains 'port')
            status=initial_rule_status, # Set initial status based on pathfinding result
            approval_status=initial_approval_status, # Set initial approval status
            firewalls_involved=firewalls_in_path, # Store the list of firewalls
            created_at=datetime.now() # Set created_at timestamp
        )
        db.session.add(rule)
        db.session.commit()
        app_logger.info(f"Network request ID {rule.id} created successfully with status '{rule.status}'.")
        return jsonify({"status": "success", "message": "Request created successfully", "rule_id": rule.id, "status_detail": rule.status, "firewalls_involved": firewalls_in_path}), 201
    except Exception as e:
        db.session.rollback()
        app_logger.error(f"Failed to create request for {source_ip} to {destination_ip}: {str(e)}")
        return jsonify({"status": "error", "message": f"Failed to create request: {str(e)}"}), 500


# --- Blacklist Management Routes ---

@routes.route('/admin/blacklist', methods=['GET'])
def blacklist_rules_list():
    """Displays a list of all blacklist rules."""
    return render_template('blacklist_rules_list.html')

@routes.route('/admin/blacklist/add', methods=['GET', 'POST'])
def add_blacklist_rule():
    """Displays the form to add a new blacklist rule and handles its submission."""
    if request.method == 'POST':
        data = request.form
        try:
            sequence = int(data['sequence'])
            # Check for existing sequence
            if BlacklistRule.query.filter_by(sequence=sequence).first():
                flash(f"Rule with sequence {sequence} already exists. Please choose a different sequence.", 'error')
                app_logger.warning(f"Attempted to add blacklist rule with duplicate sequence: {sequence}")
                return redirect(url_for('routes.add_blacklist_rule')) # Redirect back to the form
            
            new_rule = BlacklistRule(
                sequence=sequence,
                rule_name=data['rule_name'],
                enabled=bool(data.get('enabled', False)),
                source_ip=data.get('source_ip') or None,
                destination_ip=data.get('destination_ip') or None,
                protocol=data.get('protocol') or None,
                destination_port=data.get('destination_port') or None,
                description=data.get('description') or None
            )
            db.session.add(new_rule)
            db.session.commit()
            flash("Blacklist rule added successfully!", 'success')
            app_logger.info(f"Blacklist rule '{new_rule.rule_name}' (ID: {new_rule.id}, Sequence: {new_rule.sequence}) added successfully.")
            return redirect(url_for('routes.blacklist_rules_list')) # Redirect to the list page
        except ValueError:
            db.session.rollback()
            flash("Invalid sequence number. Must be an integer.", 'error')
            app_logger.error(f"Failed to add blacklist rule: Invalid sequence number provided.")
            return redirect(url_for('routes.add_blacklist_rule')) # Redirect back to the form
        except Exception as e:
            db.session.rollback()
            flash(f"Failed to add blacklist rule: {str(e)}", 'error')
            app_logger.error(f"Failed to add blacklist rule: {str(e)}")
            return redirect(url_for('routes.add_blacklist_rule')) # Redirect back to the form
    
    # For GET request, render the dedicated form
    return render_template('add_blacklist_form.html')

@routes.route('/admin/blacklist/<int:rule_id>', methods=['GET'])
def blacklist_rule_detail(rule_id):
    """Displays the details of a specific blacklist rule."""
    rule = BlacklistRule.query.get_or_404(rule_id)
    app_logger.info(f"Viewing details for blacklist rule ID: {rule_id}")
    return render_template('blacklist_rule_detail.html', rule=rule)

# --- API Endpoints for Blacklist Rules (for AJAX calls) ---
@routes.route('/api/blacklist_rules', methods=['GET'])
def get_blacklist_rules_api():
    """API endpoint to get all blacklist rules."""
    rules = BlacklistRule.query.order_by(BlacklistRule.sequence).all()
    rules_data = []
    for rule in rules:
        rules_data.append({
            'id': rule.id,
            'sequence': rule.sequence,
            'rule_name': rule.rule_name,
            'enabled': rule.enabled,
            'source_ip': rule.source_ip,
            'destination_ip': rule.destination_ip,
            'protocol': rule.protocol,
            'destination_port': rule.destination_port,
            'description': rule.description,
            'created_at': rule.created_at.isoformat() if rule.created_at else None, # Include timestamps
            'updated_at': rule.updated_at.isoformat() if rule.updated_at else None  # Include timestamps
        })
    app_logger.info("Fetched all blacklist rules via API.")
    return jsonify(rules_data), 200

@routes.route('/api/blacklist_rules/<int:rule_id>', methods=['DELETE'])
def delete_blacklist_rule_api(rule_id):
    """API endpoint to delete a single blacklist rule."""
    rule = BlacklistRule.query.get(rule_id)
    if rule:
        try:
            db.session.delete(rule)
            db.session.commit()
            app_logger.info(f"Blacklist rule ID {rule_id} deleted successfully via API.")
            return jsonify({"status": "success", "message": f"Rule ID {rule_id} deleted successfully."}), 200
        except Exception as e:
            db.session.rollback()
            app_logger.error(f"Failed to delete blacklist rule ID {rule_id} via API: {str(e)}")
            return jsonify({"status": "error", "message": f"Failed to delete rule ID {rule_id}: {str(e)}"}), 500
    app_logger.warning(f"Attempted to delete non-existent blacklist rule ID {rule_id} via API.")
    return jsonify({"status": "error", "message": f"Rule ID {rule_id} not found."}), 404

@routes.route('/api/blacklist_rules', methods=['DELETE'])
def delete_multiple_blacklist_rules_api():
    """API endpoint to delete multiple blacklist rules."""
    data = request.get_json()
    rule_ids = data.get('ids', [])
    if not rule_ids:
        app_logger.warning("Attempted to delete multiple blacklist rules, but no IDs were provided.")
        return jsonify({"status": "error", "message": "No rule IDs provided for deletion."}), 400

    try:
        deleted_count = 0
        for rule_id in rule_ids:
            rule = BlacklistRule.query.get(rule_id)
            if rule:
                db.session.delete(rule)
                deleted_count += 1
        db.session.commit()
        app_logger.info(f"Successfully deleted {deleted_count} blacklist rule(s) via API. IDs: {rule_ids}")
        return jsonify({"status": "success", "message": f"Successfully deleted {deleted_count} rule(s)."}), 200
    except Exception as e:
        db.session.rollback()
        app_logger.error(f"Failed to delete multiple blacklist rules via API (IDs: {rule_ids}): {str(e)}")
        return jsonify({"status": "error", "message": f"Failed to delete rules: {str(e)}"}), 500


# --- Routes for Approval Workflow ---

@routes.route('/approvals')
def approvals_list():
    """Displays a list of requests pending approval."""
    # Only show rules that are 'Pending Approval' and 'Pending' in approval_status
    pending_rules = FirewallRule.query.filter_by(status='Pending Approval', approval_status='Pending').all()
    # When displaying, ensure firewalls_involved is deserialized if it exists and is a string
    for rule in pending_rules:
        if rule.firewalls_involved is None:
            rule.firewalls_involved = [] # Ensure it's an empty list if None

    app_logger.info("Viewing list of pending approvals.")
    return render_template('approvals_list.html', rules=pending_rules)

@routes.route('/approvals/<int:rule_id>', methods=['GET', 'POST'])
def approve_deny_request(rule_id):
    """Allows an approver to view details and approve/deny a specific request."""
    rule = FirewallRule.query.get_or_404(rule_id)

    if request.method == 'POST':
        action = request.form.get('action') # 'approve' or 'deny'
        approver_comment = request.form.get('approver_comment')
        current_approver_id = "approver_user_123" # Placeholder for actual approver ID

        if action == 'approve':
            rule.approval_status = "Approved"
            rule.status = "Approved - Pending Implementation" # Update overall status
            rule.approver_id = current_approver_id
            rule.approver_comment = approver_comment
            rule.approved_at = datetime.now() # Set approved_at timestamp
            db.session.commit()
            app_logger.info(f"Network request ID {rule_id} approved by {current_approver_id}.")
            # Redirect to approvals list after action
            return redirect(url_for('routes.approvals_list'))
        elif action == 'deny':
            rule.approval_status = "Denied"
            rule.status = "Denied by Approver" # Update overall status
            rule.approver_id = current_approver_id
            rule.approver_comment = approver_comment
            db.session.commit()
            app_logger.info(f"Network request ID {rule_id} denied by {current_approver_id}.")
            # Redirect to approvals list after action
            return redirect(url_for('routes.approvals_list'))
        else:
            app_logger.warning(f"Invalid action '{action}' for network request ID {rule.id}.")
            return jsonify({"status": "error", "message": "Invalid action specified."}), 400
    
    # When displaying, ensure firewalls_involved is deserialized if it exists and is a string
    if rule.firewalls_involved is None:
        rule.firewalls_involved = [] # Ensure it's an empty list if None

    app_logger.info(f"Viewing approval details for network request ID {rule.id}.")
    return render_template('approval_detail.html', rule=rule)

# --- New Routes for Implementer Workflow ---

@routes.route('/implementation')
def implementation_list():
    """Displays a list of rules ready for implementation (approved and pending implementation)."""
    # Show rules that are 'Approved - Pending Implementation'
    ready_for_implementation_rules = FirewallRule.query.filter_by(status='Approved - Pending Implementation', approval_status='Approved').all()
    # When displaying, ensure firewalls_involved is deserialized if it exists and is a string
    for rule in ready_for_implementation_rules:
        if rule.firewalls_involved is None:
            rule.firewalls_involved = [] # Ensure it's an empty list if None

    app_logger.info("Viewing list of rules ready for implementation.")
    return render_template('implementation_list.html', rules=ready_for_implementation_rules)

@routes.route('/implementation/<int:rule_id>', methods=['GET', 'POST'])
def implement_rule(rule_id):
    """Allows an implementer to view details and provision/decline a specific rule."""
    rule = FirewallRule.query.get_or_404(rule_id)

    if request.method == 'POST':
        action = request.form.get('action') # 'provision' or 'decline_implementation'
        implementer_comment = request.form.get('implementer_comment') # New comment field for implementer
        current_implementer_id = "implementer_user_456" # Placeholder for actual implementer ID

        if action == 'provision':
            app_logger.info(f"Implementer triggered provisioning for rule ID {rule_id}.")
            # Logic for provisioning (already in provision_request, we'll call it)
            # This route will handle the provisioning logic
            return provision_request(rule_id) # Call the existing provisioning function
        elif action == 'decline_implementation':
            rule.status = "Declined by Implementer"
            rule.approver_comment = (rule.approver_comment or "") + f"\nImplementer Comment: {implementer_comment}"
            rule.approver_id = current_implementer_id # Re-using approver_id for simplicity, ideally separate implementer_id
            db.session.commit()
            app_logger.info(f"Implementer declined implementation for rule ID {rule_id}.")
            return redirect(url_for('routes.implementation_list'))
        else:
            app_logger.warning(f"Invalid action '{action}' for rule implementation ID {rule_id}.")
            return jsonify({"status": "error", "message": "Invalid action specified."}), 400
    
    # When displaying, ensure firewalls_involved is deserialized if it exists and is a string
    if rule.firewalls_involved is None:
        rule.firewalls_involved = [] # Ensure it's an empty list if None

    app_logger.info(f"Viewing implementation details for rule ID {rule.id}.")
    return render_template('implementation_detail.html', rule=rule)


@routes.route('/provision/<int:rule_id>', methods=['POST'])
def provision_request(rule_id):
    """
    Triggers the Ansible provisioning playbook for an approved firewall rule.
    Automatically triggers post-check after successful provisioning.
    This function is now called from the implement_rule route.
    """
    rule = FirewallRule.query.get_or_404(rule_id)

    # Check if the rule is in the correct state for provisioning
    if rule.status != "Approved - Pending Implementation" or rule.approval_status != "Approved":
        app_logger.warning(f"Attempted to provision rule ID {rule.id} which is not in 'Approved - Pending Implementation' state. Current status: {rule.status}, Approval: {rule.approval_status}")
        return jsonify({"status": "error", "message": "Rule is not in 'Approved - Pending Implementation' state for provisioning."}), 400

    # Update status to indicate provisioning is in progress
    rule.status = "Provisioning In Progress"
    db.session.commit()
    app_logger.info(f"Provisioning initiated for rule ID {rule.id}.")
    
    firewalls_to_provision = []
    provisioning_success = False
    provisioning_message = "Provisioning started."
    post_check_success = False

    try:
        # Use the firewalls_involved stored in the rule, if available
        # If not available (e.g., old rule, or error during initial pathfinding),
        # re-run pathfinder as a fallback.
        if rule.firewalls_involved:
            firewalls_to_provision = rule.firewalls_involved
            app_logger.info(f"Using stored firewalls for provisioning rule {rule.id}: {firewalls_to_provision}")
        else:
            app_logger.info(f"Stored firewalls_involved not found for rule {rule.id}. Re-running pathfinder...")
            firewalls_to_provision = network_automation_service.find_path_and_firewalls(rule.source_ip, rule.destination_ip)
            # The find_path_and_firewalls method already raises RuntimeError on error, so no need for if path_result["status"] == "error"
            app_logger.info(f"Firewalls identified for provisioning rule {rule.id} via pathfinder: {firewalls_to_provision}")


        if not firewalls_to_provision:
            rule.status = "Provisioning Failed - No Firewalls in Path"
            provisioning_message = "No firewalls found in the path for this rule. Cannot provision."
            db.session.commit()
            app_logger.error(f"Provisioning failed for rule {rule.id}: No firewalls found in path.")
            return jsonify({"status": "error", "message": provisioning_message}), 400

        # Call Ansible provisioning playbook via service
        provision_result_stdout = network_automation_service.provision_rule(
            rule_data={
                'rule_id': rule.id,
                'source_ip': rule.source_ip,
                'destination_ip': rule.destination_ip,
                'protocol': rule.protocol,
                'dest_port': rule.port # Use 'port' from FirewallRule, it's passed as dest_port to playbook
            },
            firewalls=firewalls_to_provision
        )
        
        provisioning_success = True
        provisioning_message = f"Rule {rule.id} provisioned successfully."
        app_logger.info(f"Rule {rule.id} provisioned successfully. Ansible output: {provision_result_stdout}")

        # --- Post-check (5.0) - Only run if provisioning was successful ---
        if provisioning_success:
            post_check_result_stdout = network_automation_service.post_check_rule(
                rule_data={
                    'rule_id': rule.id,
                    'source_ip': rule.source_ip,
                    'destination_ip': rule.destination_ip,
                    'protocol': rule.protocol,
                    'dest_port': rule.port # Use 'port' from FirewallRule, it's passed as dest_port to playbook
                },
                firewalls=firewalls_to_provision
            )

            post_check_success = True
            rule.status = "Completed" # Final status if provisioning and post-check pass
            rule.implemented_at = datetime.now() # Set implemented_at timestamp
            provisioning_message += " Configuration verified successfully."
            app_logger.info(f"Rule {rule.id} post-check successful. Ansible output: {post_check_result_stdout}")
        else:
            # This else block should theoretically not be hit if RuntimeError is raised for provisioning failure
            # but is here for logical completeness.
            rule.status = "Provisioning Failed"
            provisioning_message = f"Provisioning failed for rule {rule.id}. Post-check skipped. Check logs for ID {rule.id}."
            app_logger.error(f"Provisioning failed for rule {rule.id}. Post-check skipped.")


    except RuntimeError as e:
        rule.status = "Provisioning Failed"
        provisioning_message = f"Provisioning failed for rule {rule.id}: {e}. Check logs for ID {rule.id}."
        app_logger.error(f"Provisioning RuntimeError for rule {rule.id}: {e}")
    except Exception as e:
        rule.status = "Provisioning Failed"
        provisioning_message = f"An unexpected error occurred during provisioning/post-check for rule {rule.id}: {e}. Check logs for ID {rule.id}."
        app_logger.critical(f"An unexpected error occurred during provisioning for rule {rule.id}: {e}", exc_info=True)
    finally:
        db.session.commit() # Ensure status update is saved

    if rule.status == "Completed": # Check final status, not just provisioning_success flag
        return jsonify({"status": "success", "message": provisioning_message, "rule_id": rule.id, "new_status": rule.status}), 200
    else:
        return jsonify({"status": "error", "message": provisioning_message, "rule_id": rule.id, "new_status": rule.status}), 500

