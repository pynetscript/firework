from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash, abort
from app.models import FirewallRule, BlacklistRule, db, User
import ipaddress
import json
import logging
from datetime import datetime
from flask_login import login_required, current_user
from app.services.network_automation import NetworkAutomationService
from app.decorators import roles_required, no_self_approval


routes = Blueprint('routes', __name__)

network_automation_service = NetworkAutomationService()

app_logger = logging.getLogger(__name__)

@routes.route('/')
def home():
    # If not authenticated, Flask-Login will redirect to auth.login due to login_manager.login_view setting.
    # We explicitly redirect here to ensure a clean redirect from the root URL.
    if not current_user.is_authenticated:
        return redirect(url_for('auth.login'))
    # Redirect authenticated users to a default dashboard page
    return redirect(url_for('routes.task_results'))


@routes.route('/request-form')
@login_required # Ensures user is logged in
@roles_required('superadmin', 'admin', 'requester') # Only these roles can create requests
def request_form():
    return render_template('request_form.html')


@routes.route('/task-results')
@login_required # Ensures user is logged in
@roles_required('superadmin', 'admin', 'implementer', 'approver', 'requester') # All roles can see task results, but content varies
def task_results():
    if current_user.role == 'requester':
        # Requesters only see their own requests
        rules = FirewallRule.query.filter_by(requester_id=current_user.id).all()
        app_logger.info(f"Requester {current_user.username} viewing their own task results.")
    else:
        # Other roles see all requests
        rules = FirewallRule.query.all()
        app_logger.info(f"User {current_user.username} (Role: {current_user.role}) viewing all task results.")

    for rule in rules:
        if rule.firewalls_involved is None:
            rule.firewalls_involved = []
        if rule.firewalls_to_provision is None: # Ensure these are lists for rendering
            rule.firewalls_to_provision = []
        if rule.firewalls_already_configured is None: # Ensure these are lists for rendering
            rule.firewalls_already_configured = []
    return render_template('task_results.html', rules=rules)


# --- User Profile Page ---
@routes.route('/profile', methods=['GET', 'POST'])
@login_required # Ensures user is logged in
def profile():
    user = current_user # The current_user object is already loaded by Flask-Login

    if request.method == 'POST':
        # Update user details
        user.username = request.form.get('username', user.username) # Username from form, fallback to current
        user.email = request.form.get('email', user.email) # Email from form, fallback to current
        user.first_name = request.form.get('first_name')
        user.last_name = request.form.get('last_name')
        
        new_password = request.form.get('password')
        if new_password:
            user.set_password(new_password)
            flash('Password updated successfully!', 'success')
            app_logger.info(f"User {user.username} (ID: {user.id}) updated their password.")

        try:
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            app_logger.info(f"User {user.username} (ID: {user.id}) updated their profile details.")
            return redirect(url_for('routes.profile'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating profile: {e}', 'error')
            app_logger.error(f"Error updating profile for user {user.username} (ID: {user.id}): {e}", exc_info=True)

    return render_template('profile.html', user=user)

# --- Helper Validation Functions (unchanged, not directly exposed as routes) ---
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
    # Handle None or empty string input upfront
    if port_value is None or port_value == '':
        return False, "Port cannot be empty."

    # Now port_value is guaranteed not to be None or empty string
    # Convert to string and normalize for comparison/parsing
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
            port_num = int(port_str) # Corrected to use port_str here
            if 0 < port_num <= 65535:
                return True, None
            else:
                return False, f"Invalid port: {port_num}. Must be an integer between 1 and 65535."
        except ValueError:
            return False, f"Invalid port format: '{port_value}'. Must be an integer, 'start-end', or 'any'."


# --- Blacklist Logic (unchanged) ---
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
@login_required
@roles_required('superadmin', 'admin', 'requester')
def create_request():
    data = request.form

    source_ip = data.get('source_ip')
    destination_ip = data.get('destination_ip')
    protocol = data.get('protocol')
    dest_port = data.get('port')

    errors = []

    is_valid, error_msg = validate_ip_address(source_ip, "Source IP")
    if not is_valid: errors.append(error_msg)
    is_valid, error_msg = validate_ip_address(destination_ip, "Destination IP")
    if not is_valid: errors.append(error_msg)
    is_valid, error_msg = validate_protocol(protocol)
    if not is_valid: errors.append(error_msg)
    is_valid, error_msg = validate_port(dest_port)
    if not is_valid: errors.append(error_msg)

    if errors:
        app_logger.warning(f"Request validation failed: {errors}")
        return jsonify({"status": "error", "message": "Validation failed", "errors": errors}), 400

    is_blacklisted, rule_name = check_blacklist(source_ip, destination_ip, protocol, dest_port)
    if is_blacklisted:
        app_logger.warning(f"Request from {source_ip} to {destination_ip}:{dest_port}/{protocol} denied by blacklist rule: '{rule_name}' for user {current_user.username}.")
        return jsonify({"status": "denied", "message": f"Request denied: Matches blacklist rule '{rule_name}'"}), 403
    else:
        app_logger.info(f"Request from {source_ip} to {destination_ip}:{dest_port}/{protocol} passed blacklist check for user {current_user.username}.")


    firewalls_in_path = []
    firewalls_to_provision = []
    firewalls_already_configured = []
    initial_rule_status = "Pending"
    initial_approval_status = "Pending"

    try:
        collection_result = network_automation_service.run_collector()
        if collection_result["status"] == "error":
            raise RuntimeError(collection_result["message"])
        
        db_build_result = network_automation_service.build_database()
        if db_build_result["status"] == "error":
            raise RuntimeError(db_build_result["message"])


        firewalls_in_path = network_automation_service.find_path_and_firewalls(source_ip, destination_ip)
        
        if firewalls_in_path:
            precheck_result = network_automation_service.check_policy_existence(
                source_ip, destination_ip, protocol, dest_port, firewalls_in_path
            )
            firewalls_to_provision = precheck_result["firewalls_to_provision"]
            firewalls_already_configured = precheck_result["firewalls_already_configured"]
            all_policies_exist = precheck_result["all_policies_exist"]

            if all_policies_exist:
                app_logger.info(f"Existing policy found for {source_ip} to {destination_ip}:{dest_port}/{protocol} on ALL firewalls. Request marked as already implemented.")
                return jsonify({"status": "info", "message": "Requested access is already implemented on all firewalls in the path."}), 200
            elif firewalls_already_configured:
                # If some are configured, but not all, still proceed to approval
                app_logger.info(f"Policy partially configured. Firewalls already configured: {firewalls_already_configured}. Firewalls to provision: {firewalls_to_provision}. Proceeding to approval.")
                initial_rule_status = "Pending Approval"
                initial_approval_status = "Pending"
            else:
                # No firewalls configured, all need provisioning
                app_logger.info(f"No existing policy found on any firewall. Firewalls to provision: {firewalls_to_provision}. Proceeding to approval.")
                initial_rule_status = "Pending Approval"
                initial_approval_status = "Pending"
        else:
            initial_rule_status = "No Firewall Involved"
            initial_approval_status = "N/A"
            app_logger.info(f"No firewalls found in path for {source_ip} to {destination_ip}. Request set to 'No Firewall Involved'.")

    except RuntimeError as e:
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


    try:
        # Convert dest_port to int only after successful validation if it's not 'any' or a range
        final_port_value = int(dest_port) if str(dest_port).isdigit() else dest_port

        rule = FirewallRule(
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            port=final_port_value, # Use the potentially converted integer or string
            status=initial_rule_status,
            approval_status=initial_approval_status,
            firewalls_involved=firewalls_in_path,
            firewalls_to_provision=firewalls_to_provision, # Store the new lists
            firewalls_already_configured=firewalls_already_configured, # Store the new lists
            requester_id=current_user.id
        )
        db.session.add(rule)
        db.session.commit()
        app_logger.info(f"Network request ID {rule.id} created successfully by user {current_user.username} with status '{rule.status}'.")
        return jsonify({"status": "success", "message": "Request created successfully", "rule_id": rule.id, "status_detail": rule.status, "firewalls_involved": firewalls_in_path}), 201
    except Exception as e:
        db.session.rollback()
        app_logger.error(f"Failed to create request for {source_ip} to {destination_ip} by user {current_user.username}: {str(e)}")
        return jsonify({"status": "error", "message": f"Failed to create request: {str(e)}"}), 500


# --- Blacklist Management Routes ---

@routes.route('/admin/blacklist', methods=['GET'])
@login_required # Ensures user is logged in
@roles_required('superadmin', 'admin', 'implementer')
def blacklist_rules_list():
    """Displays a list of all blacklist rules."""
    return render_template('blacklist_rules_list.html')

@routes.route('/admin/blacklist/add', methods=['GET', 'POST'])
@login_required # Ensures user is logged in
@roles_required('superadmin', 'admin')
def add_blacklist_rule():
    """Displays the form to add a new blacklist rule and handles its submission."""
    if request.method == 'POST':
        data = request.form
        try:
            sequence = int(data['sequence'])
            if BlacklistRule.query.filter_by(sequence=sequence).first():
                flash(f"Rule with sequence {sequence} already exists. Please choose a different sequence.", 'error')
                app_logger.warning(f"Attempted by {current_user.username} to add blacklist rule with duplicate sequence: {sequence}")
                return redirect(url_for('routes.add_blacklist_rule'))
            
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
            app_logger.info(f"Blacklist rule '{new_rule.rule_name}' (ID: {new_rule.id}, Sequence: {new_rule.sequence}) added successfully by {current_user.username}.")
            return redirect(url_for('routes.blacklist_rules_list'))
        except ValueError:
            db.session.rollback()
            flash("Invalid sequence number. Must be an integer.", 'error')
            app_logger.error(f"Failed to add blacklist rule by {current_user.username}: Invalid sequence number provided.")
            return redirect(url_for('routes.add_blacklist_rule'))
        except Exception as e:
            db.session.rollback()
            flash(f"Failed to add blacklist rule: {str(e)}", 'error')
            app_logger.error(f"Failed to add blacklist rule by {current_user.username}: {str(e)}")
            return redirect(url_for('routes.add_blacklist_rule'))
    
    return render_template('add_blacklist_form.html')

@routes.route('/admin/blacklist/<int:rule_id>', methods=['GET'])
@login_required # Ensures user is logged in
@roles_required('superadmin', 'admin', 'implementer')
def blacklist_rule_detail(rule_id):
    """Displays the details of a specific blacklist rule."""
    rule = BlacklistRule.query.get_or_404(rule_id)
    app_logger.info(f"User {current_user.username} viewing details for blacklist rule ID: {rule_id}")
    return render_template('blacklist_rule_detail.html', rule=rule)

# --- API Endpoints for Blacklist Rules (for AJAX calls) ---
@routes.route('/api/blacklist_rules', methods=['GET'])
@login_required # Ensures user is logged in
@roles_required('superadmin', 'admin', 'implementer')
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
            'created_at': rule.created_at.isoformat() if rule.created_at else None,
            'updated_at': rule.updated_at.isoformat() if rule.updated_at else None
        })
    app_logger.info(f"User {current_user.username} fetched all blacklist rules via API.")
    return jsonify(rules_data), 200

@routes.route('/api/blacklist_rules/<int:rule_id>', methods=['DELETE'])
@login_required # Ensures user is logged in
@roles_required('superadmin', 'admin')
def delete_blacklist_rule_api(rule_id):
    """API endpoint to delete a single blacklist rule."""
    rule = BlacklistRule.query.get(rule_id)
    if rule:
        try:
            db.session.delete(rule)
            db.session.commit()
            app_logger.info(f"Blacklist rule ID {rule_id} deleted successfully by {current_user.username} via API.")
            return jsonify({"status": "success", "message": f"Rule ID {rule_id} deleted successfully."}), 200
        except Exception as e:
            db.session.rollback()
            app_logger.error(f"Failed to delete blacklist rule ID {rule_id} by {current_user.username} via API: {str(e)}")
            return jsonify({"status": "error", "message": f"Failed to delete rule ID {rule_id}: {str(e)}"}), 500
    app_logger.warning(f"Attempted to delete non-existent blacklist rule ID {rule_id} by {current_user.username} via API.")
    return jsonify({"status": "error", "message": f"Rule ID {rule_id} not found."}), 404

@routes.route('/api/blacklist_rules', methods=['DELETE'])
@login_required # Ensures user is logged in
@roles_required('superadmin', 'admin')
def delete_multiple_blacklist_rules_api():
    """API endpoint to delete multiple blacklist rules."""
    data = request.get_json()
    rule_ids = data.get('ids', [])
    if not rule_ids:
        app_logger.warning(f"Attempted to delete multiple blacklist rules by {current_user.username}, but no IDs were provided.")
        return jsonify({"status": "error", "message": "No rule IDs provided for deletion."}), 400

    try:
        deleted_count = 0
        for rule_id in rule_ids:
            rule = BlacklistRule.query.get(rule_id)
            if rule:
                db.session.delete(rule)
                deleted_count += 1
        db.session.commit()
        app_logger.info(f"Successfully deleted {deleted_count} blacklist rule(s) by {current_user.username} via API. IDs: {rule_ids}")
        return jsonify({"status": "success", "message": f"Successfully deleted {deleted_count} rule(s)."}), 200
    except Exception as e:
        db.session.rollback()
        app_logger.error(f"Failed to delete multiple blacklist rules by {current_user.username} via API (IDs: {rule_ids}): {str(e)}")
        return jsonify({"status": "error", "message": f"Failed to delete rules: {str(e)}"}), 500


# --- Routes for Approval Workflow ---

@routes.route('/approvals')
@login_required # Ensures user is logged in
@roles_required('superadmin', 'admin', 'approver')
def approvals_list():
    """Displays a list of requests pending approval."""
    # Only show rules that are 'Pending Approval' and not yet denied
    pending_rules = FirewallRule.query.filter_by(status='Pending Approval', approval_status='Pending').all()
    app_logger.info(f"User {current_user.username} viewing list of pending approvals.")
    for rule in pending_rules:
        # Ensure lists are initialized for rendering if None
        if rule.firewalls_involved is None:
            rule.firewalls_involved = []
        if rule.firewalls_to_provision is None:
            rule.firewalls_to_provision = []
        if rule.firewalls_already_configured is None:
            rule.firewalls_already_configured = []
    return render_template('approvals_list.html', rules=pending_rules)

@routes.route('/approvals/<int:rule_id>', methods=['GET', 'POST'])
@login_required # Ensures user is logged in
@roles_required('superadmin', 'admin', 'approver')
@no_self_approval # Prevent approver from approving their own requests
def approve_deny_request(rule_id):
    """Allows an approver to view details and approve/deny a specific request."""
    rule = FirewallRule.query.get_or_404(rule_id)

    if request.method == 'POST':
        action = request.form.get('action')
        approver_comment = request.form.get('approver_comment')
        
        current_approver_id = current_user.id 
        
        if action == 'approve':
            rule.approval_status = "Approved"
            # Set status to 'Approved - Pending Implementation' ONLY if there are firewalls to provision
            # Otherwise, if all are already configured, mark as 'Completed'
            if rule.firewalls_to_provision:
                rule.status = "Approved - Pending Implementation"
            else:
                rule.status = "Completed - No Provisioning Needed" # New status for clarity
                rule.implemented_at = datetime.utcnow() # Mark as implemented immediately
            
            rule.approver_id = current_approver_id
            rule.approver_comment = approver_comment
            rule.approved_at = datetime.utcnow()
            db.session.commit()
            flash('Request approved successfully!', 'success')
            app_logger.info(f"Network request ID {rule_id} approved by {current_user.username} (ID: {current_user.id}). Status set to '{rule.status}'.")
            return redirect(url_for('routes.approvals_list'))
        elif action == 'deny':
            rule.approval_status = "Denied"
            rule.status = "Denied by Approver"
            rule.approver_id = current_approver_id
            rule.approver_comment = approver_comment
            db.session.commit()
            flash('Request denied.', 'info')
            app_logger.info(f"Network request ID {rule_id} denied by {current_user.username} (ID: {current_user.id}).")
            return redirect(url_for('routes.approvals_list'))
        else:
            app_logger.warning(f"Invalid action '{action}' for network request ID {rule.id} by {current_user.username}.")
            return jsonify({"status": "error", "message": "Invalid action specified."}), 400
    
    # Ensure lists are initialized for rendering if None
    if rule.firewalls_involved is None:
        rule.firewalls_involved = []
    if rule.firewalls_to_provision is None:
        rule.firewalls_to_provision = []
    if rule.firewalls_already_configured is None:
        rule.firewalls_already_configured = []

    app_logger.info(f"User {current_user.username} viewing approval details for network request ID {rule.id}.")
    return render_template('approval_detail.html', rule=rule)

# --- Routes for Implementer Workflow ---

@routes.route('/implementation')
@login_required # Ensures user is logged in
@roles_required('superadmin', 'admin', 'implementer')
def implementation_list():
    """Displays a list of rules ready for implementation (approved and pending implementation)."""
    # Only show rules that are 'Approved - Pending Implementation'
    ready_for_implementation_rules = FirewallRule.query.filter_by(status='Approved - Pending Implementation', approval_status='Approved').all()
    app_logger.info(f"User {current_user.username} viewing list of rules ready for implementation.")
    for rule in ready_for_implementation_rules:
        # Ensure lists are initialized for rendering if None
        if rule.firewalls_involved is None:
            rule.firewalls_involved = []
        if rule.firewalls_to_provision is None:
            rule.firewalls_to_provision = []
        if rule.firewalls_already_configured is None:
            rule.firewalls_already_configured = []
    return render_template('implementation_list.html', rules=ready_for_implementation_rules)

@routes.route('/implementation/<int:rule_id>', methods=['GET', 'POST'])
@login_required # Ensures user is logged in
@roles_required('superadmin', 'admin', 'implementer')
def implement_rule(rule_id):
    """Allows an implementer to view details and provision/decline a specific rule."""
    rule = FirewallRule.query.get_or_404(rule_id)

    if request.method == 'POST':
        action = request.form.get('action')
        implementer_comment = request.form.get('implementer_comment')
        current_implementer_id = current_user.id

        if action == 'provision':
            app_logger.info(f"Implementer {current_user.username} triggered provisioning for rule ID {rule_id}.")
            return provision_request(rule_id)
        elif action == 'decline_implementation':
            rule.status = "Declined by Implementer"
            # Append implementer's comment to existing approver comments
            existing_comments = rule.approver_comment if rule.approver_comment else ""
            rule.approver_comment = f"{existing_comments}\nImplementer ({current_user.username}) Comment: {implementer_comment}"
            rule.approver_id = current_implementer_id # Implementer also recorded as the last action user
            db.session.commit()
            flash('Implementation declined.', 'info')
            app_logger.info(f"Implementer {current_user.username} declined implementation for rule ID {rule_id}.")
            return redirect(url_for('routes.implementation_list'))
        else:
            app_logger.warning(f"Invalid action '{action}' for rule implementation ID {rule_id} by {current_user.username}.")
            return jsonify({"status": "error", "message": "Invalid action specified."}), 400
    
    # Ensure lists are initialized for rendering if None
    if rule.firewalls_involved is None:
        rule.firewalls_involved = []
    if rule.firewalls_to_provision is None:
        rule.firewalls_to_provision = []
    if rule.firewalls_already_configured is None:
        rule.firewalls_already_configured = []

    app_logger.info(f"User {current_user.username} viewing implementation details for rule ID {rule.id}.")
    return render_template('implementation_detail.html', rule=rule)


@routes.route('/provision/<int:rule_id>', methods=['POST'])
@login_required # Ensures user is logged in
@roles_required('superadmin', 'admin', 'implementer')
def provision_request(rule_id):
    """
    Triggers the Ansible provisioning playbook for an approved firewall rule.
    Automatically triggers post-check after successful provisioning.
    This function is now called from the implement_rule route.
    """
    rule = FirewallRule.query.get_or_404(rule_id)

    if rule.status != "Approved - Pending Implementation" or rule.approval_status != "Approved":
        app_logger.warning(f"Attempted to provision rule ID {rule_id} by {current_user.username} which is not in 'Approved - Pending Implementation' state. Current status: {rule.status}, Approval: {rule.approval_status}")
        return jsonify({"status": "error", "message": "Rule is not in 'Approved - Pending Implementation' state for provisioning."}), 400

    if not rule.firewalls_to_provision:
        # This case should ideally not happen if logic in create_request/approve is correct
        # But as a safeguard: if there are no firewalls to provision, mark as completed
        rule.status = "Completed - No Provisioning Needed"
        rule.implemented_at = datetime.utcnow()
        db.session.commit()
        app_logger.info(f"Rule {rule.id} had no firewalls to provision. Marked as 'Completed - No Provisioning Needed'.")
        return jsonify({"status": "info", "message": "No firewalls required provisioning for this rule. Status updated.", "redirect_url": url_for('routes.implementation_list')}), 200


    rule.status = "Provisioning In Progress"
    db.session.commit()
    app_logger.info(f"Provisioning initiated by {current_user.username} for rule ID {rule.id}.")
    
    provisioning_message = "Provisioning started."

    try:
        # Use firewalls_to_provision from the rule object
        firewalls_for_ansible_provision = rule.firewalls_to_provision
        
        app_logger.info(f"Provisioning only on firewalls that require it for rule {rule.id}: {firewalls_for_ansible_provision}")

        provision_result_stdout = network_automation_service.provision_rule(
            rule_data={
                'rule_id': rule.id,
                'source_ip': rule.source_ip,
                'destination_ip': rule.destination_ip,
                'protocol': rule.protocol,
                'port': rule.port,
                'rule_description': f"Rule for ticket #{rule.id}"
            },
            firewalls=firewalls_for_ansible_provision # Pass only firewalls that need provisioning
        )
        
        provisioning_message = f"Rule {rule.id} provisioned successfully on required firewalls."
        app_logger.info(f"Rule {rule.id} provisioned successfully by {current_user.username}. Ansible output: {provision_result_stdout}")

        # After successful provisioning, run post-check only on the firewalls that were just provisioned
        # and re-verify any that were already configured (optional, but good for full check)
        firewalls_for_ansible_post_check = rule.firewalls_involved # Post-check all firewalls in path
        
        post_check_result = network_automation_service.check_policy_existence( # Re-run full check
            rule.source_ip, rule.destination_ip, rule.protocol, rule.port, firewalls_for_ansible_post_check
        )
        # Update the rule with the latest check results
        rule.firewalls_to_provision = post_check_result["firewalls_to_provision"]
        rule.firewalls_already_configured = post_check_result["firewalls_already_configured"]
        
        if not rule.firewalls_to_provision: # If no firewalls left to provision after this run
            rule.status = "Completed"
            rule.implemented_at = datetime.utcnow()
            provisioning_message += " All configurations verified successfully."
            app_logger.info(f"Rule {rule.id} post-check successful by {current_user.username}. All firewalls now configured.")
        else:
            # This scenario indicates that even after provisioning, some firewalls still don't have the policy.
            # This is an error state that requires attention.
            rule.status = "Partially Implemented - Requires Attention"
            provisioning_message += f" However, policy could not be verified on: {rule.firewalls_to_provision}. Manual intervention may be required."
            app_logger.error(f"Rule {rule.id} partially implemented. Policy not verified on: {rule.firewalls_to_provision}.")


    except RuntimeError as e:
        rule.status = "Provisioning Failed"
        provisioning_message = f"Provisioning failed for rule {rule.id}: {e}. Check logs for ID {rule.id}."
        app_logger.error(f"Provisioning RuntimeError for rule {rule.id} by {current_user.username}: {e}")
    except Exception as e:
        rule.status = "Provisioning Failed"
        provisioning_message = f"An unexpected error occurred during provisioning/post-check for rule {rule.id}: {e}. Check logs for ID {rule.id}."
        app_logger.critical(f"An unexpected error occurred during provisioning for rule {rule.id} by {current_user.username}: {e}", exc_info=True)
    finally:
        db.session.commit()

    if rule.status in ["Completed", "Completed - No Provisioning Needed"]:
        return jsonify({"status": "success", "message": provisioning_message, "rule_id": rule.id, "new_status": rule.status, "redirect_url": url_for('routes.implementation_list')}), 200
    else:
        # For 'Provisioning Failed' or 'Partially Implemented'
        return jsonify({"status": "error", "message": provisioning_message, "rule_id": rule.id, "new_status": rule.status, "redirect_url": url_for('routes.implementation_list')}), 500
