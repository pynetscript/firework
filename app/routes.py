from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash, abort
from app.models import FirewallRule, BlacklistRule, db, User, ActivityLogEntry
from app.utils import log_activity
import ipaddress
import json
import logging
from datetime import datetime
from flask_login import login_required, current_user
from app.services.network_automation import NetworkAutomationService
from app.services.network_automation import DestinationUnreachableError, PathfindingError
from app.decorators import roles_required, no_self_approval
import os
import psutil
import socket

routes = Blueprint('routes', __name__)

app_logger = logging.getLogger(__name__)

#######################################################################
#                         HELPER FUNCTIONS                            #
#######################################################################

def get_network_automation_service():
    """
    Retrieves the NetworkAutomationService instance attached to the blueprint.
    This instance is created and managed by the Flask app factory (`create_app`).
    """
    if not hasattr(routes, 'network_automation_service'):
        app_logger.warning("NetworkAutomationService not found on blueprint. Creating a fallback instance.")
        routes.network_automation_service = NetworkAutomationService()
    return routes.network_automation_service

def check_port(host, port, timeout=0.5):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False
    finally:
        sock.close()

def get_usage_color(percentage, amber_threshold, red_threshold):
    """
    Determines the color based on percentage usage and thresholds.
    :param percentage: Current usage percentage (0-100).
    :param amber_threshold: Percentage at which status turns amber.
    :param red_threshold: Percentage at which status turns red.
    :return: 'green', 'amber', or 'red'.
    """
    if percentage >= red_threshold:
        return 'red'
    elif percentage >= amber_threshold:
        return 'amber'
    else:
        return 'green'

def is_ip_in_network(ip_str, network_str):
    """
    Checks if an IP address is contained within an IP network (CIDR).
    Handles both IPv4 and IPv6.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        # strict=False allows host bits to be set in the network definition
        network = ipaddress.ip_network(network_str, strict=False)
        return ip in network
    except ValueError as e:
        # Log invalid IP/network strings instead of failing silently
        app_logger.warning(f"Invalid IP or network string encountered during blacklist check: IP='{ip_str}', Network='{network_str}' Error: {e}")
        return False

def check_blacklist_for_request(request_data):
    """
    Checks a given firewall rule request against all active blacklist rules.
    `request_data` should be a dictionary with keys:
    'source_ip', 'destination_ip', 'protocol', 'ports'.
    `ports` in request_data is expected to be a list containing a single string
    (e.g., ["80"], ["any"]).
    """
    source_ip = request_data.get('source_ip')
    destination_ip = request_data.get('destination_ip')
    protocol = request_data.get('protocol', '').lower()
    requested_ports = request_data.get('ports', []) # This will be like ['80'] or ['any']

    # Extract the single requested port value
    requested_port_value = requested_ports[0] if requested_ports else None

    enabled_rules = BlacklistRule.query.filter_by(enabled=True).order_by(BlacklistRule.sequence.asc()).all()

    for rule in enabled_rules:
        rule_protocol = rule.protocol.lower() if rule.protocol else 'any'
        rule_dest_port = rule.destination_port.lower() if rule.destination_port else 'any'

        # --- Source IP Check ---
        source_match = False
        if rule.source_ip:
            if '/' in rule.source_ip: # Rule Source IP is a CIDR
                source_match = is_ip_in_network(source_ip, rule.source_ip)
            else: # Rule Source IP is a specific IP
                source_match = (source_ip == rule.source_ip)
        else: # If rule.source_ip is None, it matches any source IP
            source_match = True

        # --- Destination IP Check ---
        dest_match = False
        if source_match and rule.destination_ip: # Only check if source IP matched
            if '/' in rule.destination_ip: # Rule Destination IP is a CIDR
                dest_match = is_ip_in_network(destination_ip, rule.destination_ip)
            else: # Rule Destination IP is a specific IP
                dest_match = (destination_ip == rule.destination_ip)
        elif source_match: # If no destination_ip in rule, and source matched, dest matches
            dest_match = True

        if not (source_match and dest_match):
            continue # If IPs don't match, move to next rule

        # --- Protocol Check ---
        protocol_match = False
        if rule_protocol == 'any':
            protocol_match = True
        else:
            protocol_match = (protocol == rule_protocol)

        if not protocol_match:
            continue # If protocol doesn't match, move to next rule

        # --- Port Check ---
        port_match = False
        if requested_port_value == 'any' or rule_dest_port == 'any':
            port_match = True
        elif requested_port_value and rule_dest_port: # Both are specific (not 'any')
            try:
                requested_port_int = int(requested_port_value)
                if '-' in rule_dest_port: # Rule has a port range
                    rule_start_port, rule_end_port = map(int, rule_dest_port.split('-'))
                    port_match = (rule_start_port <= requested_port_int <= rule_end_port)
                else: # Rule has a single specific port
                    port_match = (requested_port_int == int(rule_dest_port))
            except ValueError:
                app_logger.warning(f"Error parsing port during blacklist check. Requested: '{requested_port_value}', Rule: '{rule_dest_port}'. Skipping port check for this rule.")
                port_match = False # Treat as non-match if parsing fails

        # If all criteria match, the request is blacklisted
        if source_match and dest_match and protocol_match and port_match:
            app_logger.warning(f"BLACKLIST MATCH: Rule ID {rule.id} ('{rule.rule_name}') matched request: "
                               f"Src:{source_ip}, Dst:{destination_ip}, Proto:{protocol}, Ports:{requested_ports}")
            return True, rule.rule_name # Request is blacklisted, return rule name

    return False, None # No blacklist rule matched

#######################################################################
#                           HOME ROUTES                               #
#######################################################################

@routes.route('/')
@routes.route('/home', methods=['GET'])
@login_required
def home():
    """
    Redirects unauthenticated users to the login page.
    Redirects authenticated users to the dashboard with paginated activity logs.
    """

    if not current_user.is_authenticated:
        return redirect(url_for('auth.login'))

    # --- Pagination
    page = request.args.get('page', 1, type=int)
    per_page = 20
    search_query = request.args.get('search', '', type=str).strip()
    query = ActivityLogEntry.query.order_by(ActivityLogEntry.timestamp.desc())

    if search_query:
        query = query.filter(
            db.or_(
                ActivityLogEntry.username.ilike(f'%{search_query}%'),
                ActivityLogEntry.event_type.ilike(f'%{search_query}%'),
                ActivityLogEntry.description.ilike(f'%{search_query}%'),
                ActivityLogEntry.related_resource_type.ilike(f'%{search_query}%')
            )
        )

    paginated_activities = query.paginate(page=page, per_page=per_page, error_out=False)
    recent_activities = paginated_activities.items

    return render_template(
        'dashboard.html',
        title='Dashboard',
        recent_activities=recent_activities,
        pagination=paginated_activities,
        search_query=search_query
    )

@routes.route('/api/dashboard/application-status')
@login_required
def get_application_status():
    open_tickets = FirewallRule.query.filter(
        FirewallRule.status.in_(['Pending Pre-Check', 'Pending Approval', 'Pending Implementation'])
    ).count()
    pending_approval = FirewallRule.query.filter_by(approval_status='Pending Approval').count()
    pending_implementation = FirewallRule.query.filter_by(status='Pending Implementation').count()
    closed_implemented = FirewallRule.query.filter(
        FirewallRule.status.in_(['Completed - Implemented', 'Completed - Route Not Found', 'Closed Manually', 'Pre-Check Failed'])
    ).count()

    return jsonify({
        'open_tickets': open_tickets,
        'pending_approval': pending_approval,
        'pending_implementation': pending_implementation,
        'closed_implemented': closed_implemented
    })

@routes.route('/api/dashboard/system-status')
@login_required
def get_system_status():
    system_status = {}

    # --- CPU ---
    try:
        cpu_percent = psutil.cpu_percent(interval=0.5)
        system_status['cpu_load'] = {
            'text': f"{cpu_percent}%",
            'color': get_usage_color(cpu_percent, 70, 90) # Amber at 70%, Red at 90%
        }
    except Exception:
        system_status['cpu_load'] = {'text': 'N/A', 'color': 'gray'}

    # --- Memory ---
    try:
        mem = psutil.virtual_memory()
        mem_percent = mem.percent
        system_status['memory_load'] = {
            'text': f"{mem_percent}% ({mem.used / (1024**3):.2f} GB / {mem.total / (1024**3):.2f} GB)",
            'color': get_usage_color(mem_percent, 70, 90) # Amber at 70%, Red at 90%
        }
    except Exception:
        system_status['memory_load'] = {'text': 'N/A', 'color': 'gray'}

    # --- Disk ---
    try:
        disk = psutil.disk_usage('/')
        disk_percent = disk.percent
        system_status['disk_space'] = {
            'text': f"{disk_percent:.1f}% ({disk.used / (1024**3):.2f} GB / {disk.total / (1024**3):.2f} GB)",
            'color': get_usage_color(disk_percent, 70, 90) # Amber at 70%, Red at 90%
        }
    except Exception:
        system_status['disk_space'] = {'text': 'N/A', 'color': 'gray'}

    # --- Bandwidth (ens33) ---
    try:
        net_io = psutil.net_io_counters(pernic=True)
        if 'ens33' in net_io:
            ens33_stats = net_io['ens33']
            system_status['bandwidth_bytes_sent'] = ens33_stats.bytes_sent
            system_status['bandwidth_bytes_recv'] = ens33_stats.bytes_recv
            system_status['bandwidth_error'] = None
        else:
            system_status['bandwidth_bytes_sent'] = 0
            system_status['bandwidth_bytes_recv'] = 0
            system_status['bandwidth_error'] = 'Interface ens33 not found'
    except Exception:
        system_status['bandwidth_bytes_sent'] = 0
        system_status['bandwidth_bytes_recv'] = 0
        system_status['bandwidth_error'] = 'Error fetching network stats'

    # Placeholder for bandwidth color - this will be calculated on frontend
    system_status['bandwidth'] = {'text': 'Calculating...', 'color': 'gray'}

    # Firework
    firework_is_running = True # If this API endpoint is reachable, Firework app is generally running
    system_status['firework_app'] = {
        'text': 'Running' if firework_is_running else 'Not Running',
        'color': 'green' if firework_is_running else 'red'
    }

    # Gunicorn
    try:
        gunicorn_is_running = any("gunicorn" in p.name() for p in psutil.process_iter())
        gunicorn_status_text = 'Running' if gunicorn_is_running else 'Not Running'
        gunicorn_status_color = 'green' if gunicorn_is_running else 'red'
    except Exception:
        gunicorn_status_text = 'Unknown'
        gunicorn_status_color = 'gray' # Use gray for unknown status

    system_status['gunicorn'] = {
        'text': gunicorn_status_text,
        'color': gunicorn_status_color
    }

    # Nginx
    nginx_is_running = check_port('127.0.0.1', 80) or check_port('127.0.0.1', 443)
    system_status['nginx'] = {
        'text': 'Running' if nginx_is_running else 'Not Running',
        'color': 'green' if nginx_is_running else 'red'
    }

    # PostgreSQL
    postgres_is_running = check_port('127.0.0.1', 5432)
    system_status['postgres'] = {
        'text': 'Running' if postgres_is_running else 'Not Running',
        'color': 'green' if postgres_is_running else 'red'
    }

    return jsonify(system_status)

#######################################################################
#                         REQUEST ROUTES                              #
#######################################################################

@routes.route('/request')
@login_required
def request_list():
    """
    Displays the list of all requests.
    Accessible by all authenticated users.
    """
    query = FirewallRule.query

    if current_user.has_role('superadmin') or current_user.has_role('admin'):
        rules = query.order_by(FirewallRule.created_at.desc()).all() # Admins see all
    else: # For requester, approver, implementer
        rules = query.filter(FirewallRule.status.in_([
            'Pending',
            'Pending Pre-Check',
            'Pending Implementation',
            'Provisioning',
            'Provisioning Failed',
            'Completed',
            'Completed - Implemented',
            'Completed - No Provisioning Needed',
            'Completed - Route Not Found',
            "Declined by Implementer",
            "Denied by Approver",
            "Partially Implemented - Requires Attention",
            "Canceled"
        ])).order_by(FirewallRule.created_at.desc()).all()

    # Enrich rules with usernames
    for rule in rules:
        if rule.requester_id:
            requester = User.query.get(rule.requester_id)
            rule.requester_username = requester.username if requester else ''
        else:
            rule.requester_username = ''

        if rule.approver_id:
            approver = User.query.get(rule.approver_id)
            rule.approver_username = approver.username if approver else ''
        else:
            rule.approver_username = ''

        if rule.implementer_id:
            implementer = User.query.get(rule.implementer_id)
            rule.implementer_username = implementer.username if implementer else ''
        else:
            rule.implementer_username = ''

    # Pass rules to the template
    return render_template('request.html', title='Request', rules=rules)

@routes.route('/request/add')
@login_required
@roles_required('superadmin', 'admin', 'requester', 'approver', 'implementer')
def request_form():
    """
    Renders the form for submitting a new request.
    Accessible by superadmin, admin, requester, approver, and implementer roles.
    """
    return render_template('request_form.html')

@routes.route('/request/submit', methods=['POST'])
@login_required
@roles_required('superadmin', 'admin', 'requester', 'approver', 'implementer')
def submit_request():
    """
    Handles the submission of a new request.
    Performs validation, blacklist checks, initiates a pre-check,
    creates the request in the DB, and determines initial status based on pre-check results and roles.
    """
    app_logger.info(f"Received new request from {current_user.username}")
    source_ip = request.form.get('source_ip')
    destination_ip = request.form.get('destination_ip')
    protocol = request.form.get('protocol')
    ports_raw = request.form.get('ports')
    rule_description = request.form.get('rule_description')

    errors = []

    # Validate source IP
    try:
        # Attempt to parse as an IP address (for /32 equivalent or single IPs)
        ipaddress.ip_address(source_ip)
    except ValueError:
        try:
            # If it's not a single IP, attempt to parse as a network (CIDR)
            ipaddress.ip_network(source_ip)
        except ValueError:
            errors.append('Invalid Source IP address or CIDR format.')

    # Validate destination IP
    try:
        # Attempt to parse as an IP address (for /32 equivalent or single IPs)
        ipaddress.ip_address(destination_ip)
    except ValueError:
        try:
            # If it's not a single IP, attempt to parse as a network (CIDR)
            ipaddress.ip_network(destination_ip)
        except ValueError:
            errors.append('Invalid Destination IP address or CIDR format.')

    # Validate protocol
    allowed_protocols = ['tcp', 'udp', 'icmp', 'any', '6', '17', '1']
    if protocol.lower() not in allowed_protocols and not protocol.isdigit():
        errors.append('Invalid Protocol. Must be tcp, udp, icmp, any, or a protocol number.')

    # Validate port: Allow only a single port (0-65535) or the string "any"
    ports = []
    if protocol.lower() in ['icmp', 'any', '1']:
        ports = ['any'] # For ICMP or ANY protocol, ports are 'any'
    elif ports_raw:
        ports_raw_lower = ports_raw.strip().lower()
        if ports_raw_lower == 'any':
            ports = ['any']
        else:
            try:
                port_num = int(ports_raw)
                if 0 <= port_num <= 65535:
                    ports = [str(port_num)] # Store as string in list for consistency with 'any'
                else:
                    errors.append(f'Invalid port: {ports_raw}. Must be a number between 0-65535 or "any".')
            except ValueError:
                errors.append(f'Invalid port: {ports_raw}. Must be a number between 0-65535 or "any".')

    if not ports and protocol.lower() not in ['icmp', 'any', '1']:
        errors.append('Port is required for the specified protocol. Must be a number between 0-65535 or "any".')

    if errors:
        for error in errors:
            flash(error, 'error')
        app_logger.warning(f"Validation errors for new request from {current_user.username}: {errors}")
        log_activity(
            event_type='REQUEST_FAILED',
            description=f"User '{current_user.username}' failed to submit request due to validation errors: {', '.join(errors)}.",
            user=current_user
        )
        return jsonify({"status": "error", "message": "Validation failed", "errors": errors}), 400

    # Prepare request data for blacklist check using the 'ports' list
    request_data = {
        'source_ip': source_ip,
        'destination_ip': destination_ip,
        'protocol': protocol,
        'ports': ports # This is the list ['80'] or ['any']
    }

    blacklisted, matching_blacklist_rule_name = check_blacklist_for_request(request_data)

    if blacklisted:
        flash(f"Request [{source_ip},{destination_ip},{protocol},{ports_raw}] denied by blacklist rule '{matching_blacklist_rule_name or ''}'.", 'error')
        app_logger.info(f"Request [{source_ip},{destination_ip},{protocol},{ports_raw}] denied by blacklist rule '{matching_blacklist_rule_name or ''}'.")
        log_activity(
            event_type='BLACKLIST_DENIED',
            description=f"Request [{source_ip},{destination_ip},{protocol},{ports_raw}] denied by blacklist rule '{matching_blacklist_rule_name or ''}'.",
            user=current_user
        )
        return jsonify({"status": "error", "message": "Request blocked by blacklist rule."}), 403
    else:
        app_logger.info(f"Request [{source_ip},{destination_ip},{protocol},{ports_raw}] by user {current_user.username} passed blacklist check.")
        log_activity(
            event_type='BLACKLIST_PASSED',
            description=f"Request [{source_ip},{destination_ip},{protocol},{ports_raw}] passed blacklist check.",
            user=current_user
        )

    # Create the new rule with a temporary status before pre-check
    new_rule = FirewallRule(
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol=protocol,
        ports=ports, # Save as a list
        status='Pending Pre-Check', # Temporary status
        rule_description=rule_description,
        approval_status='Pending Pre-Check', # Temporary status
        requester_id=current_user.id
    )
    db.session.add(new_rule)
    db.session.commit() # Commit to get an ID for the rule, important for pre-check
    app_logger.info(f"Request ID {new_rule.id} created by {current_user.username} with temporary status 'Pending Pre-Check'.")

    # --- Perform Pre-Check for ALL requests ---
    try:
        rule_data_for_precheck = {
            'rule_id': new_rule.id,
            'source_ip': new_rule.source_ip,
            'destination_ip': new_rule.destination_ip,
            'protocol': new_rule.protocol,
            'ports': new_rule.ports,
            'rule_description': rule_description
        }

        # The perform_pre_check method returns 4 values.
        stdout, stderr, discovered_firewalls, firewalls_already_configured = \
            get_network_automation_service().perform_pre_check(
                rule_data=rule_data_for_precheck,
                firewalls_involved=[] # This list is dynamically populated by the service
            )

        # Retrieve the rule again to ensure we're working with the latest data after pre-check
        db_rule = FirewallRule.query.get(new_rule.id)
        if db_rule:
            # Assign the firewall lists directly from the returned values
            db_rule.firewalls_involved = discovered_firewalls
            db_rule.firewalls_already_configured = firewalls_already_configured

            # firewalls_to_provision is populated into rule_data_for_precheck by perform_pre_check
            db_rule.firewalls_to_provision = rule_data_for_precheck.get('firewalls_to_provision', [])

            db_rule.pre_check_result_stdout = stdout
            db_rule.pre_check_result_stderr = stderr

            if stdout:
                app_logger.info(f"Pre-check STDOUT for request ID {db_rule.id}:\n{stdout}")
            if stderr:
                app_logger.error(f"Pre-check STDERR for request ID {db_rule.id}:\n{stderr}")

            # Determine final status after pre-check, considering user roles for approval
            # Check for no firewalls in path first, regardless of user role
            if not db_rule.firewalls_involved or len(db_rule.firewalls_involved) == 0:
                db_rule.status = 'Completed - No Provisioning Needed'
                db_rule.approval_status = 'Approved'
                flash_message = f"Request ID {db_rule.id} completed as no firewalls were involved."
                app_logger.info(f"Request ID {db_rule.id} submitted by '{current_user.username}' completed as no firewalls were involved.")
                log_activity(
                    event_type='REQUEST_COMPLETED',
                    description=f"Request ID {db_rule.id} completed as no firewalls were involved.",
                    user=current_user,
                    related_resource_id=db_rule.id,
                    related_resource_type='FirewallRule'
                )

            elif current_user.has_role('superadmin', 'admin'):
                # Admin/Superadmin specific logic when firewalls ARE involved
                db_rule.approval_status = 'Approved' # Auto-approve for admins

                if db_rule.firewalls_to_provision and len(db_rule.firewalls_to_provision) > 0:
                    db_rule.status = 'Pending Implementation'
                    flash_message = f"Request ID {db_rule.id} auto-approved and pending implementation."
                    app_logger.info(f"Request ID {db_rule.id} auto-approved and pending implementation on firewalls: {', '.join(db_rule.firewalls_to_provision)}")
                    log_activity(
                        event_type='REQUEST_CREATED',
                        description=f"Request ID {db_rule.id} auto-approved and pending implementation on firewalls: {', '.join(db_rule.firewalls_to_provision)}.",
                        user=current_user,
                        related_resource_id=db_rule.id,
                        related_resource_type='FirewallRule'
                    )

                elif db_rule.firewalls_involved and db_rule.firewalls_already_configured and \
                     set(db_rule.firewalls_involved) == set(db_rule.firewalls_already_configured):
                    db_rule.status = 'Completed - No Provisioning Needed'
                    flash_message = f"Request ID {db_rule.id} auto-approved and completed as policy already exists on: {', '.join(db_rule.firewalls_already_configured)}"
                    app_logger.info(f"Request ID {db_rule.id} auto-approved and completed as policy already exists on: {', '.join(db_rule.firewalls_already_configured)}")
                    log_activity(
                        event_type='REQUEST_COMPLETED',
                        description=f"Request ID {db_rule.id} auto-approved and completed as policy already exists on: {', '.join(db_rule.firewalls_already_configured)}.",
                        user=current_user,
                        related_resource_id=db_rule.id,
                        related_resource_type='FirewallRule'
                    )
                else:
                    db_rule.status = 'Approved - Review Needed'
                    flash_message = f"Request ID {db_rule.id} auto-approved but requires manual review. firewalls_involved={db_rule.firewalls_involved}, firewalls_to_provision={db_rule.firewalls_to_provision}, firewalls_already_configured={db_rule.firewalls_already_configured}"
                    app_logger.warning(f"Request ID {db_rule.id} auto-approved but requires manual review: firewalls_involved={db_rule.firewalls_involved}, firewalls_to_provision={db_rule.firewalls_to_provision}, firewalls_already_configured={db_rule.firewalls_already_configured}")
                    log_activity(
                        event_type='REQUEST_CREATED_REVIEW_NEEDED',
                        description=f"Request ID {db_rule.id} auto-approved but requires manual review. firewalls_involved={db_rule.firewalls_involved}, firewalls_to_provision={db_rule.firewalls_to_provision}, firewalls_already_configured={db_rule.firewalls_already_configured}",
                        user=current_user,
                        related_resource_id=db_rule.id,
                        related_resource_type='FirewallRule'
                    )

                app_logger.info(f"User {current_user.username} (role: {current_user.role}) auto-approved request {db_rule.id}.")
            else:
                # For non-admin roles when firewalls ARE involved, it goes to Pending Approval
                db_rule.status = 'Pending'
                db_rule.approval_status = 'Pending Approval'
                flash_message = f"Request ID {db_rule.id} submitted successfully"
                app_logger.info(f"Request ID {db_rule.id} submitted successfully by user {current_user.username}.")
                log_activity(
                    event_type='REQUEST_CREATED',
                    description=f"Request ID {db_rule.id} submitted successfully.",
                    user=current_user,
                    related_resource_id=db_rule.id,
                    related_resource_type='FirewallRule'
                )

            db.session.commit()
            flash(flash_message, 'info') # Flash messages will still work on the redirected page

            # Determine if the current user can access approvals
            can_access_approvals = current_user.has_role('approver') or \
                                   current_user.has_role('admin') or \
                                   current_user.has_role('superadmin')

            return jsonify({
                "status": "success",
                "message": flash_message,
                "redirect_url": url_for('routes.request_list'),
                "rule_id": db_rule.id,
                "status_detail": db_rule.status,
                "approval_status": db_rule.approval_status,
                "firewalls_involved": discovered_firewalls,
                "can_access_approvals": can_access_approvals
            }), 200

    except DestinationUnreachableError as e:
        db.session.rollback()
        db_rule = FirewallRule.query.get(new_rule.id)
        if db_rule:
            db_rule.status = 'Completed - Route Not Found'
            db_rule.approval_status = 'Closed'
            db.session.commit()
        app_logger.warning(f"Network automation pre-check failed for request ID {new_rule.id}: {e}")
        log_activity(
            event_type='REQUEST_FAILED',
            description=f"Network automation pre-check failed for request ID {new_rule.id}. Error: {str(e)}.",
            user=current_user,
            related_resource_id=new_rule.id,
            related_resource_type='FirewallRule'
        )
        return jsonify({
            "status": "error",
            "message": str(e),
            "ticket_status": "closed",
            "reason": "destination_not_found",
            "rule_id": new_rule.id
        }), 400
    except RuntimeError as e:
        db.session.rollback()
        db_rule = FirewallRule.query.get(new_rule.id)
        if db_rule:
            db_rule.status = 'Pre-Check Failed'
            db_rule.approval_status = 'Pre-Check Failed'
            db.session.commit()
        app_logger.error(f"Network automation pre-check failed for request ID {new_rule.id}: {e}", exc_info=True)
        flash(f"Pre-check failed: {e}", 'error')
        log_activity(
            event_type='REQUEST_FAILED',
            description=f"Network automation pre-check failed for request ID {new_rule.id}. Runtime error: {str(e)}.",
            user=current_user,
            related_resource_id=new_rule.id,
            related_resource_type='FirewallRule'
        )
        return redirect(url_for('routes.request_form'))
    except Exception as e:
        db.session.rollback()
        db_rule = FirewallRule.query.get(new_rule.id)
        if db_rule:
            db_rule.status = 'Error During Pre-Check'
            db_rule.approval_status = 'Error'
            db.session.commit()
        app_logger.critical(f"An unexpected error occurred during network automation pre-check for request ID {new_rule.id}: {e}", exc_info=True)
        flash(f"An unexpected error occurred during network automation pre-check: {e}.", 'error')
        log_activity(
            event_type='REQUEST_FAILED',
            description=f"An unexpected error occurred during network automation pre-check for request ID {new_rule.id}. Error: {str(e)}.",
            user=current_user,
            related_resource_id=new_rule.id,
            related_resource_type='FirewallRule'
        )
        return redirect(url_for('routes.request_form'))

@routes.route('/request/cancel/<int:rule_id>', methods=['POST'])
@login_required
def cancel_request(rule_id):
    """
    Allows the user who created the request to cancel it.
    """
    rule = FirewallRule.query.get_or_404(rule_id)

    # Only the user who created the request can cancel it.
    if rule.requester_id != current_user.id:
        app_logger.warning(f"Unauthorized cancellation attempt: User {current_user.username} (ID: {current_user.id}) tried to cancel rule {rule_id} owned by {rule.requester_id}.")
        log_activity(
            event_type='REQUEST_CANCEL_FAILED',
            description=f"Unauthorized cancellation attempt: User {current_user.username} (ID: {current_user.id}) tried to cancel rule {rule_id} owned by {rule.requester_id}.",
            user=current_user,
            related_resource_id=rule_id,
            related_resource_type='FirewallRule'
        )
        return jsonify({"status": "error", "message": "You are not authorized to cancel this request. Only the owner of this request can cancel it."}), 403

    # Define statuses that CANNOT be cancelled via this method.
    if rule.status in ['Completed', 'Completed - No Provisioning Needed', 'Denied by Approver', 'Declined by Implementer', 'Partially Implemented - Requires Attention', 'Provisioning In Progress']:
        app_logger.warning(f"Cancellation attempt failed: Rule ID {rule_id} (status: {rule.status}) cannot be cancelled by {current_user.username}. Current status: {rule.status}")
        log_activity(
            event_type='REQUEST_CANCEL_DENIED',
            description=f"Cancellation attempt failed: Rule ID {rule_id} (status: {rule.status}) cannot be cancelled by {current_user.username}. Current status: {rule.status}",
            user=current_user,
            related_resource_id=rule_id,
            related_resource_type='FirewallRule'
        )
        return jsonify({"status": "error", "message": f"This request is currently '{rule.status}' and cannot be cancelled."}), 400

    try:
        rule.status = "Cancelled"
        rule.approval_status = "Cancelled"
        db.session.commit()
        app_logger.info(f"Request ID {rule_id} sucessfully cancelled by {current_user.username}.")
        log_activity(
            event_type='REQUEST_CANCEL_SUCCESS',
            description=f"Request ID {rule_id} successfully cancelled.",
            user=current_user,
            related_resource_id=rule_id,
            related_resource_type='FirewallRule'
        )
        return jsonify({"status": "success", "message": f"Request ID {rule_id} successfully cancelled."}), 200
    except Exception as e:
        db.session.rollback()
        app_logger.error(f"Error cancelling request ID {rule_id} by {current_user.username}: {str(e)}", exc_info=True)
        return jsonify({"status": "error", "message": f"An error occurred while cancelling the request: {e}"}), 500

#######################################################################
#                         APPROVAL ROUTES                             #
#######################################################################

@routes.route('/approval')
@login_required
@roles_required('superadmin', 'admin', 'approver')
def approvals_list():
    """
    Displays a list of requests pending approval (for approvers)
    or all requests that are pending/approved (for superadmins/admins).
    """
    if current_user.has_role('superadmin') or current_user.has_role('admin'):
        rules = FirewallRule.query.filter(
            FirewallRule.approval_status.in_(['Pending Approval', 'Approved'])
        ).order_by(FirewallRule.created_at.desc()).all()
    elif current_user.has_role('approver'):
        rules = FirewallRule.query.filter(FirewallRule.approval_status.in_(['Pending Approval', 'Approved'])).order_by(FirewallRule.created_at.desc()).all()
    else:
        # Fallback for any other role that might somehow access this (though roles_required should prevent it)
        rules = []

    # Enrich rules with requester, approver, and implementer usernames
    for rule in rules:
        if rule.requester_id:
            requester = User.query.get(rule.requester_id)
            rule.requester_username = requester.username if requester else ''
        else:
            rule.requester_username = ''

        if rule.approver_id:
            approver = User.query.get(rule.approver_id)
            rule.approver_username = approver.username if approver else ''
        else:
            rule.approver_username = ''

        if rule.implementer_id:
            implementer = User.query.get(rule.implementer_id)
            rule.implementer_username = implementer.username if implementer else ''
        else:
            rule.implementer_username = ''

    return render_template('approval_list.html', rules=rules)


@routes.route('/approval/<int:rule_id>', methods=['GET', 'POST'])
@login_required
@roles_required('superadmin', 'admin', 'approver')
@no_self_approval # Prevent approvers from approving their own requests
def approve_deny_request(rule_id):
    """
    Allows approvers to review, approve, or deny requests.
    Approval will transition the request to 'Pending Implementation' status
    without triggering automation.
    """
    rule = FirewallRule.query.get_or_404(rule_id)

    # Ensure only pending rules can be acted upon by non-superadmin/admin approvers
    if not current_user.has_role('superadmin', 'admin') and rule.approval_status != 'Pending Approval':
        flash('Request ID {rule.id} is not pending approval.', 'warning')
        app_logger.info(f"Request ID {rule.id} is not pedning approval. Status: {rule.approval_status}).")
        log_activity(
            event_type='APPROVAL_FAILED',
            description=f"Request ID {rule.id} is not pending approval. Status: {rule.approval_status}).",
            user=current_user,
            related_resource_id=rule.id,
            related_resource_type='FirewallRule'
        )
        return redirect(url_for('routes.approvals_list'))

    if request.method == 'POST':
        action = request.form.get('action')
        justification = request.form.get('approver_comment')

        rule.approver_id = current_user.id
        rule.approval_justification = justification

        if action == 'approve':
            rule.status = 'Pending Implementation'
            rule.approval_status = 'Approved'
            rule.approved_at = datetime.utcnow()
            flash(f"Request ID {rule.id} sucessfully approved.", 'success')
            app_logger.info(f"Request ID {rule.id} sucessfully approved by {current_user.username}. Status: {rule.status}.")
            log_activity(
                event_type='APPROVAL_SUCCESSFUL',
                description=f"Request ID {rule.id} sucessfully approved. Justification: '{justification or 'None'}'.",
                user=current_user,
                related_resource_id=rule.id,
                related_resource_type='FirewallRule'
            )

        elif action == 'deny':
            rule.status = 'Denied by Approver'
            rule.approval_status = 'Denied'
            flash(f"Request ID {rule.id} denied by {current_user.username}.", 'info')
            app_logger.info(f"Request ID {rule.id} denied by {current_user.username}.")
            log_activity(
                event_type='APPROVAL_DENIED',
                description=f"Request ID {rule.id} denied by '{current_user.username}'. Justification: '{justification or 'None'}'.",
                user=current_user,
                related_resource_id=rule.id,
                related_resource_type='FirewallRule'
            )

        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            app_logger.error(f"Request ID {rule.id} by {current_user.username} failed: {e}", exc_info=True)
            flash(f"Request ID {rule.id} failed: {e}", 'error')
            log_activity(
                event_type='APPROVAL_FAILED',
                description=f"Request ID {rule.id} failed. Action: {action}. Error: {str(e)}.",
                user=current_user,
                related_resource_id=rule.id,
                related_resource_type='FirewallRule'
            )
            return redirect(url_for('routes.approvals_list'))

        return redirect(url_for('routes.approvals_list'))

    # Enrich rule with usernames for display
    if rule.requester_id:
        requester = User.query.get(rule.requester_id)
        rule.requester_username = requester.username if requester else ''
    else:
        rule.requester_username = ''

    return render_template('approval_detail.html', rule=rule)

#######################################################################
#                      IMPLEMENTATION ROUTES                          #
#######################################################################

@routes.route('/implementation')
@login_required
@roles_required('superadmin', 'admin', 'implementer')
def implementation_list():
    """
    Displays a list of requests pending implementation.
    """
    rules = FirewallRule.query.filter(
        FirewallRule.status.in_(['Pending Implementation', 'Provisioning In Progress', 'Partially Implemented - Requires Attention', 'Declined by Implementer', 'Completed'])
    ).order_by(FirewallRule.created_at.asc()).all()

    for rule in rules:
        if rule.requester_id:
            requester = User.query.get(rule.requester_id)
            rule.requester_username = requester.username if requester else ''
        else:
            rule.requester_username = ''

        if rule.approver_id:
            approver = User.query.get(rule.approver_id)
            rule.approver_username = approver.username if approver else ''
        else:
            rule.approver_username = ''

        if rule.implementer_id:
            implementer = User.query.get(rule.implementer_id)
            rule.implementer_username = implementer.username if implementer else ''
        else:
            rule.implementer_username = ''

    return render_template('implementation_list.html', rules=rules)

@routes.route('/implementation/<int:rule_id>', methods=['GET', 'POST'])
@login_required
@roles_required('superadmin', 'admin', 'implementer')
def implement_rule(rule_id):
    """
    Allows implementers to review and provision requests.
    Triggers provisioning and post-checks.
    """
    rule = FirewallRule.query.get_or_404(rule_id)

    # Enrich the single 'rule' object with usernames
    if rule.requester_id:
        requester = User.query.get(rule.requester_id)
        rule.requester_username = requester.username if requester else ''
    else:
        rule.requester_username = ''

    if rule.approver_id:
        approver = User.query.get(rule.approver_id)
        rule.approver_username = approver.username if approver else ''
    else:
        rule.approver_username = ''

    if rule.implementer_id:
        implementer = User.query.get(rule.implementer_id)
        rule.implementer_username = implementer.username if implementer else ''
    else:
        rule.implementer_username = ''

    # Only allow action if status is 'Pending Implementation' or 'Partially Implemented - Requires Attention'
    if rule.status not in ['Pending Implementation', 'Partially Implemented - Requires Attention']:
        flash(f"Request ID {rule_id} is currently '{rule.status}'. No implementation action available.", 'info')
        app_logger.info(f"Request ID {rule_id} is currently '{rule.status}'. No implementation action available.")
        log_activity(
            event_type='IMPLEMENTATION_FAILED',
            description=f"Request ID {rule.id} is currently '{rule.status}'. No implementation action available.",
            user=current_user,
            related_resource_id=rule.id,
            related_resource_type='FirewallRule'
        )
        return redirect(url_for('routes.implementation_list'))

    if request.method == 'POST':
        action = request.form.get('action')
        implementer_comment = request.form.get('implementer_comment')

        rule.implementer_id = current_user.id
        rule.implementer_comment = implementer_comment
        rule.implemented_at = datetime.utcnow()

        if action == 'provision':
            firewalls_to_provision = rule.firewalls_to_provision if rule.firewalls_to_provision else []
            if not firewalls_to_provision:
                rule.status = 'Completed - No Provisioning Needed'
                db.session.commit()
                flash(f"Request ID {rule.id} marked as 'Completed - No Provisioning Needed' (no firewalls to provision).", 'info')
                app_logger.info(f"Request ID {rule.id} marked as 'Completed - No Provisioning Needed' by {current_user.username} (no firewalls to provision).")
                log_activity(
                    event_type='IMPLEMENTATION_NOT_REQUIRED',
                    description=f"Request ID {rule.id} marked as 'Completed - No Provisioning Needed' by {current_user.username} (no firewalls to provision).",
                    user=current_user,
                    related_resource_id=rule.id,
                    related_resource_type='FirewallRule'
                )
                return redirect(url_for('routes.implementation_list'))

            try:
                rule.status = 'Provisioning In Progress'
                db.session.commit()

                # Perform provisioning
                provision_stdout, provision_stderr, successfully_provisioned, failed_provisioning = \
                    get_network_automation_service().provision_firewall_rule(
                        rule_data={
                            'rule_id': rule.id,
                            'source_ip': rule.source_ip,
                            'destination_ip': rule.destination_ip,
                            'protocol': rule.protocol,
                            'ports': rule.ports,
                            'rule_description': rule.rule_description
                        },
                        firewalls_to_provision=firewalls_to_provision
                    )

                if provision_stdout:
                    app_logger.info(f"Provisioning STDOUT for request ID {rule.id}:\n{provision_stdout}")
                if provision_stderr:
                    app_logger.error(f"Provisioning STDERR for request ID {rule.id}:\n{provision_stderr}")

                rule.firewalls_already_configured = list(set(rule.firewalls_already_configured or []) | set(successfully_provisioned))
                rule.firewalls_to_provision = [fw for fw in firewalls_to_provision if fw not in successfully_provisioned]


                if len(failed_provisioning) == 0:
                    # All provisioned, now perform post-check
                    post_check_stdout, post_check_stderr, verified_firewalls, unverified_firewalls = \
                        get_network_automation_service().perform_post_check(
                            rule_data={
                                'rule_id': rule.id,
                                'source_ip': rule.source_ip,
                                'destination_ip': rule.destination_ip,
                                'protocol': rule.protocol,
                                'ports': rule.ports,
                                'rule_description': rule.rule_description
                            },
                            provisioned_firewalls=successfully_provisioned
                        )
                    if post_check_stdout:
                        app_logger.info(f"Post-check STDOUT for request ID {rule.id}:\n{post_check_stdout}")
                    if post_check_stderr:
                        app_logger.error(f"Post-check STDERR for request ID {rule.id}:\n{post_check_stderr}")

                    if len(unverified_firewalls) == 0:
                        rule.status = 'Completed'
                        flash(f"Request ID {rule.id} successfully provisioned and verified on all target firewalls.", 'success')
                        app_logger.info(f"Request ID {rule.id} by '{current_user.username} successfully provisioned and verified on all target firewalls: {', '.join(successfully_provisioned)}.")
                        log_activity(
                             event_type='IMPLEMENTATION_SUCCESSFUL',
                             description=f"Request ID {rule.id} successfully provisioned and verified on all target firewalls: {', '.join(successfully_provisioned)}.",
                             user=current_user,
                             related_resource_id=rule.id,
                             related_resource_type='FirewallRule'
                         )
                    else:
                        rule.status = 'Partially Implemented - Requires Attention'
                        flash(f"Request ID {rule.id} provisioned but failed verification on some firewalls: {', '.join(unverified_firewalls)}. Provisioned on: {', '.join(successfully_provisioned)}.", 'warning')
                        app_logger.info(f"Request ID {rule.id} by '{current_user.username} provisioned but failed verification on some firewalls: {', '.join(unverified_firewalls)}. Provisioned on: {', '.join(successfully_provisioned)}.")
                        log_activity(
                            event_type='IMPLEMENTATION_PARTIAL',
                            description=f"Request ID {rule.id} provisioned but failed verification on some firewalls: {', '.join(unverified_firewalls)}. Provisioned on: {', '.join(successfully_provisioned)}.",
                            user=current_user,
                            related_resource_id=rule.id,
                            related_resource_type='FirewallRule'
                        )

                else:
                    if len(successfully_provisioned) > 0:
                        rule.status = 'Partially Implemented - Requires Attention'
                        flash(f"Request ID {rule.id} partially implemented. Failed on: {', '.join(failed_provisioning)}. Successful on: {', '.join(successfully_provisioned)}.", 'warning')
                        app_logger.info(f"Request ID {rule.id} partially implemented by '{current_user.username}'. Failed on: {', '.join(failed_provisioning)}. Successful on: {', '.join(successfully_provisioned)}.")
                        log_activity(
                            event_type='IMPLEMENTATION_PARTIAL',
                            description=f"Request ID {rule.id} partially implemented. Failed on: {', '.join(failed_provisioning)}. Successful on: {', '.join(successfully_provisioned)}.",
                            user=current_user,
                            related_resource_id=rule.id,
                            related_resource_type='FirewallRule'
                        )
                    else:
                        rule.status = 'Provisioning Failed'
                        flash(f"Request ID {rule.id} failed implementation on all target firewalls: {', '.join(failed_provisioning)}.", 'error')
                        app_logger.info(f"Request ID {rule.id} failed implementation by '{current_user.username}' on all target firewalls {', '.join(failed_provisioning)}.")
                        log_activity(
                            event_type='IMPLEMENTATION_FAILED',
                            description=f"Request ID {rule.id} failed implementation on all target firewalls {', '.join(failed_provisioning)}.",
                            user=current_user,
                            related_resource_id=rule.id,
                            related_resource_type='FirewallRule'
                        )

                db.session.commit()
                app_logger.info(f"Implementer {current_user.username} processed request ID {rule.id}. Final status: {rule.status}.")

            except RuntimeError as e:
                rule.status = 'Implementation Failed - Automation Error'
                db.session.commit()
                flash(f"Automation runtime error during implementation for request ID {rule.id}: {e}", 'error')
                app_logger.error(f"Automation runtime error during implementation for request ID {rule.id}: {e}", exc_info=True)
                log_activity(
                    event_type='IMPLEMENTATION_ERROR',
                    description=f"Automation runtime error during implementation for request ID {rule.id}. Error: {str(e)}.",
                    user=current_user,
                    related_resource_id=rule.id,
                    related_resource_type='FirewallRule'
                )
            except Exception as e:
                rule.status = 'Implementation Failed - Unexpected Error'
                db.session.commit()
                flash(f"An unexpected error occurred during implementation for request ID {rule.id}: {e}", 'error')
                app_logger.critical(f"An unexpected error occurred during implementation for request ID {rule.id}: {e}", exc_info=True)
                log_activity(
                    event_type='IMPLEMENTATION_ERROR',
                    description=f"An unexpected error occurred during implementation for request ID {rule.id}. Error: {str(e)}.",
                    user=current_user,
                    related_resource_id=rule.id,
                    related_resource_type='FirewallRule'
                )

        elif action == 'decline_implementation':
            rule.status = 'Declined by Implementer'
            db.session.commit()
            flash(f"Implementer '{current_user.username}' declined implementation for request ID {rule.id}.", 'warning')
            app_logger.info(f"Implementer '{current_user.username}' declined implementation for request ID {rule.id}.")
            log_activity(
                event_type='IMPLEMENTATION_DECLINED',
                description=f"Implementer '{current_user.username}' declined implementation for request ID {rule.id}. Justification: '{implementer_comment or 'None'}'.",
                user=current_user,
                related_resource_id=rule.id,
                related_resource_type='FirewallRule'
            )

        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash(f"Failed to commit final implementation status for request ID {rule.id}: {e}", 'error')
            app_logger.error(f"Failed to commit final implementation status for request ID {rule.id} by {current_user.username}: {e}", exc_info=True)
            log_activity(
                event_type='IMPLEMENTATION_ERROR',
                description=f"Failed to commit final implementation status for request ID {rule.id}. Action: {action}. Error: {str(e)}.",
                user=current_user,
                related_resource_id=rule.id,
                related_resource_type='FirewallRule'
            )
            return redirect(url_for('routes.implementation_list'))

        return redirect(url_for('routes.implementation_list'))

    return render_template('implementation_detail.html', rule=rule)

#######################################################################
#                       BLACKLIST ROUTES                              #
#######################################################################

@routes.route('/admin/blacklist-rules')
@login_required
@roles_required('superadmin', 'admin')
def blacklist_rules_list():
    """
    Displays a list of all blacklist rules.
    Accessible only by superadmin and admin roles.
    """
    return render_template('blacklist_rule_list.html')

@routes.route('/admin/blacklist-rules/add', methods=['GET', 'POST'])
@login_required
@roles_required('superadmin', 'admin')
def add_blacklist_rule():
    """
    Allows superadmin and admin roles to add new blacklist rules.
    """
    if request.method == 'POST':
        sequence = request.form.get('sequence', type=int)
        rule_name = request.form.get('rule_name')
        enabled = request.form.get('enabled') == 'True'
        source_ip = request.form.get('source_ip') or None
        destination_ip = request.form.get('destination_ip') or None
        protocol = request.form.get('protocol') or None
        destination_port = request.form.get('destination_port') or None
        description = request.form.get('description') or None

        errors = []
        if not rule_name:
            errors.append("Rule Name is required.")
        if sequence is None:
            errors.append("Sequence is required and must be an integer.")
        elif BlacklistRule.query.filter_by(sequence=sequence).first():
            errors.append(f"A rule with sequence {sequence} already exists. Please choose a unique sequence number.")

        if source_ip:
            try:
                ipaddress.ip_network(source_ip, strict=False)
            except ValueError:
                errors.append("Invalid Source IP format.")

        if destination_ip:
            try:
                ipaddress.ip_network(destination_ip, strict=False)
            except ValueError:
                errors.append("Invalid Destination IP format.")

        if protocol and protocol.lower() not in ['tcp', 'udp', 'icmp', 'any', '6', '17', '1']:
            errors.append("Invalid Protocol. Must be tcp, udp, icmp, or should be left blank for 'any'.")

        if destination_port:
            if destination_port.lower() == 'any':
                pass
            else:
                try:
                    port_num = int(destination_port)
                    if not (0 <= port_num <= 65535):
                        errors.append("Invalid port number. Must be between 0-65535 or 'any'.")
                except ValueError:
                    errors.append("Invalid port format. Must be a single port number (0-65535) or 'any'.")

            if protocol and protocol.lower() in ['icmp', '1'] and destination_port and destination_port.lower() not in ['any', '']:
                errors.append("For ICMP protocol, destination port should be 'any' or left blank.")
            if protocol and protocol.lower() == 'any' and destination_port and destination_port.lower() not in ['any', '']:
                errors.append("For 'any' protocol, destination port should be 'any' or left blank.")

        if errors:
            for error in errors:
                flash(error, 'error')
            app_logger.warning(f"User {current_user.username} failed to add blacklist rule due to validation errors: {errors}")
            log_activity(
                event_type='BLACKLIST_RULE_FAILED',
                description=f"Failed to add blacklist rule due to validation errors: {', '.join(errors)}",
                user=current_user,
                status='failed',
                context={'rule_name': rule_name, 'sequence': sequence, 'source_ip': source_ip, 'destination_ip': destination_ip}
            )
            return render_template('blacklist_rule_add.html',
                                   sequence=sequence, rule_name=rule_name, enabled=enabled,
                                   source_ip=source_ip, destination_ip=destination_ip,
                                   protocol=protocol, destination_port=destination_port, description=description,
                                   is_edit_mode=False,
                                   title='Add Blacklist Rule')

        new_rule = BlacklistRule(
            sequence=sequence,
            rule_name=rule_name,
            enabled=enabled,
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            destination_port=destination_port,
            description=description,
            created_by_user_id=current_user.id,
            last_updated_by_user_id=current_user.id
        )
        db.session.add(new_rule)
        try:
            db.session.commit()
            flash(f"Blacklist rule '{rule_name}' added successfully!", 'success')
            app_logger.info(f"Blacklist rule ID {new_rule.id} ('{new_rule.rule_name}') added by {current_user.username}.")
            log_activity(
                event_type='BLACKLIST_RULE_CREATED',
                description=f"Blacklist rule '{new_rule.rule_name}' (ID: {new_rule.id}, Sequence: {new_rule.sequence}) was created.",
                user=current_user,
                related_resource_id=new_rule.id,
                related_resource_type='BlacklistRule'
            )
            return redirect(url_for('routes.blacklist_rules_list'))
        except Exception as e:
            db.session.rollback()
            flash(f"Error adding blacklist rule: {e}", 'error')
            app_logger.error(f"Error adding blacklist rule by {current_user.username}: {e}", exc_info=True)
            log_activity(
                event_type='BLACKLIST_RULE_FAILED',
                description=f"Failed to add blacklist rule '{rule_name}' (Sequence: {sequence}): {str(e)}",
                user=current_user,
                status='failed',
                context={'rule_name': rule_name, 'sequence': sequence}
            )
            return render_template('blacklist_rule_add.html',
                                   sequence=sequence, rule_name=rule_name, enabled=enabled,
                                   source_ip=source_ip, destination_ip=destination_ip,
                                   protocol=protocol, destination_port=destination_port, description=description)

    return render_template('blacklist_rule_add.html',
                           is_edit_mode=False,
                           title='Add New Blacklist Rule')

@routes.route('/admin/blacklist-rules/detail/<int:rule_id>')
@login_required
@roles_required('superadmin', 'admin')
def blacklist_rule_detail(rule_id):
    """
    Displays detailed information about a specific blacklist rule.
    """
    rule = BlacklistRule.query.get_or_404(rule_id)

    created_at_utc = rule.created_at.isoformat() + 'Z' if rule.created_at else None
    updated_at_utc = rule.updated_at.isoformat() + 'Z' if rule.updated_at else None

    return render_template('blacklist_rule_detail.html',
                           rule=rule,
                           created_at_utc=created_at_utc,
                           updated_at_utc=updated_at_utc,
                           title=f'Blacklist Rule Details (ID: {rule_id})'
                           )

@routes.route('/admin/blacklist-rules/delete/<int:rule_id>', methods=['POST'])
@login_required
@roles_required('superadmin', 'admin')
def delete_blacklist_rule(rule_id):
    """
    Deletes a single blacklist rule by ID and redirects to the list page.
    This route is hit by the standard HTML form submission.
    """
    rule = BlacklistRule.query.get(rule_id)
    if not rule:
        flash(f"Blacklist rule with ID {rule_id} not found.", 'error')
        app_logger.warning(f"Attempted to delete non-existent blacklist rule ID {rule_id} by {current_user.username}.")
        log_activity(
            event_type='BLACKLIST_RULE_DELETE_FAILED',
            description=f"Attempted to delete non-existent blacklist rule ID {rule_id}.",
            user=current_user,
            status='failed',
            related_resource_id=rule_id,
            related_resource_type='BlacklistRule'
        )
        return redirect(url_for('routes.blacklist_rules_list'))

    rule_name_for_log = rule.rule_name

    try:
        db.session.delete(rule)
        db.session.commit()
        flash(f"Blacklist rule '{rule_name_for_log}' (ID: {rule_id}) deleted successfully.", 'success')
        app_logger.info(f"Blacklist rule ID {rule_id} ('{rule_name_for_log}') deleted by {current_user.username}.")
        log_activity(
            event_type='BLACKLIST_RULE_DELETED',
            description=f"Blacklist rule '{rule_name_for_log}' (ID: {rule_id}) was deleted.",
            user=current_user,
            related_resource_id=rule_id,
            related_resource_type='BlacklistRule'
        )
        return redirect(url_for('routes.blacklist_rules_list'))
    except Exception as e:
        db.session.rollback()
        app_logger.error(f"Error deleting blacklist rule {rule_id} by {current_user.username}: {str(e)}", exc_info=True)
        flash(f"Error deleting rule '{rule_name_for_log}': {e}", 'error')
        log_activity(
            event_type='BLACKLIST_RULE_DELETE_FAILED',
            description=f"Failed to delete blacklist rule '{rule_name_for_log}' (ID: {rule_id}). Error: {str(e)}",
            user=current_user,
            status='failed',
            related_resource_id=rule_id,
            related_resource_type='BlacklistRule'
        )
        return redirect(url_for('routes.blacklist_rules_list'))

@routes.route('/admin/blacklist-rules/edit/<int:rule_id>', methods=['GET', 'POST'])
@login_required
@roles_required('superadmin', 'admin')
def edit_blacklist_rule(rule_id):
    """
    Allows superadmin and admin roles to edit existing blacklist rules.
    """
    rule = BlacklistRule.query.get_or_404(rule_id)

    sequence_data = rule.sequence
    rule_name_data = rule.rule_name
    enabled_data = rule.enabled
    source_ip_data = rule.source_ip
    destination_ip_data = rule.destination_ip
    protocol_data = rule.protocol
    destination_port_data = rule.destination_port
    description_data = rule.description

    if request.method == 'POST':
        sequence_data = request.form.get('sequence', type=int)
        rule_name_data = request.form.get('rule_name')
        enabled_data = request.form.get('enabled') == 'on'
        source_ip_data = request.form.get('source_ip') or None
        destination_ip_data = request.form.get('destination_ip') or None
        protocol_data = request.form.get('protocol') or None
        destination_port_data = request.form.get('destination_port') or None
        description_data = request.form.get('description') or None

        errors = []
        if not rule_name_data:
            errors.append("Rule Name is required.")
        if sequence_data is None:
            errors.append("Sequence is required and must be an integer.")
        elif sequence_data != rule.sequence and BlacklistRule.query.filter_by(sequence=sequence_data).first():
            errors.append(f"A rule with sequence {sequence_data} already exists. Please choose a unique sequence number.")

        # --- IP Address Validation ---
        if source_ip_data:
            try:
                ipaddress.ip_network(source_ip_data, strict=False)
            except ValueError:
                errors.append("Invalid Source IP format.")

        if destination_ip_data:
            try:
                ipaddress.ip_network(destination_ip_data, strict=False)
            except ValueError:
                errors.append("Invalid Destination IP format.")

        # --- Protocol Validation ---
        if protocol_data and protocol_data.lower() not in ['tcp', 'udp', 'icmp', 'any', '6', '17', '1']:
            errors.append("Invalid Protocol. Must be tcp, udp, icmp, any, or protocol number.")

        # --- Destination Port Validation ---
        if destination_port_data:
            if destination_port_data.lower() == 'any':
                pass
            else:
                try:
                    port_num = int(destination_port_data)
                    if not (0 <= port_num <= 65535):
                        errors.append("Invalid port number. Must be between 0-65535 or 'any'.")
                except ValueError:
                    errors.append("Invalid port format. Must be a single port number (0-65535) or 'any'.")

        if protocol_data and protocol_data.lower() in ['icmp', '1'] and destination_port_data and destination_port_data.lower() not in ['any', '']:
            errors.append("For ICMP protocol, destination port should be 'any' or left blank.")
        if protocol_data and protocol_data.lower() == 'any' and destination_port_data and destination_port_data.lower() not in ['any', '']:
            errors.append("For 'any' protocol, destination port should be 'any' or left blank.")

        if errors:
            # Flash all accumulated errors
            for error in errors:
                flash(error, 'error')
            app_logger.warning(f"Validation errors for editing blacklist rule {rule.id} from {current_user.username}: {errors}")

            # Re-render the form with the submitted data to preserve user input
            return render_template('blacklist_rule_add.html',
                                   rule=rule, # Still pass the 'rule' object for rule.id in title
                                   sequence=sequence_data, rule_name=rule_name_data, enabled=enabled_data,
                                   source_ip=source_ip_data, destination_ip=destination_ip_data,
                                   protocol=protocol_data, destination_port=destination_port_data,
                                   description=description_data,
                                   title=f'Edit Blacklist Rule ID: {rule_id}',
                                   is_edit_mode=True
                                   )

        # If no errors, update the rule object and commit to DB
        rule.sequence = sequence_data
        rule.rule_name = rule_name_data
        rule.enabled = enabled_data
        rule.source_ip = source_ip_data
        rule.destination_ip = destination_ip_data
        rule.protocol = protocol_data
        rule.destination_port = destination_port_data
        rule.description = description_data
        rule.updated_at = datetime.utcnow()
        rule.last_updated_by_user_id = current_user.id

        try:
            db.session.commit()
            flash(f'Blacklist rule {rule.id} updated successfully!', 'success')
            app_logger.info(f"Blacklist rule {rule.id} updated by {current_user.username}.")
            log_activity(
                event_type='BLACKLIST_RULE_UPDATED',
                description=f"Blacklist rule '{rule.rule_name}' (ID: {rule.id}, Sequence: {rule.sequence}) was updated.",
                user=current_user,
                related_resource_id=rule.id,
                related_resource_type='BlacklistRule'
            )
            # Redirect to the list page after successful update
            return redirect(url_for('routes.blacklist_rules_list'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating blacklist rule: {e}', 'error')
            app_logger.error(f"Error updating blacklist rule {rule.id} by {current_user.username}: {e}", exc_info=True)
            log_activity(
                event_type='BLACKLIST_RULE_ERROR',
                description=f"Error updating blacklist rule {rule.id}.",
                user=current_user,
                related_resource_id=rule.id,
                related_resource_type='BlacklistRule'
            )
            # Re-render form with submitted data in case of DB error
            return render_template('blacklist_rule_add.html',
                                   rule=rule, # Still pass 'rule' for title
                                   sequence=sequence_data, rule_name=rule_name_data, enabled=enabled_data,
                                   source_ip=source_ip_data, destination_ip=destination_ip_data,
                                   protocol=protocol_data, destination_port=destination_port_data,
                                   description=description_data,
                                   title=f'Edit Blacklist Rule ID: {rule_id}',
                                   is_edit_mode=True
                                   )

    # This block is for the initial GET request (when you first click 'Edit')
    # All 'data' variables are already pre-populated from the 'rule' object at the top
    return render_template('blacklist_rule_add.html',
                           rule=rule, # Pass the rule object itself for {{ rule.id }} in the title
                           sequence=sequence_data,
                           rule_name=rule_name_data,
                           enabled=enabled_data,
                           source_ip=source_ip_data,
                           destination_ip=destination_ip_data,
                           protocol=protocol_data,
                           destination_port=destination_port_data,
                           description=description_data,
                           title=f'Edit Blacklist Rule ID: {rule_id}',
                           is_edit_mode=True
                           )

@routes.route('/api/blacklist_rules', methods=['GET'])
@login_required
@roles_required('superadmin', 'admin')
def api_get_blacklist_rules():
    """
    API endpoint to retrieve all blacklist rules as JSON.
    """
    try:
        rules = BlacklistRule.query.order_by(BlacklistRule.sequence.asc()).all()
        rules_data = [rule.to_dict() for rule in rules]
        return jsonify(rules_data), 200
    except Exception as e:
        app_logger.error(f"API: Error retrieving blacklist rules: {e}", exc_info=True)
        return jsonify({"status": "error", "message": "Failed to retrieve blacklist rules."}), 500

@routes.route('/api/blacklist_rules', methods=['DELETE'])
@login_required
@roles_required('superadmin', 'admin')
def api_delete_blacklist_rules():
    """
    API endpoint to delete multiple blacklist rules by IDs.
    """
    data = request.get_json()
    rule_ids = data.get('ids', [])

    if not rule_ids:
        log_activity(
            event_type='BLACKLIST_RULES_BULK_DELETE_FAILED',
            description="Attempted bulk deletion of blacklist rules but no IDs were provided.",
            user=current_user
        )
        app_logger.warning(f"API: No rule IDs provided for bulk deletion by {current_user.username}.")
        return jsonify({"status": "error", "message": "No rule IDs provided for deletion."}), 400

    deleted_rule_names = []
    deleted_rule_ids = []

    try:
        rules_to_delete = []
        for rule_id in rule_ids:
            rule = BlacklistRule.query.get(rule_id)
            if rule:
                deleted_rule_names.append(rule.rule_name)
                deleted_rule_ids.append(rule.id)
                rules_to_delete.append(rule)
            else:
                log_activity(
                    event_type='BLACKLIST_RULE_DELETE_FAILED',
                    description=f"Attempted to delete non-existent blacklist rule ID {rule_id} during bulk operation.",
                    user=current_user,
                    related_resource_id=rule_id,
                    related_resource_type='BlacklistRule'
                )
                app_logger.warning(f"API: Blacklist rule ID {rule_id} not found for bulk deletion by {current_user.username}.")

        for rule_obj in rules_to_delete:
            db.session.delete(rule_obj)

        db.session.commit()
        deleted_count = len(deleted_rule_ids)
        #flash(f"{deleted_count} blacklist rules deleted:  {deleted_rule_ids}.", 'success')
        app_logger.info(f"API: {deleted_count} blacklist rules deleted by {current_user.username}: {deleted_rule_ids}.")
        log_activity(
            event_type='BLACKLIST_RULES_BULK_DELETE',
            description=f"{deleted_count} blacklist rule(s) deleted via API. IDs: {deleted_rule_ids}. Names: {deleted_rule_names}.",
            user=current_user
        )
        return jsonify({"status": "success", "message": f"{deleted_count} rule(s) deleted successfully."}), 200 

    except Exception as e:
        db.session.rollback()
        log_activity(
            event_type='BLACKLIST_RULES_BULK_DELETE_FAILED',
            description=f"Failed to delete multiple blacklist rules via API. Attempted IDs: {rule_ids}. Error: {str(e)}",
            user=current_user
        )
        app_logger.error(f"API: Error deleting multiple blacklist rules by {current_user.username}: {e}", exc_info=True)
        return jsonify({"status": "error", "message": f"An error occurred during bulk deletion: {e}"}), 500

#######################################################################
#                        PROFILE ROUTES                               #
#######################################################################

@routes.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """
    Allows a user to view and update their profile information (email, first/last name, password).
    Username and role are not editable by the user.
    """
    user = current_user

    if request.method == 'POST':
        original_email = user.email
        original_first_name = user.first_name
        original_last_name = user.last_name

        email = request.form.get('email')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        password = request.form.get('password')

        errors = []

        if not email:
            errors.append('Email is required.')
        elif email != user.email and User.query.filter_by(email=email).first():
            errors.append('Email address already registered by another user.')

        if errors:
            for error in errors:
                flash(error, 'error')
            app_logger.warning(f"Profile update failed for {user.username}: {errors}")
            return render_template('profile.html', user=user)

        password_changed = False
        if password:
            user.set_password(password)
            flash('Password updated successfully.', 'success')
            app_logger.info(f"User {user.username} (ID: {user.id}) updated their password.")
            log_activity(
                event_type='USER_PASSWORD_CHANGED',
                description=f"User {user.username} (ID: {user.id}) changed their own password.",
                user=user,
                related_resource_id=user.id,
                related_resource_type='User'
            )
            password_changed = True

        user.email = email
        user.first_name = first_name
        user.last_name = last_name

        try:
            changes_made = False
            change_details = []

            if user.email != original_email:
                change_details.append(f"Email changed from '{original_email}' to '{user.email}'")
                changes_made = True
            if user.first_name != original_first_name:
                change_details.append(f"First name changed from '{original_first_name}' to '{user.first_name}'")
                changes_made = True
            if user.last_name != original_last_name:
                change_details.append(f"Last name changed from '{original_last_name}' to '{user.last_name}'")
                changes_made = True

            db.session.commit()
            flash('Profile updated successfully!', 'success')
            app_logger.info(f"User {user.username} (ID: {user.id}) updated their profile.")

            if changes_made:
                log_activity(
                    event_type='PROFILE_UPDATED',
                    description=f"User {user.username} (ID: {user.id}) updated his profile. Changes: {'; '.join(change_details)}",
                    user=user,
                    related_resource_id=user.id,
                    related_resource_type='User'
                )
            elif  password_changed:
                pass
            return redirect(url_for('routes.profile'))
        except Exception as e:
            db.session.rollback()
            flash(f"Error updating profile: {e}", 'error')
            app_logger.error(f"Error updating profile for {user.username}: {e}", exc_info=True)
            return render_template('profile.html', user=user)

    return render_template('profile.html', user=user)

@routes.route('/admin/debug')
@login_required
@roles_required('superadmin')
def admin_debug():
    """
    Displays the content of the firework_app.log file for superadmins.
    """
    log_content = "Log file not found."
    log_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'firework_app.log')

    try:
        with open(log_file_path, 'r') as f:
            log_content = f.read()
    except FileNotFoundError:
        app_logger.error(f"firework_app.log not found at: {log_file_path}")
        flash("Error: Log file 'firework_app.log' could not be found.", 'error')
    except Exception as e:
        app_logger.error(f"Error reading firework_app.log: {e}", exc_info=True)
        flash(f"Error reading log file: {e}", 'error')

    return render_template('debug.html', log_content=log_content, title='Debug')
