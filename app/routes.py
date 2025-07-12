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
            'text': f"{disk_percent}% used ({disk.free / (1024**3):.2f} GB free)",
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
    creates the rule in the DB, and determines initial status based on pre-check results and roles.
    """
    app_logger.info(f"Received new request from {current_user.username}")
    source_ip = request.form.get('source_ip')
    destination_ip = request.form.get('destination_ip')
    protocol = request.form.get('protocol')
    ports_raw = request.form.get('ports')
    rule_description = request.form.get('rule_description')

    errors = []

    # Validate IP addresses
    try:
        ipaddress.ip_address(source_ip)
    except ValueError:
        errors.append('Invalid Source IP address format.')

    try:
        ipaddress.ip_address(destination_ip)
    except ValueError:
        errors.append('Invalid Destination IP address format.')

    # Validate protocol (simple check)
    allowed_protocols = ['tcp', 'udp', 'icmp', 'any', '6', '17', '1']
    if protocol.lower() not in allowed_protocols and not protocol.isdigit():
        errors.append('Invalid Protocol. Must be tcp, udp, icmp, any, or a protocol number.')

    # Process ports: Allow only a single port (0-65535) or the string "any"
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

    blacklisted = False
    matching_blacklist_rule_name = None

    # Blacklist check
    try:
        blacklisted = False
        blacklist_rules = BlacklistRule.query.filter_by(enabled=True).order_by(BlacklistRule.sequence.asc()).all()

        for rule in blacklist_rules:
            ip_match = True
            protocol_match = True
            port_match = True

            # Source IP check
            if rule.source_ip:
                try:
                    if '/' in rule.source_ip: # CIDR notation
                        if not ipaddress.ip_address(source_ip) in ipaddress.ip_network(rule.source_ip):
                            ip_match = False
                    else: # Single IP
                        if source_ip != rule.source_ip:
                            ip_match = False
                except ValueError:
                    app_logger.warning(f"Invalid source_ip in blacklist rule {rule.id}: {rule.source_ip}")
                    ip_match = False # Treat as non-match if rule is malformed

            # Destination IP check
            if ip_match and rule.destination_ip: # Only check if source IP matched
                try:
                    if '/' in rule.destination_ip: # CIDR notation
                        if not ipaddress.ip_address(destination_ip) in ipaddress.ip_network(rule.destination_ip):
                            ip_match = False
                    else: # Single IP
                        if destination_ip != rule.destination_ip:
                            ip_match = False
                except ValueError:
                    app_logger.warning(f"Invalid destination_ip in blacklist rule {rule.id}: {rule.destination_ip}")
                    ip_match = False # Treat as non-match if rule is malformed

            # Protocol check
            if ip_match and rule.protocol and rule.protocol.lower() != 'any':
                if protocol.lower() != rule.protocol.lower():
                    protocol_match = False

            # Port check (only if protocol matches)
            # This logic must handle rule.destination_port being 'any', a single port, or a range
            # And requested ports being ['any'] or ['single_port_number_string']
            if ip_match and protocol_match and rule.destination_port: # If rule has a destination port specified
                rule_dest_port_lower = rule.destination_port.lower()
                requested_port_value = ports[0] if ports else None # Get the single requested port (or 'any')

                if requested_port_value == 'any':
                    # If requested is 'any', it matches any rule that specifies a port (whether 'any' or specific)
                    # We assume if a rule.destination_port exists, 'any' request matches it.
                    pass # port_match remains True
                elif rule_dest_port_lower == 'any':
                    # If rule's destination port is 'any', it matches the specific requested port
                    pass # port_match remains True
                else:
                    # Both requested and rule ports are specific (not 'any').
                    # Convert requested port to int. Rule port can be single or range.
                    try:
                        requested_port_int = int(requested_port_value)

                        if '-' in rule_dest_port_lower:
                            start, end = map(int, rule_dest_port_lower.split('-'))
                            if not (start <= requested_port_int <= end):
                                port_match = False
                        else:
                            if requested_port_int != int(rule_dest_port_lower):
                                port_match = False
                    except ValueError:
                        # Should not happen with prior validation, but for robustness
                        app_logger.warning(f"Error parsing port in blacklist check for rule {rule.id}. Requested: {requested_port_value}, Rule: {rule_dest_port_lower}")
                        port_match = False # Treat as non-match if parsing fails

            if ip_match and protocol_match and port_match:
                blacklisted = True
                app_logger.warning(f"Request from {source_ip} to {destination_ip}:{ports_raw}/{protocol} BLOCKED by blacklist rule ID {rule.id} ('{rule.rule_name}') for user {current_user.username}.")
                break # Exit loop if a blacklist rule matches

        if blacklisted:
            flash(f"Your request from {source_ip} to {destination_ip}:{ports_raw}/{protocol} matches a blacklisted pattern and cannot be submitted. Contact an administrator for details.", 'error')
            log_activity(
                event_type='BLACKLIST_DENIED',
                description=f"Request [{source_ip},{destination_ip},{protocol},{ports_raw}] denied by blacklist rule '{matching_blacklist_rule_name or ''}'.",
                user=current_user
            )
            return jsonify({"status": "error", "message": "Request blocked by blacklist rule."}), 403
        else:
            log_activity(
                event_type='BLACKLIST_PASSED',
                description=f"Request [{source_ip},{destination_ip},{protocol},{ports_raw}] passed blacklist check.",
                user=current_user
            )
            app_logger.info(f"Request from {source_ip} to {destination_ip}:{ports_raw}/{protocol} passed blacklist check for user {current_user.username}.")

    except Exception as e:
        app_logger.error(f"Error during blacklist check: {e}", exc_info=True)
        flash("An error occurred during the blacklist check. Please try again or contact support.", 'error')
        log_activity(
            event_type='BLACKLIST_ERROR',
            description=f"Error during blacklist check: {str(e)}. Matching rule was '{matching_blacklist_rule_name or 'None'}'.",
            user=current_user
        )
        return jsonify({"status": "error", "message": "Internal error during blacklist check."}), 500

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
                app_logger.info(f"Pre-check STDOUT for rule {db_rule.id}:\n{stdout}")
            if stderr:
                app_logger.error(f"Pre-check STDERR for rule {db_rule.id}:\n{stderr}")

            # Determine final status after pre-check, considering user roles for approval
            # Check for no firewalls in path first, regardless of user role
            if not db_rule.firewalls_involved or len(db_rule.firewalls_involved) == 0:
                # Scenario: No firewalls found in the path for ANY role
                db_rule.status = 'Completed - No Provisioning Needed'
                db_rule.approval_status = 'Approved' # Implied approval if no action is needed
                flash_message = f"Request ID {db_rule.id} submitted. No firewalls discovered in the traffic path. Marked as 'Completed - No Provisioning Needed'."
                app_logger.info(f"Rule {db_rule.id} completed as no firewalls were found in path for user {current_user.username}.")
                log_activity(
                    event_type='REQUEST_COMPLETED',
                    description=f"Request ID {db_rule.id} submitted by '{current_user.username}' completed as no firewalls were involved.",
                    user=current_user,
                    related_resource_id=db_rule.id,
                    related_resource_type='FirewallRule'
                )

            elif current_user.has_role('superadmin', 'admin'):
                # Admin/Superadmin specific logic when firewalls ARE involved
                db_rule.approval_status = 'Approved' # Auto-approve for admins

                if db_rule.firewalls_to_provision and len(db_rule.firewalls_to_provision) > 0:
                    db_rule.status = 'Pending Implementation'
                    flash_message = f"Request ID {db_rule.id} auto-approved and moved to 'Pending Implementation' after pre-check."
                    app_logger.info(f"Rule {db_rule.id} approved and pending implementation on: {', '.join(db_rule.firewalls_to_provision)}")
                    log_activity(
                        event_type='REQUEST_CREATED',
                        description=f"Request ID {db_rule.id} submitted by '{current_user.username}' auto-approved and pending implementation on firewalls: {', '.join(db_rule.firewalls_to_provision)}.",
                        user=current_user,
                        related_resource_id=db_rule.id,
                        related_resource_type='FirewallRule'
                    )

                elif db_rule.firewalls_involved and db_rule.firewalls_already_configured and \
                     set(db_rule.firewalls_involved) == set(db_rule.firewalls_already_configured):
                    db_rule.status = 'Completed - No Provisioning Needed'
                    flash_message = f"Request ID {db_rule.id} auto-approved. Policy already exists on all involved firewalls. Marked as 'Completed - No Provisioning Needed'."
                    app_logger.info(f"Rule {db_rule.id} completed as policy already exists on: {', '.join(db_rule.firewalls_already_configured)}")
                    log_activity(
                        event_type='REQUEST_COMPLETED',
                        description=f"Request ID {db_rule.id} submitted by '{current_user.username}' auto-approved and found to be already configured on all involved firewalls: {', '.join(db_rule.firewalls_already_configured)}.",
                        user=current_user,
                        related_resource_id=db_rule.id,
                        related_resource_type='FirewallRule'
                    )
                else:
                    db_rule.status = 'Approved - Review Needed'
                    flash_message = f"Request ID {db_rule.id} auto-approved. Review needed for its final status."
                    app_logger.warning(f"Rule {db_rule.id} auto-approved but requires review: firewalls_involved={db_rule.firewalls_involved}, firewalls_to_provision={db_rule.firewalls_to_provision}, firewalls_already_configured={db_rule.firewalls_already_configured}")
                    log_activity(
                        event_type='REQUEST_CREATED_REVIEW_NEEDED',
                        description=f"Request ID {db_rule.id} submitted by '{current_user.username}' auto-approved but requires manual review.",
                        user=current_user,
                        related_resource_id=db_rule.id,
                        related_resource_type='FirewallRule'
                    )

                app_logger.info(f"User {current_user.username} (role: {current_user.role}) auto-approved request {db_rule.id}.")
            else:
                # For non-admin roles when firewalls ARE involved, it goes to Pending Approval
                db_rule.status = 'Pending'
                db_rule.approval_status = 'Pending Approval'
                flash_message = f"Request ID {db_rule.id} submitted successfully and is now 'Pending' after pre-check."
                app_logger.info(f"Request ID {db_rule.id} moved to 'Pending Approval' after pre-check for user {current_user.username}.")
                log_activity(
                    event_type='REQUEST_CREATED',
                    description=f"Request ID {db_rule.id} submitted by '{current_user.username}' is now pending approval.",
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
                "rule_id": db_rule.id,  # Include the rule ID
                "status_detail": db_rule.status,  # Include the detailed status
                "approval_status": db_rule.approval_status, # Include approval status
                "firewalls_involved": discovered_firewalls, # Include discovered firewalls
                "can_access_approvals": can_access_approvals # Include flag for approvals link
            }), 200

    except DestinationUnreachableError as e:
        db.session.rollback()
        db_rule = FirewallRule.query.get(new_rule.id)
        if db_rule:
            db_rule.status = 'Completed - Route Not Found'
            db_rule.approval_status = 'Closed'
            db.session.commit()
        app_logger.warning(f"Network automation pre-check indicated unreachable destination for rule {new_rule.id}: {e}")
        log_activity(
            event_type='REQUEST_FAILED',
            description=f"Pre-check failed for request ID {new_rule.id}. Error: {str(e)}.",
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
        app_logger.error(f"Network automation pre-check failed for rule {new_rule.id}: {e}", exc_info=True)
        flash(f"Pre-check failed: {e}", 'error')
        log_activity(
            event_type='REQUEST_FAILED',
            description=f"Pre-check failed for request ID {new_rule.id}. Runtime error: {str(e)}.",
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
        app_logger.critical(f"An unexpected error occurred during network automation pre-check for rule {new_rule.id}: {e}", exc_info=True)
        flash(f"An unexpected error occurred during pre-check: {e}. Please contact the administartor.", 'error')
        log_activity(
            event_type='REQUEST_FAILED',
            description=f"An unexpected error occurred during pre-check for request ID {new_rule.id}. Please contact the administrator. Error: {str(e)}.",
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
            event_type='UNAUTHORIZED_CANCELLATION_ATTEMPT',
            description=f"Unauthorized attempt to cancel rule ID {rule_id} by user {current_user.username}.",
            user=current_user,
            related_resource_id=rule_id,
            related_resource_type='FirewallRule'
        )
        return jsonify({"status": "error", "message": "You are not authorized to cancel this request. Only the original creator can cancel their own requests."}), 403

    # Define statuses that CANNOT be cancelled via this method.
    if rule.status in ['Completed', 'Completed - No Provisioning Needed', 'Denied by Approver', 'Declined by Implementer', 'Partially Implemented - Requires Attention', 'Provisioning In Progress']:
        app_logger.warning(f"Cancellation attempt failed: Rule ID {rule_id} (status: {rule.status}) cannot be cancelled by {current_user.username}. Current status: {rule.status}")
        log_activity(
            event_type='CANCELLATION_BLOCKED',
            description=f"Cancellation of rule ID {rule_id} by {current_user.username} blocked due to current status: '{rule.status}'.",
            user=current_user,
            related_resource_id=rule_id,
            related_resource_type='FirewallRule'
        )
        return jsonify({"status": "error", "message": f"This request is currently '{rule.status}' and cannot be cancelled."}), 400

    try:
        rule.status = "Cancelled"
        rule.approval_status = "Cancelled"
        db.session.commit()
        app_logger.info(f"request ID {rule_id} cancelled by {current_user.username} (ID: {current_user.id}).")
        log_activity(
            event_type='REQUEST_CANCELLED',
            description=f"Request ID {rule_id} successfully cancelled.",
            user=current_user,
            related_resource_id=rule_id,
            related_resource_type='FirewallRule'
        )
        return jsonify({"status": "success", "message": f"Request ID {rule_id} has been successfully cancelled."}), 200
    except Exception as e:
        db.session.rollback()
        app_logger.error(f"Error cancelling request ID {rule_id} by {current_user.username}: {str(e)}", exc_info=True)
        return jsonify({"status": "error", "message": f"An error occurred while cancelling the request: {e}"}), 500

#######################################################################
#                         APPROVAL ROUTES                             #
#######################################################################

@routes.route('/approvals')
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


@routes.route('/approvals/<int:rule_id>', methods=['GET', 'POST'])
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
        flash('This request is not pending approval.', 'warning')
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
            flash(f"Request ID {rule.id} successfully approved!", 'success')
            app_logger.info(f"Request ID {rule.id} approved by {current_user.username}. Status: {rule.status}.")
            log_activity(
                event_type='APPROVAL_SUCCESSFUL',
                description=f"Request ID {rule.id} successfully approved! Justification: '{justification or 'None'}'.",
                user=current_user,
                related_resource_id=rule.id,
                related_resource_type='FirewallRule'
            )

        elif action == 'deny':
            rule.status = 'Denied by Approver'
            rule.approval_status = 'Denied'
            flash(f"Rule {rule.id} denied by {current_user.username}.", 'info')
            app_logger.info(f"Rule {rule.id} denied by {current_user.username}.")
            log_activity(
                event_type='APPROVAL_DENIED',
                description=f"Request ID {rule.id} denied by approver '{current_user.username}'. Justification: '{justification or 'None'}'.",
                user=current_user,
                related_resource_id=rule.id,
                related_resource_type='FirewallRule'
            )

        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            app_logger.error(f"Error committing rule ID {rule.id} by {current_user.username}: {e}", exc_info=True)
            flash(f"Error commiting rule ID {rule.id}: {e}", 'error')
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
        flash(f"Rule ID {rule_id} is currently '{rule.status}'. No implementation action available.", 'info')
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
                flash("No firewalls marked for provisioning for this rule. Marking as 'Completed - No Provisioning Needed'.", 'info')
                rule.status = 'Completed - No Provisioning Needed'
                db.session.commit()
                app_logger.info(f"Rule {rule.id} marked as 'Completed - No Provisioning Needed' by {current_user.username} (no firewalls to provision).")
                return redirect(url_for('routes.implementation_list'))

            try:
                rule.status = 'Provisioning In Progress' # Set status before starting
                db.session.commit() # Commit status change immediately

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
                    app_logger.info(f"Provisioning STDOUT for rule {rule.id}:\n{provision_stdout}")
                if provision_stderr:
                    app_logger.error(f"Provisioning STDERR for rule {rule.id}:\n{provision_stderr}")

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
                        app_logger.info(f"Post-check STDOUT for rule {rule.id}:\n{post_check_stdout}")
                    if post_check_stderr:
                        app_logger.error(f"Post-check STDERR for rule {rule.id}:\n{post_check_stderr}")

                    if len(unverified_firewalls) == 0:
                        rule.status = 'Completed'
                        flash(f"Rule ID {rule.id} successfully provisioned and verified on all target firewalls.", 'success')
                    else:
                        rule.status = 'Partially Implemented - Requires Attention'
                        flash(f"Rule ID {rule.id} provisioned but failed verification on some firewalls: {', '.join(unverified_firewalls)}. Please investigate.", 'warning')

                else: # Some provisioning failed
                    if len(successfully_provisioned) > 0:
                        rule.status = 'Partially Implemented - Requires Attention'
                        flash(f"Rule ID {rule.id} partially provisioned. Failed on: {', '.join(failed_provisioning)}. Please investigate.", 'warning')
                    else:
                        rule.status = 'Provisioning Failed'
                        flash(f"Rule ID {rule.id} failed provisioning on all target firewalls: {', '.join(failed_provisioning)}.", 'error')

                db.session.commit()
                app_logger.info(f"Implementer {current_user.username} (ID: {current_user.id}) processed rule {rule.id}. Final status: {rule.status}.")

            except RuntimeError as e:
                rule.status = 'Implementation Failed - Automation Error'
                db.session.commit()
                app_logger.error(f"Automation failed during provisioning/post-check for rule {rule.id}: {e}", exc_info=True)
                flash(f"Implementation failed due to automation error: {e}", 'error')
            except Exception as e:
                rule.status = 'Implementation Failed - Unexpected Error'
                db.session.commit()
                app_logger.critical(f"An unexpected error occurred during implementation for rule {rule.id}: {e}", exc_info=True)
                flash(f"An unexpected error occurred during implementation: {e}", 'error')

        elif action == 'decline_implementation':
            rule.status = 'Declined by Implementer'
            flash(f"Rule ID {rule.id} implementation declined.", 'warning')
            db.session.commit()
            app_logger.info(f"Implementer {current_user.username} (ID: {current_user.id}) declined implementation for rule {rule.id}.")

        return redirect(url_for('routes.implementation_list'))

    return render_template('implementation_detail.html', rule=rule)

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
            errors.append("Invalid Protocol. Must be tcp, udp, icmp, any, or protocol number.")

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
            app_logger.warning(f"Validation errors for new blacklist rule from {current_user.username}: {errors}")
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
                                   protocol=protocol, destination_port=destination_port, description=description)

        new_rule = BlacklistRule(
            sequence=sequence,
            rule_name=rule_name,
            enabled=enabled,
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            destination_port=destination_port,
            description=description
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
            return redirect(url_for('routes.blacklist_rules_list')) # Redirect to the list view
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

    return render_template('blacklist_rule_add.html')


@routes.route('/admin/blacklist-rules/detail/<int:rule_id>')
@login_required
@roles_required('superadmin', 'admin')
def blacklist_rule_detail(rule_id):
    """
    Displays detailed information for a specific blacklist rule.
    """
    rule = BlacklistRule.query.get_or_404(rule_id)
    return render_template('blacklist_rule_detail.html', rule=rule)


@routes.route('/admin/blacklist-rules/delete/<int:rule_id>', methods=['POST'])
@login_required
@roles_required('superadmin', 'admin')
def delete_blacklist_rule(rule_id):
    """
    Deletes a blacklist rule.
    """
    rule = BlacklistRule.query.get_or_404(rule_id)
    try:
        db.session.delete(rule)
        db.session.commit()
        flash(f"Blacklist rule '{rule.rule_name}' deleted successfully.", 'success')
        app_logger.info(f"Blacklist rule ID {rule_id} ('{rule.rule_name}') deleted by {current_user.username}.")
        log_activity(
            event_type='BLACKLIST_RULE_DELETE',
            description=f"Blacklist rule '{rule_name}' (ID: {rule_id}) was deleted.",
            user=current_user,
            related_resource_id=rule_id,
            related_resource_type='BlacklistRule'
        )
        return jsonify({"status": "success", "message": "Rule deleted."}), 200
    except Exception as e:
        db.session.rollback()
        app_logger.error(f"Error deleting blacklist rule {rule_id} by {current_user.username}: {str(e)}", exc_info=True)
        return jsonify({"status": "error", "message": f"Error deleting rule: {e}"}), 500

@routes.route('/admin/blacklist-rules/edit/<int:rule_id>', methods=['GET', 'POST'])
@login_required
@roles_required('superadmin', 'admin')
def edit_blacklist_rule(rule_id):
    """
    Allows superadmin and admin roles to edit existing blacklist rules.
    """
    rule = BlacklistRule.query.get_or_404(rule_id)

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
        # Check for sequence uniqueness only if it's being changed and conflicts with another rule
        elif sequence != rule.sequence and BlacklistRule.query.filter_by(sequence=sequence).first():
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
            errors.append("Invalid Protocol. Must be tcp, udp, icmp, any, or protocol number.")

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
            app_logger.warning(f"Validation errors for editing blacklist rule {rule.id} from {current_user.username}: {errors}")
            return render_template('blacklist_rule_add.html',
                                   sequence=sequence, rule_name=rule_name, enabled=enabled,
                                   source_ip=source_ip, destination_ip=destination_ip,
                                   protocol=protocol, destination_port=destination_port, description=description,
                                   title=f'Edit Blacklist Rule ID: {rule_id}')

        rule.sequence = sequence
        rule.rule_name = rule_name
        rule.enabled = enabled
        rule.source_ip = source_ip
        rule.destination_ip = destination_ip
        rule.protocol = protocol
        rule.destination_port = destination_port
        rule.description = description

        try:
            db.session.commit()
            flash(f'Blacklist rule {rule.id} updated successfully!', 'success')
            app_logger.info(f"Blacklist rule {rule.id} updated by {current_user.username}.")
            return redirect(url_for('routes.blacklist_rules_list'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating blacklist rule: {e}', 'error')
            app_logger.error(f"Error updating blacklist rule {rule.id} by {current_user.username}: {e}", exc_info=True)
            return render_template('blacklist_rule_add.html',
                                   sequence=sequence, rule_name=rule_name, enabled=enabled,
                                   source_ip=source_ip, destination_ip=destination_ip,
                                   protocol=protocol, destination_port=destination_port, description=description,
                                   title=f'Edit Blacklist Rule ID: {rule_id}')

    # For GET requests (initial load of the edit page)
    # Populate the form with the existing rule's data
    return render_template('blacklist_rule_add.html',
                           sequence=rule.sequence,
                           rule_name=rule.rule_name,
                           enabled=rule.enabled,
                           source_ip=rule.source_ip,
                           destination_ip=rule.destination_ip,
                           protocol=rule.protocol,
                           destination_port=rule.destination_port,
                           description=rule.description,
                           title=f'Edit Blacklist Rule ID: {rule_id}')

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

@routes.route('/api/blacklist_rules/<int:rule_id>', methods=['DELETE'])
@login_required
@roles_required('superadmin', 'admin')
def api_delete_single_blacklist_rule(rule_id):
    """
    API endpoint to delete a single blacklist rule by ID.
    """
    rule = BlacklistRule.query.get(rule_id)
    if not rule:
        app_logger.warning(f"API: Attempted to delete non-existent blacklist rule ID {rule_id} by {current_user.username}.")
        log_activity(
            event_type='BLACKLIST_RULE_DELETE_FAILED',
            description=f"Attempted to delete non-existent blacklist rule ID {rule_id}.",
            user=current_user,
            status='failed',
            related_resource_id=rule_id,
            related_resource_type='BlacklistRule'
        )
        return jsonify({"status": "error", "message": f"Rule with ID {rule_id} not found."}), 404

    rule_name = rule.rule_name

    try:
        db.session.delete(rule)
        db.session.commit()
        app_logger.info(f"API: Blacklist rule ID {rule_id} deleted by {current_user.username}.")
        log_activity(
            event_type='BLACKLIST_RULE_DELETE',
            description=f"Blacklist rule '{rule_name}' (ID: {rule_id},) was deleted.",
            user=current_user,
            related_resource_id=rule_id,
            related_resource_type='BlacklistRule'
        )
        return jsonify({"status": "success", "message": f"Rule ID {rule_id} deleted successfully."}), 200
    except Exception as e:
        db.session.rollback()
        app_logger.error(f"API: Error deleting single blacklist rule {rule_id} by {current_user.username}: {e}", exc_info=True)
        log_activity(
            event_type='BLACKLIST_RULE_DELETE_FAILED',
            description=f"Failed to delete blacklist rule '{rule_name}' (ID: {rule_id}).: {str(e)}",
            user=current_user,
            related_resource_id=rule_id,
            related_resource_type='BlacklistRule',
            status='failed'
        )
        return jsonify({"status": "error", "message": f"An error occurred during deletion: {e}"}), 500

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
