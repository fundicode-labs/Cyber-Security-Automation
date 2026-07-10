"""
RBAC Decorators and Utilities
Provides permission checking decorators for Flask routes
"""

from functools import wraps
from flask import redirect, flash, abort
from flask_login import current_user
from roles import has_permission, ROLES


def require_permission(permission):
    """
    Decorator to check if user has a specific permission
    
    Usage:
        @app.route("/delete_user/<int:user_id>")
        @require_permission("users.delete")
        def delete_user(user_id):
            ...
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                flash("Please log in first.", "danger")
                return redirect("/login")
            
            user_role = getattr(current_user, 'role', 'viewer')
            
            if not has_permission(user_role, permission):
                flash(f"You don't have permission to {permission}.", "danger")
                return abort(403)
            
            return view_func(*args, **kwargs)
        return wrapper
    return decorator


def require_any_permission(*permissions):
    """
    Decorator to check if user has ANY of the specified permissions
    
    Usage:
        @require_any_permission("users.edit", "users.create")
        def manage_users():
            ...
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                flash("Please log in first.", "danger")
                return redirect("/login")
            
            user_role = getattr(current_user, 'role', 'viewer')
            has_any = any(has_permission(user_role, perm) for perm in permissions)
            
            if not has_any:
                flash("You don't have sufficient permissions.", "danger")
                return abort(403)
            
            return view_func(*args, **kwargs)
        return wrapper
    return decorator


def require_all_permissions(*permissions):
    """
    Decorator to check if user has ALL of the specified permissions
    
    Usage:
        @require_all_permissions("users.view", "report.view")
        def admin_dashboard():
            ...
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                flash("Please log in first.", "danger")
                return redirect("/login")
            
            user_role = getattr(current_user, 'role', 'viewer')
            has_all = all(has_permission(user_role, perm) for perm in permissions)
            
            if not has_all:
                flash("You don't have sufficient permissions.", "danger")
                return abort(403)
            
            return view_func(*args, **kwargs)
        return wrapper
    return decorator


def require_role(*allowed_roles):
    """
    Decorator to check if user has one of the specified roles
    
    Usage:
        @require_role("super_admin", "security_admin")
        def system_settings():
            ...
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                flash("Please log in first.", "danger")
                return redirect("/login")
            
            user_role = getattr(current_user, 'role', 'viewer')
            
            if user_role not in allowed_roles:
                flash(f"Only {', '.join(allowed_roles)} can access this.", "danger")
                return abort(403)
            
            return view_func(*args, **kwargs)
        return wrapper
    return decorator


# Utility functions for templates

def user_can(permission):
    """Check in templates if user has permission"""
    if not current_user.is_authenticated:
        return False
    user_role = getattr(current_user, 'role', 'viewer')
    return has_permission(user_role, permission)


def user_has_role(*roles):
    """Check in templates if user has one of the roles"""
    if not current_user.is_authenticated:
        return False
    user_role = getattr(current_user, 'role', 'viewer')
    return user_role in roles


def get_user_permissions():
    """Get all permissions for current user"""
    if not current_user.is_authenticated:
        return []
    user_role = getattr(current_user, 'role', 'viewer')
    return ROLES.get(user_role, {}).get("permissions", [])


def get_user_role_info():
    """Get role information for current user"""
    if not current_user.is_authenticated:
        return None
    user_role = getattr(current_user, 'role', 'viewer')
    return ROLES.get(user_role)


# Audit logging helper
def log_action(username, action, details=""):
    """
    Log user actions for audit trail
    
    Usage:
        log_action(current_user.username, "scan.port", f"Scanned {target}")
    """
    from datetime import datetime
    from database import connect
    
    try:
        with connect() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO audit_logs (username, action, details, log_time)
                VALUES (?, ?, ?, ?)
            """, (username, action, details, datetime.utcnow().isoformat()))
    except Exception as e:
        print(f"Error logging action: {e}")
