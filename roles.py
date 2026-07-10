"""
Role-Based Access Control (RBAC) Configuration
Defines 5 roles and their permissions for Cyber Security Automation
"""

ROLES = {
    "super_admin": {
        "name": "Super Admin",
        "description": "Full system access - can manage everything",
        "permissions": [
            # User Management
            "users.view", "users.create", "users.edit", "users.delete",
            "roles.assign", "roles.manage",
            
            # Security Scans
            "scan.port", "scan.network", "scan.password", 
            "scan.logs", "scan.integrity", "scan.vulnerability",
            "scan.history.view", "scan.history.delete",
            
            # Reports & Analysis
            "report.view", "report.generate", "report.export", "report.delete",
            "logs.view", "logs.analyze", "logs.export",
            
            # System Settings
            "settings.view", "settings.edit",
            "backup.create", "backup.restore",
            "api.manage", "email.manage",

            # Payments
            "payments.view", "payments.create", "payments.approve", "payments.invoice",
            
            # Audit & Monitoring
            "audit.view", "audit.export", "audit.delete",
            "notifications.manage",
            
            # System Admin
            "system.maintenance", "system.restart", "database.manage"
        ]
    },
    
    "security_admin": {
        "name": "Security Administrator",
        "description": "Can manage scans and users",
        "permissions": [
            # User Management (limited)
            "users.view", "users.create", "users.edit",
            "roles.assign",
            
            # Security Scans (full)
            "scan.port", "scan.network", "scan.password",
            "scan.logs", "scan.integrity", "scan.vulnerability",
            "scan.history.view",
            
            # Reports & Analysis
            "report.view", "report.generate", "report.export",
            "logs.view", "logs.analyze", "logs.export",
            
            # Settings (limited)
            "settings.view",
            "email.manage",

            # Payments
            "payments.view", "payments.create", "payments.approve", "payments.invoice",
            
            # Notifications
            "notifications.view",
            
            # Audit (read-only)
            "audit.view"
        ]
    },
    
    "security_analyst": {
        "name": "Security Analyst",
        "description": "Can view reports and analyze logs (read-only)",
        "permissions": [
            # User Management (view only)
            "users.view",
            
            # Security Scans (view only)
            "scan.history.view",
            
            # Reports & Analysis (full read)
            "report.view", "report.generate", "report.export",
            "logs.view", "logs.analyze", "logs.export",
            
            # Settings (view only)
            "settings.view",

            # Payments (read-only)
            "payments.view", "payments.invoice",
            
            # Notifications
            "notifications.view",
            
            # Audit (view only)
            "audit.view"
        ]
    },
    
    "operator": {
        "name": "Operator",
        "description": "Can run scans only",
        "permissions": [
            # Security Scans (limited)
            "scan.port", "scan.network", "scan.password",
            "scan.logs", "scan.integrity",
            "scan.history.view",
            
            # Notifications
            "notifications.view",

            # Payments
            "payments.view", "payments.create", "payments.invoice"
        ]
    },
    
    "viewer": {
        "name": "Viewer",
        "description": "Can only view reports and results (read-only)",
        "permissions": [
            # Reports & Analysis (read-only)
            "report.view",
            "logs.view",
            "scan.history.view",
            
            # Notifications
            "notifications.view",

            # Payments (basic)
            "payments.view", "payments.create", "payments.invoice"
        ]
    }
}

# Backward-compatible aliases for existing data and older templates
ROLES["admin"] = {
    **ROLES["super_admin"],
    "name": "Admin",
    "description": "Legacy admin role with full system access"
}

ROLES["user"] = {
    **ROLES["viewer"],
    "name": "User",
    "description": "Standard user with read-only access"
}

# Permission categories for frontend display
PERMISSION_CATEGORIES = {
    "user_management": {
        "name": "User Management",
        "permissions": ["users.view", "users.create", "users.edit", "users.delete"]
    },
    "role_management": {
        "name": "Role & Permission Management",
        "permissions": ["roles.assign", "roles.manage"]
    },
    "scans": {
        "name": "Security Scans",
        "permissions": [
            "scan.port", "scan.network", "scan.password", "scan.logs", 
            "scan.integrity", "scan.vulnerability", "scan.history.view", "scan.history.delete"
        ]
    },
    "reports": {
        "name": "Reports & Analysis",
        "permissions": [
            "report.view", "report.generate", "report.export", "report.delete",
            "logs.view", "logs.analyze", "logs.export"
        ]
    },
    "system": {
        "name": "System Management",
        "permissions": [
            "settings.view", "settings.edit", "backup.create", "backup.restore",
            "api.manage", "email.manage", "system.maintenance", "system.restart", "database.manage"
        ]
    },
    "payments": {
        "name": "Payments",
        "permissions": ["payments.view", "payments.create", "payments.approve", "payments.invoice"]
    },
    "audit": {
        "name": "Audit & Compliance",
        "permissions": ["audit.view", "audit.export", "audit.delete", "notifications.manage"]
    }
}

def get_role_permissions(role_name):
    """Get all permissions for a given role"""
    if role_name not in ROLES:
        return []
    return ROLES[role_name]["permissions"]

def has_permission(user_role, permission):
    """Check if a role has a specific permission"""
    if not user_role or user_role not in ROLES:
        return False
    return permission in ROLES[user_role]["permissions"]

def get_role_info(role_name):
    """Get full role information"""
    if role_name not in ROLES:
        return None
    return ROLES[role_name]

def list_all_roles():
    """Get list of all available roles"""
    return [
        {"id": role_id, **role_info}
        for role_id, role_info in ROLES.items()
    ]

def list_all_permissions():
    """Get list of all available permissions"""
    permissions = set()
    for role_info in ROLES.values():
        permissions.update(role_info["permissions"])
    return sorted(list(permissions))
