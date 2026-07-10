"""
Notifications Center
Manages user notifications and alerts
"""

import os
from datetime import datetime, timedelta

from database import connect

DB_PATH = os.path.join(
    os.path.dirname(__file__),
    "database.db"
)

class Notification:
    """Notification model"""
    
    def __init__(self, id=None, user_id=None, title="", message="", 
                 notification_type="info", is_read=False, created_at=None):
        self.id = id
        self.user_id = user_id
        self.title = title
        self.message = message
        self.notification_type = notification_type  # info, warning, danger, success
        self.is_read = is_read
        self.created_at = created_at or datetime.utcnow().isoformat()
    
    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "title": self.title,
            "message": self.message,
            "type": self.notification_type,
            "is_read": bool(self.is_read),
            "created_at": self.created_at
        }


class NotificationManager:
    """Manage notifications"""
    
    TYPES = {
        "info": "ℹ️",
        "warning": "⚠️",
        "danger": "🚨",
        "success": "✅"
    }
    
    @staticmethod
    def create(user_id, title, message, notification_type="info"):
        """Create a new notification"""
        try:
            with connect() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO notifications (user_id, title, message, notification_type, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    RETURNING id
                """, (user_id, title, message, notification_type, datetime.utcnow().isoformat()))
                conn.commit()
                row = cursor.fetchone()
                notification_id = row[0] if row else None
            
            return notification_id
            
        except Exception as e:
            print(f"Error creating notification: {e}")
            return None
    
    @staticmethod
    def get_user_notifications(user_id, unread_only=False, limit=20):
        """Get user notifications"""
        try:
            with connect() as conn:
                cursor = conn.cursor()
                
                query = "SELECT * FROM notifications WHERE user_id = ?"
                params = [user_id]
                
                if unread_only:
                    query += " AND is_read = 0"
                
                query += " ORDER BY created_at DESC LIMIT ?"
                params.append(limit)
                
                cursor.execute(query, params)
                rows = cursor.fetchall()
            
            notifications = [Notification(
                row["id"],
                row["user_id"],
                row["title"],
                row["message"],
                row["notification_type"],
                row["is_read"],
                row["created_at"]
            ) for row in rows]
            
            return notifications
            
        except Exception as e:
            print(f"Error getting notifications: {e}")
            return []
    
    @staticmethod
    def get_unread_count(user_id):
        """Get count of unread notifications"""
        try:
            with connect() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0",
                    (user_id,)
                )
                count = cursor.fetchone()[0]
            
            return count
            
        except Exception as e:
            print(f"Error getting unread count: {e}")
            return 0
    
    @staticmethod
    def mark_as_read(notification_id):
        """Mark notification as read"""
        try:
            with connect() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE notifications SET is_read = 1 WHERE id = ?",
                    (notification_id,)
                )
                conn.commit()
            
            return True
            
        except Exception as e:
            print(f"Error marking notification as read: {e}")
            return False
    
    @staticmethod
    def mark_all_as_read(user_id):
        """Mark all user notifications as read"""
        try:
            with connect() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE notifications SET is_read = 1 WHERE user_id = ?",
                    (user_id,)
                )
                conn.commit()
            
            return True
            
        except Exception as e:
            print(f"Error marking all as read: {e}")
            return False
    
    @staticmethod
    def delete_notification(notification_id):
        """Delete a notification"""
        try:
            with connect() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "DELETE FROM notifications WHERE id = ?",
                    (notification_id,)
                )
                conn.commit()
            
            return True
            
        except Exception as e:
            print(f"Error deleting notification: {e}")
            return False
    
    @staticmethod
    def delete_old_notifications(days=30):
        """Delete notifications older than N days"""
        try:
            cutoff_date = (datetime.utcnow() - timedelta(days=days)).isoformat()
            
            with connect() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "DELETE FROM notifications WHERE created_at < ?",
                    (cutoff_date,)
                )
                deleted = cursor.rowcount
                conn.commit()
            
            return deleted
            
        except Exception as e:
            print(f"Error deleting old notifications: {e}")
            return 0
    
    @staticmethod
    def notify_all_admins(title, message, notification_type="warning"):
        """Send notification to all admin users"""
        try:
            with connect() as conn:
                cursor = conn.cursor()
                
                # Get all admin users
                cursor.execute("SELECT id FROM users WHERE role IN ('super_admin', 'security_admin', 'admin')")
                admin_ids = [row[0] for row in cursor.fetchall()]
                
                # Create notification for each admin
                for admin_id in admin_ids:
                    NotificationManager.create(
                        admin_id,
                        title,
                        message,
                        notification_type
                    )
            
            return len(admin_ids)
            
        except Exception as e:
            print(f"Error notifying admins: {e}")
            return 0


# Common notification templates
NOTIFICATION_TEMPLATES = {
    "weak_password": {
        "title": "⚠️ Weak Password Detected",
        "message": "User '{username}' has a weak password. Recommend password reset.",
        "type": "warning"
    },
    "new_device": {
        "title": "ℹ️ New Device Login",
        "message": "New device detected for user '{username}' from IP {ip_address}",
        "type": "info"
    },
    "file_modified": {
        "title": "🚨 File Integrity Violation",
        "message": "File '{file_path}' has been modified. Expected hash: {old_hash}",
        "type": "danger"
    },
    "failed_login": {
        "title": "⚠️ Failed Login Attempts",
        "message": "Multiple failed login attempts detected from IP {ip_address}",
        "type": "warning"
    },
    "scan_complete": {
        "title": "✅ Scan Complete",
        "message": "Scan '{scan_type}' on {target} completed. Results: {result}",
        "type": "success"
    },
    "scan_failed": {
        "title": "🚨 Scan Failed",
        "message": "Scan '{scan_type}' on {target} failed. Error: {error}",
        "type": "danger"
    },
    "vulnerability_found": {
        "title": "🚨 Vulnerability Detected",
        "message": "Critical vulnerability found: {vulnerability} on {target}",
        "type": "danger"
    }
}

# Convenience aliases
notification_manager = NotificationManager()

def create_notification(user_id, title, message, notification_type="info"):
    """Create a notification"""
    return NotificationManager.create(user_id, title, message, notification_type)

def get_user_notifications(user_id, unread_only=False, limit=20):
    """Get user notifications"""
    return NotificationManager.get_user_notifications(user_id, unread_only, limit)

def get_unread_count(user_id):
    """Get unread notification count"""
    return NotificationManager.get_unread_count(user_id)
