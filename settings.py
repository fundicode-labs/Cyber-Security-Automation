"""
System Settings Management
Manages application configuration stored in database
"""

import sqlite3
import os
from datetime import datetime

from database import connect

DB_PATH = os.path.join(
    os.path.dirname(__file__),
    "database.db"
)

class SystemSettings:
    """Singleton class to manage system settings"""
    
    _instance = None
    _cache = {}
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(SystemSettings, cls).__new__(cls)
        return cls._instance
    
    @staticmethod
    def get(key, default=None):
        """Get a setting value"""
        try:
            # Check cache first
            if key in SystemSettings._cache:
                return SystemSettings._cache[key]
            
            with connect() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT value, setting_type FROM system_settings WHERE key = ?",
                    (key,)
                )
                row = cursor.fetchone()
            
            if not row:
                return default
            
            value = row["value"]
            setting_type = row["setting_type"]
            
            # Convert value to appropriate type
            if setting_type == "integer":
                value = int(value)
            elif setting_type == "boolean":
                value = value.lower() in ("true", "1", "yes")
            
            # Cache the value
            SystemSettings._cache[key] = value
            return value
            
        except Exception as e:
            print(f"Error getting setting '{key}': {e}")
            return default
    
    @staticmethod
    def set(key, value, setting_type="string", description=""):
        """Set a setting value"""
        try:
            # Invalidate cache
            if key in SystemSettings._cache:
                del SystemSettings._cache[key]
            
            with connect() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO system_settings (key, value, setting_type, description, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET 
                        value = excluded.value,
                        setting_type = excluded.setting_type,
                        description = excluded.description,
                        updated_at = excluded.updated_at
                """, (key, str(value), setting_type, description, datetime.utcnow().isoformat()))
                conn.commit()
            
            return True
            
        except Exception as e:
            print(f"Error setting '{key}': {e}")
            return False
    
    @staticmethod
    def get_all():
        """Get all settings as dictionary"""
        try:
            with connect() as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM system_settings ORDER BY key")
                rows = cursor.fetchall()
            
            settings = {}
            for row in rows:
                settings[row["key"]] = {
                    "value": row["value"],
                    "type": row["setting_type"],
                    "description": row["description"]
                }
            
            return settings
            
        except Exception as e:
            print(f"Error getting all settings: {e}")
            return {}
    
    @staticmethod
    def delete(key):
        """Delete a setting"""
        try:
            # Invalidate cache
            if key in SystemSettings._cache:
                del SystemSettings._cache[key]
            
            with connect() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM system_settings WHERE key = ?", (key,))
                conn.commit()
            
            return True
            
        except Exception as e:
            print(f"Error deleting setting '{key}': {e}")
            return False
    
    @staticmethod
    def clear_cache():
        """Clear the cache"""
        SystemSettings._cache.clear()


# Convenience aliases
settings = SystemSettings()

def get_setting(key, default=None):
    """Get a single setting"""
    return SystemSettings.get(key, default)

def set_setting(key, value, setting_type="string", description=""):
    """Set a single setting"""
    return SystemSettings.set(key, value, setting_type, description)

def get_all_settings():
    """Get all settings"""
    return SystemSettings.get_all()
