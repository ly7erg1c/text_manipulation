"""
Audit Logging System

Provides comprehensive audit logging for all operations and API calls
with data sanitization to prevent sensitive data leaks.
"""

import json
import sqlite3
import hashlib
import time
import re
from typing import Dict, Any, Optional, List, Union
from pathlib import Path
import logging
from datetime import datetime
from dataclasses import dataclass, asdict
import threading
from enum import Enum

logger = logging.getLogger(__name__)


class AuditLevel(Enum):
    """Audit logging levels."""
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    SECURITY = "SECURITY"


class AuditCategory(Enum):
    """Audit event categories."""
    API_CALL = "API_CALL"
    DATA_EXTRACTION = "DATA_EXTRACTION"
    FILE_OPERATION = "FILE_OPERATION"
    USER_ACTION = "USER_ACTION"
    CACHE_OPERATION = "CACHE_OPERATION"
    CONFIGURATION = "CONFIGURATION"
    AUTHENTICATION = "AUTHENTICATION"


@dataclass
class AuditEvent:
    """Represents an audit event."""
    timestamp: float
    level: AuditLevel
    category: AuditCategory
    action: str
    details: Dict[str, Any]
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    ip_address: Optional[str] = None
    sanitized_data: Optional[Dict[str, Any]] = None


class DataSanitizer:
    """Sanitizes sensitive data from audit logs."""
    
    # Patterns for sensitive data
    SENSITIVE_PATTERNS = {
        'api_key': re.compile(r'(["\']?(?:api[_-]?key|token|secret)["\']?\s*[:=]\s*["\']?)([a-zA-Z0-9+/=\-_]{10,})', re.IGNORECASE),
        'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        'ip_private': re.compile(r'\b(?:10\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|172\.(?:1[6-9]|2[0-9]|3[01])\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|192\.168\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\b'),
        'hash': re.compile(r'\b[a-fA-F0-9]{32,64}\b'),
        'phone': re.compile(r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b'),
        'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
        'credit_card': re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b')
    }
    
    # Fields that should always be sanitized
    SENSITIVE_FIELDS = {
        'password', 'secret', 'token', 'key', 'auth', 'credential',
        'private', 'confidential', 'sensitive'
    }
    
    @classmethod
    def sanitize_data(cls, data: Any, preserve_structure: bool = True) -> Any:
        """
        Sanitize sensitive data from any data structure.
        
        Args:
            data: Data to sanitize
            preserve_structure: Whether to preserve the original structure
            
        Returns:
            Sanitized data
        """
        if isinstance(data, dict):
            return cls._sanitize_dict(data, preserve_structure)
        elif isinstance(data, list):
            return cls._sanitize_list(data, preserve_structure)
        elif isinstance(data, str):
            return cls._sanitize_string(data)
        else:
            return data
    
    @classmethod
    def _sanitize_dict(cls, data: Dict[str, Any], preserve_structure: bool) -> Dict[str, Any]:
        """Sanitize dictionary data."""
        sanitized = {}
        
        for key, value in data.items():
            # Check if key indicates sensitive data
            key_lower = key.lower()
            is_sensitive_field = any(sensitive in key_lower for sensitive in cls.SENSITIVE_FIELDS)
            
            if is_sensitive_field:
                if preserve_structure:
                    sanitized[key] = "[REDACTED]"
                # Skip if not preserving structure
            else:
                sanitized[key] = cls.sanitize_data(value, preserve_structure)
        
        return sanitized
    
    @classmethod
    def _sanitize_list(cls, data: List[Any], preserve_structure: bool) -> List[Any]:
        """Sanitize list data."""
        return [cls.sanitize_data(item, preserve_structure) for item in data]
    
    @classmethod
    def _sanitize_string(cls, data: str) -> str:
        """Sanitize string data."""
        sanitized = data
        
        for pattern_name, pattern in cls.SENSITIVE_PATTERNS.items():
            if pattern_name == 'api_key':
                sanitized = pattern.sub(r'\1[REDACTED]', sanitized)
            elif pattern_name in ['email', 'phone', 'ssn', 'credit_card']:
                sanitized = pattern.sub('[REDACTED]', sanitized)
            elif pattern_name == 'ip_private':
                # Only redact private IPs, leave public ones for threat intel
                sanitized = pattern.sub('[PRIVATE_IP]', sanitized)
            elif pattern_name == 'hash':
                # Partially redact hashes (keep first 8 chars for identification)
                def redact_hash(match):
                    hash_val = match.group(0)
                    if len(hash_val) >= 32:  # Only for actual hashes
                        return hash_val[:8] + '[REDACTED]'
                    return hash_val
                sanitized = pattern.sub(redact_hash, sanitized)
        
        return sanitized
    
    @classmethod
    def create_data_hash(cls, data: Any) -> str:
        """Create a hash of the original data for verification purposes."""
        data_str = json.dumps(data, sort_keys=True) if not isinstance(data, str) else data
        return hashlib.sha256(data_str.encode()).hexdigest()[:16]


class AuditLogger:
    """Manages audit logging with sanitization and persistence."""
    
    def __init__(self, audit_dir: str = ".audit", max_log_size_mb: int = 100):
        """
        Initialize audit logger.
        
        Args:
            audit_dir: Directory to store audit logs
            max_log_size_mb: Maximum log file size in MB before rotation
        """
        self.audit_dir = Path(audit_dir)
        self.audit_dir.mkdir(exist_ok=True)
        self.max_log_size = max_log_size_mb * 1024 * 1024
        self.audit_lock = threading.RLock()
        
        # Initialize SQLite database for audit logs
        self.db_path = self.audit_dir / "audit.db"
        self._init_database()
        
        # Initialize text log file
        self.log_file = self.audit_dir / "audit.log"
        self._setup_file_logging()
    
    def _init_database(self) -> None:
        """Initialize SQLite database for audit logs."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS audit_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp REAL NOT NULL,
                        level TEXT NOT NULL,
                        category TEXT NOT NULL,
                        action TEXT NOT NULL,
                        details TEXT NOT NULL,
                        sanitized_data TEXT,
                        user_id TEXT,
                        session_id TEXT,
                        ip_address TEXT,
                        data_hash TEXT
                    )
                """)
                
                # Create indexes for better performance
                conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_events(timestamp)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_category ON audit_events(category)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_level ON audit_events(level)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_user_id ON audit_events(user_id)")
                
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to initialize audit database: {e}")
    
    def _setup_file_logging(self) -> None:
        """Setup file logging handler."""
        try:
            # Create file handler with rotation
            file_handler = logging.FileHandler(self.log_file)
            file_handler.setLevel(logging.INFO)
            
            # Create formatter
            formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(name)s - %(message)s'
            )
            file_handler.setFormatter(formatter)
            
            # Add handler to audit logger
            audit_file_logger = logging.getLogger('audit_file')
            audit_file_logger.addHandler(file_handler)
            audit_file_logger.setLevel(logging.INFO)
            
        except Exception as e:
            logger.error(f"Failed to setup file logging: {e}")
    
    def log_event(self, level: AuditLevel, category: AuditCategory, action: str,
                  details: Dict[str, Any], user_id: Optional[str] = None,
                  session_id: Optional[str] = None, ip_address: Optional[str] = None) -> None:
        """
        Log an audit event.
        
        Args:
            level: Audit level
            category: Event category
            action: Action description
            details: Event details
            user_id: User identifier
            session_id: Session identifier
            ip_address: IP address
        """
        try:
            # Sanitize the details
            sanitized_details = DataSanitizer.sanitize_data(details)
            data_hash = DataSanitizer.create_data_hash(details)
            
            # Create audit event
            event = AuditEvent(
                timestamp=time.time(),
                level=level,
                category=category,
                action=action,
                details=details,
                user_id=user_id,
                session_id=session_id,
                ip_address=ip_address,
                sanitized_data=sanitized_details
            )
            
            with self.audit_lock:
                # Store in database
                self._store_to_database(event, data_hash)
                
                # Log to file
                self._log_to_file(event)
                
        except Exception as e:
            logger.error(f"Failed to log audit event: {e}")
    
    def _store_to_database(self, event: AuditEvent, data_hash: str) -> None:
        """Store audit event to database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO audit_events 
                    (timestamp, level, category, action, details, sanitized_data, 
                     user_id, session_id, ip_address, data_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    event.timestamp,
                    event.level.value,
                    event.category.value,
                    event.action,
                    json.dumps(event.sanitized_data),  # Store sanitized version
                    json.dumps(event.sanitized_data),
                    event.user_id,
                    event.session_id,
                    event.ip_address,
                    data_hash
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to store audit event to database: {e}")
    
    def _log_to_file(self, event: AuditEvent) -> None:
        """Log audit event to file."""
        try:
            audit_file_logger = logging.getLogger('audit_file')
            
            log_message = (
                f"[{event.level.value}] [{event.category.value}] {event.action} - "
                f"User: {event.user_id or 'N/A'} - "
                f"Session: {event.session_id or 'N/A'} - "
                f"IP: {event.ip_address or 'N/A'} - "
                f"Details: {json.dumps(event.sanitized_data)}"
            )
            
            audit_file_logger.info(log_message)
            
            # Check file size and rotate if necessary
            self._check_log_rotation()
            
        except Exception as e:
            logger.error(f"Failed to log to file: {e}")
    
    def _check_log_rotation(self) -> None:
        """Check if log file needs rotation."""
        try:
            if self.log_file.exists() and self.log_file.stat().st_size > self.max_log_size:
                # Rotate log file
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_name = f"audit_{timestamp}.log"
                backup_path = self.audit_dir / backup_name
                
                self.log_file.rename(backup_path)
                
                # Reinitialize file logging
                self._setup_file_logging()
                
                logger.info(f"Rotated audit log to {backup_name}")
        except Exception as e:
            logger.error(f"Failed to rotate audit log: {e}")
    
    def query_events(self, start_time: Optional[float] = None, end_time: Optional[float] = None,
                    level: Optional[AuditLevel] = None, category: Optional[AuditCategory] = None,
                    user_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Query audit events with filters.
        
        Args:
            start_time: Start timestamp
            end_time: End timestamp
            level: Audit level filter
            category: Category filter
            user_id: User ID filter
            limit: Maximum number of results
            
        Returns:
            List of audit events
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                
                query = "SELECT * FROM audit_events WHERE 1=1"
                params = []
                
                if start_time:
                    query += " AND timestamp >= ?"
                    params.append(start_time)
                
                if end_time:
                    query += " AND timestamp <= ?"
                    params.append(end_time)
                
                if level:
                    query += " AND level = ?"
                    params.append(level.value)
                
                if category:
                    query += " AND category = ?"
                    params.append(category.value)
                
                if user_id:
                    query += " AND user_id = ?"
                    params.append(user_id)
                
                query += " ORDER BY timestamp DESC LIMIT ?"
                params.append(limit)
                
                cursor = conn.execute(query, params)
                events = []
                
                for row in cursor.fetchall():
                    event_dict = dict(row)
                    event_dict['details'] = json.loads(event_dict['details'])
                    if event_dict['sanitized_data']:
                        event_dict['sanitized_data'] = json.loads(event_dict['sanitized_data'])
                    events.append(event_dict)
                
                return events
                
        except Exception as e:
            logger.error(f"Failed to query audit events: {e}")
            return []
    
    def get_audit_stats(self) -> Dict[str, Any]:
        """Get audit statistics."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                stats = {}
                
                # Total events
                cursor = conn.execute("SELECT COUNT(*) FROM audit_events")
                stats['total_events'] = cursor.fetchone()[0]
                
                # Events by level
                cursor = conn.execute("""
                    SELECT level, COUNT(*) as count 
                    FROM audit_events 
                    GROUP BY level
                """)
                stats['by_level'] = {row[0]: row[1] for row in cursor.fetchall()}
                
                # Events by category
                cursor = conn.execute("""
                    SELECT category, COUNT(*) as count 
                    FROM audit_events 
                    GROUP BY category
                """)
                stats['by_category'] = {row[0]: row[1] for row in cursor.fetchall()}
                
                # Recent activity (last 24 hours)
                last_24h = time.time() - (24 * 60 * 60)
                cursor = conn.execute(
                    "SELECT COUNT(*) FROM audit_events WHERE timestamp >= ?",
                    (last_24h,)
                )
                stats['last_24h'] = cursor.fetchone()[0]
                
                # Database size
                stats['db_size_mb'] = self.db_path.stat().st_size / (1024 * 1024)
                
                return stats
                
        except Exception as e:
            logger.error(f"Failed to get audit stats: {e}")
            return {}


# Global audit logger instance
_audit_logger = None


def get_audit_logger() -> AuditLogger:
    """Get the global audit logger instance."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger


def audit_log(level: AuditLevel, category: AuditCategory, action: str, **kwargs):
    """
    Convenience function for audit logging.
    
    Args:
        level: Audit level
        category: Event category
        action: Action description
        **kwargs: Additional details
    """
    audit_logger = get_audit_logger()
    
    # Extract special parameters
    user_id = kwargs.pop('user_id', None)
    session_id = kwargs.pop('session_id', None)
    ip_address = kwargs.pop('ip_address', None)
    
    # Remaining kwargs become details
    details = kwargs
    
    audit_logger.log_event(
        level=level,
        category=category,
        action=action,
        details=details,
        user_id=user_id,
        session_id=session_id,
        ip_address=ip_address
    )


def audit_api_call(provider: str, endpoint: str, success: bool = True, **kwargs):
    """
    Convenience function for auditing API calls.
    
    Args:
        provider: API provider name
        endpoint: API endpoint
        success: Whether the call was successful
        **kwargs: Additional details
    """
    level = AuditLevel.INFO if success else AuditLevel.ERROR
    action = f"{provider} API call to {endpoint}"
    
    audit_log(
        level=level,
        category=AuditCategory.API_CALL,
        action=action,
        provider=provider,
        endpoint=endpoint,
        success=success,
        **kwargs
    ) 